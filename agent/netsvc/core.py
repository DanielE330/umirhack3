"""Ядро агента: опрос конфигурации у центра, запуск/остановка ловушек, надёжная отправка телеметрии."""
from __future__ import annotations

import asyncio
import logging
import random

from .buffer import EventBuffer
from .center import CenterClient, CenterError
from .emitter import Emitter
from .traps.banner import BannerTrap
from .traps.http import HttpTrap
from .traps.ssh import SshTrap

log = logging.getLogger("netsvc")
BATCH = 200


def jittered(base: float, jitter: float) -> float:
    return max(0.5, base * random.uniform(1 - jitter, 1 + jitter))


class Agent:
    def __init__(self, center: CenterClient, buffer: EventBuffer, state_dir: str, bind_host: str = "0.0.0.0",
                 port_offset: int = 0):
        self.center, self.buffer, self.state_dir, self.bind_host = center, buffer, state_dir, bind_host
        self.port_offset = port_offset  # для демо без root: 2222 -> 12222
        self.emitter = Emitter(buffer)
        self.traps: list = []
        self.rev: str | None = None
        self.jitter = 0.3
        self._stop = asyncio.Event()

    # --- ловушки ---
    def _make(self, service: dict, config: dict):
        service = {**service, "port": service["port"] + self.port_offset}
        proto = service.get("proto", "banner")
        if config.get("level") == "low" or proto == "banner":
            return BannerTrap(service, config, self.emitter)
        if proto == "ssh":
            return SshTrap(service, config, self.emitter, self.state_dir)
        if proto == "http":
            return HttpTrap(service, config, self.emitter)
        return BannerTrap(service, config, self.emitter)

    async def stop_traps(self) -> None:
        for trap in self.traps:
            await trap.stop()
        self.traps = []

    async def start_traps(self, config: dict) -> None:
        await self.stop_traps()
        self.emitter.capture_passwords = config.get("logging", {}).get("capture_passwords", True)
        self.jitter = config.get("masking", {}).get("jitter", 0.3)
        for service in config.get("services", []):
            trap = self._make(service, config)
            try:
                await trap.start(self.bind_host)
                self.traps.append(trap)
                log.info("listening on %s", getattr(trap, "port", "?"))
            except OSError as exc:
                log.error("cannot bind %s: %s", service.get("port"), exc)

    async def apply_manifest(self, m: dict) -> float:
        commands = m.get("cmds", [])
        if m.get("state") != "run" or not m.get("config"):
            if self.traps:
                await self.stop_traps()
            self.rev = m.get("rev")
        elif m.get("rev") != self.rev or "restart" in commands or not self.traps:
            await self.start_traps(m["config"])
            self.rev = m["rev"]
        return float(m.get("poll", 15))

    # --- циклы ---
    async def poll_loop(self) -> None:
        interval, failures = 15.0, 0
        while not self._stop.is_set():
            try:
                interval = await self.apply_manifest(await self.center.manifest())
                failures = 0
            except CenterError as exc:
                failures += 1
                log.warning("center unreachable: %s", exc)
            delay = jittered(interval, self.jitter) if not failures else min(60, jittered(2 ** failures, 0.3))
            await self._sleep(delay)

    async def send_loop(self) -> None:
        failures = 0
        while not self._stop.is_set():
            batch = self.buffer.peek(BATCH)
            if not batch:
                self.emitter.wakeup.clear()
                await self._wait_wakeup(30)
                await self._sleep(random.uniform(0.1, 0.6))  # короткий разброс: не отправляем строго по событию
                continue
            try:
                await self.center.send(batch)
                self.buffer.delete([e["uid"] for e in batch])
                failures = 0
            except CenterError as exc:
                failures += 1
                log.warning("send failed (%d buffered): %s", self.buffer.count(), exc)
                await self._sleep(min(60, jittered(2 ** failures, 0.3)))

    async def _wait_wakeup(self, timeout: float) -> None:
        try:
            await asyncio.wait_for(self.emitter.wakeup.wait(), timeout)
        except asyncio.TimeoutError:
            pass

    async def _sleep(self, seconds: float) -> None:
        try:
            await asyncio.wait_for(self._stop.wait(), seconds)
        except asyncio.TimeoutError:
            pass

    async def run(self) -> None:
        tasks = [asyncio.create_task(self.poll_loop()), asyncio.create_task(self.send_loop())]
        await self._stop.wait()
        for t in tasks:
            t.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        await self.stop_traps()

    def shutdown(self) -> None:
        self._stop.set()
