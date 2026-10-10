import asyncio
import logging
import os
import signal
import sys

from .buffer import EventBuffer
from .center import CenterClient
from .core import Agent


def main() -> None:
    url, token = os.environ.get("HF_CENTER_URL", ""), os.environ.get("HF_TRAP_TOKEN", "")
    if not url or not token:
        sys.exit("HF_CENTER_URL и HF_TRAP_TOKEN обязательны")
    state_dir = os.environ.get("HF_STATE_DIR", "/var/tmp/.cache-netsvc")
    logging.basicConfig(level=os.environ.get("HF_LOG", "WARNING"), format="%(asctime)s %(message)s")

    try:  # неприметное имя процесса (MASK-4); имя можно переопределить, пока центр его не прислал
        import setproctitle
        setproctitle.setproctitle(os.environ.get("HF_PROCESS_NAME", "systemd-journal-helper"))
    except ImportError:
        pass

    center = CenterClient(url, token, ca_file=os.environ.get("HF_CA_FILE", ""),
                          insecure=os.environ.get("HF_INSECURE_TLS") == "1")
    agent = Agent(center, EventBuffer(os.path.join(state_dir, "q.db")), state_dir,
                  bind_host=os.environ.get("HF_BIND", "0.0.0.0"), port_offset=int(os.environ.get("HF_PORT_OFFSET", "0")))

    async def runner() -> None:
        loop = asyncio.get_running_loop()
        for sig in (signal.SIGINT, signal.SIGTERM):
            loop.add_signal_handler(sig, agent.shutdown)
        await agent.run()

    asyncio.run(runner())


main()
