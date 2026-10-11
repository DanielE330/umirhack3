"""Нормализация и деобфускация текста команды.

Правило: все регулярки здесь без вложенных кванторов (линейные), а вход
обрезается до MAX_LEN — атакующий контролирует строку целиком, и ReDoS на
сервисе-анализаторе был бы самой глупой уязвимостью в системе безопасности.
"""
from __future__ import annotations

import base64
import binascii
import re
from dataclasses import dataclass, field

MAX_LEN = 4096          # всё, что длиннее, обрезается (команда ботов редко >1 КБ)
MAX_B64_DECODED = 2048  # потолок на раскодированный фрагмент
MAX_DECODE_ROUNDS = 2

_WS = re.compile(r"\s+")
_IFS = re.compile(r"\$\{?IFS\}?(?:\$\d)?", re.I)
_QUOTE_SPLIT = re.compile(r"(?<=\w)(?:''|\"\")(?=\w)")      # w''get -> wget
_QUOTE_INNER = re.compile(r"(?<=[A-Za-z])(['\"])([A-Za-z]{1,12})\1(?=[A-Za-z])")   # w"g"et -> wget
_BACKSLASH_IN_WORD = re.compile(r"(?<=[A-Za-z])\\(?=[A-Za-z])(?!x[0-9a-fA-F]{2})")  # w\get -> wget
_HEXESC = re.compile(r"\\x([0-9a-fA-F]{2})")
_HEXRUN = re.compile(r"(?:\\x[0-9a-fA-F]{2})+")
_HEXBIN_ML = re.compile(r"(?:\\x[0-9a-f]{2}){4,}")
_B64_PIPE = re.compile(
    r"(?:echo|printf)\s+(?:-[a-z]+\s+)*['\"]?([A-Za-z0-9+/=]{16,})['\"]?\s*\|\s*"
    r"(?:base64|openssl\s+base64)\s+(?:-d|--decode|-D)")
_B64_SUBST = re.compile(r"base64\s+(?:-d|--decode)\s*<<<\s*['\"]?([A-Za-z0-9+/=]{16,})")

_URL = re.compile(r"\b(?:https?|ftp|tftp)://[^\s'\"<>|;&`]+", re.I)
_IP = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
_SSHKEY = re.compile(r"ssh-(?:rsa|ed25519|dss)\s+[A-Za-z0-9+/=]{20,}")
_LONG_B64 = re.compile(r"[A-Za-z0-9+/=]{40,}")
_LONG_HEX = re.compile(r"\b[0-9a-fA-F]{16,}\b")
_DIGITS = re.compile(r"\d+")


@dataclass(frozen=True)
class Normalized:
    original: str                 # обрезанная исходная строка
    text: str                     # деобфусцированный текст (регистр сохранён) + раскодированные вставки
    lower: str                    # text.lower() — вход для правил
    ml: str                       # канонический текст для TF-IDF (URL/IP/хэши/числа заменены токенами)
    decoded: tuple[str, ...] = field(default_factory=tuple)  # что раскодировали (base64)
    truncated: bool = False
    obfuscated: bool = False


def _printable(s: str) -> bool:
    return bool(s) and all(32 <= ord(c) < 127 or c in "\n\t" for c in s)


def _decode_hex_escapes(s: str) -> str:
    """\\x47\\x72 -> 'Gr'. Раскрываем только серии, где ВСЕ байты печатные: `echo -e "\\x6F\\x6B"` -> `ok`.
    Серии с непечатными байтами — это бинарные куски ELF (дроппер пишет вирус через echo -ne), их оставляем как есть,
    чтобы правило могло их увидеть."""
    def repl(m: re.Match) -> str:
        run = m.group(0)
        chars = [chr(int(h, 16)) for h in re.findall(r"[0-9a-fA-F]{2}", run)]
        return "".join(chars) if all(32 <= ord(c) < 127 or c in "\t\n\r" for c in chars) else run
    return _HEXRUN.sub(repl, s)


def _try_b64(blob: str) -> str | None:
    blob = blob.strip("=")
    blob += "=" * (-len(blob) % 4)
    try:
        raw = base64.b64decode(blob, validate=True)
    except (binascii.Error, ValueError):
        return None
    if not raw or len(raw) > MAX_B64_DECODED:
        return None
    txt = raw.decode("utf-8", "ignore")
    return txt if _printable(txt) else None


def _extract_b64(s: str) -> list[str]:
    out: list[str] = []
    frontier = [s]
    for _ in range(MAX_DECODE_ROUNDS):
        nxt: list[str] = []
        for chunk in frontier:
            for rx in (_B64_PIPE, _B64_SUBST):
                for m in rx.finditer(chunk):
                    dec = _try_b64(m.group(1))
                    if dec:
                        out.append(dec)
                        nxt.append(dec)
        frontier = nxt
        if not frontier:
            break
    return out


def deobfuscate(cmd: str) -> tuple[str, tuple[str, ...], bool, bool]:
    """-> (текст, раскодированные вставки, обрезано?, были ли приёмы обфускации?)"""
    truncated = len(cmd) > MAX_LEN
    s = cmd[:MAX_LEN].replace("\x00", " ")
    before = s
    s = _decode_hex_escapes(s)
    s = _IFS.sub(" ", s)
    s = _QUOTE_SPLIT.sub("", s)
    s = _QUOTE_INNER.sub(r"\2", s)
    s = _BACKSLASH_IN_WORD.sub("", s)
    decoded = tuple(_extract_b64(s))
    obf = s != before or bool(decoded)
    if decoded:
        s = s + " ; " + " ; ".join(decoded)
    return _WS.sub(" ", s).strip(), decoded, truncated, obf


def to_ml_text(text: str) -> str:
    """Заменяет «шумные» значения токенами, чтобы модель училась на структуре, а не на конкретных IP/хэшах."""
    t = text.lower()

    def url_repl(m: re.Match) -> str:
        base = m.group(0).rstrip("/").rsplit("/", 1)[-1]
        base = _DIGITS.sub("0", base)[:24]
        return f" urltok fn_{base} "

    t = _SSHKEY.sub(" sshkeytok ", t)
    t = _URL.sub(url_repl, t)
    t = _IP.sub(" iptok ", t)
    t = _LONG_HEX.sub(" hextok ", t)
    t = _LONG_B64.sub(" b64tok ", t)
    t = _HEXBIN_ML.sub(" hexbintok ", t)
    t = _DIGITS.sub("0", t)
    return _WS.sub(" ", t).strip()


def normalize(cmd: str | None) -> Normalized:
    cmd = cmd if isinstance(cmd, str) else ("" if cmd is None else str(cmd))
    text, decoded, truncated, obf = deobfuscate(cmd)
    return Normalized(original=cmd[:MAX_LEN], text=text, lower=text.lower(),
                      ml=to_ml_text(text), decoded=decoded, truncated=truncated, obfuscated=obf)
