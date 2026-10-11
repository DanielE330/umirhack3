"""Нормализация и деобфускация текста команды.

Правило: все регулярки здесь без вложенных кванторов (линейные), а вход
обрезается до MAX_LEN — атакующий контролирует строку целиком, и ReDoS на
сервисе-анализаторе был бы самой глупой уязвимостью в системе безопасности.
"""
from __future__ import annotations

import base64
import binascii
import fnmatch
import re
import zlib
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

_ANSI_C = re.compile(r"\$'([^'\\]{0,200})'")             # $'wget' (после раскрытия \x..) -> wget
_OCTRUN = re.compile(r"(?:\\[0-3][0-7]{2}){2,}")             # \167\147\145\164 -> wget
_ASSIGN = re.compile(r"(?:^|[;&\s])([A-Za-z_][A-Za-z0-9_]{0,15})=([A-Za-z0-9./:_-]{1,40})(?=[;&\s]|$)")
_REV = re.compile(r"echo\s+(?:-[a-z]+\s+)?['\"]?([^'\"|;&]{3,200}?)['\"]?\s*\|\s*rev\b")
_GLOB_TOKEN = re.compile(r"(?<![\w/])/[\w?*\[\]]{1,12}(?:/[\w?*\[\]]{1,16}){0,2}")
_GLOB_TARGETS = ("/bin/sh", "/bin/bash", "/bin/dash", "/bin/busybox", "/bin/nc", "/bin/cat", "/bin/echo", "/bin/rm",
                 "/usr/bin/wget", "/usr/bin/curl", "/usr/bin/nc", "/usr/bin/perl", "/usr/bin/python", "/usr/bin/python3",
                 "/usr/bin/base64", "/usr/bin/chmod", "/bin/chmod", "/etc/passwd", "/etc/shadow", "/usr/bin/tftp")
MAX_GZIP_OUT = 4096
_VAR_TRICK = re.compile(r"\$\{?[A-Za-z_]\w*\}?\$\{?[A-Za-z_]|(?:^|[;&|]\s*)\$\{?[A-Za-z_]\w*\}?\s")

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


def _decode_octal_escapes(s: str) -> str:
    """\\167\\147\\145\\164 -> wget (printf/$'...' с восьмеричными кодами); только если все байты печатные."""
    def repl(m: re.Match) -> str:
        chars = [chr(int(o, 8)) for o in re.findall(r"[0-7]{3}", m.group(0))]
        return "".join(chars) if all(32 <= ord(c) < 127 for c in chars) else m.group(0)
    return _OCTRUN.sub(repl, s)


def _expand_vars(s: str) -> str:
    """a=wg;b=et;$a$b http://x -> wget http://x. Только простые литералы, не больше 20 переменных, без рекурсии."""
    env: dict[str, str] = {}
    for m in _ASSIGN.finditer(s):
        if len(env) >= 20:
            break
        env[m.group(1)] = m.group(2)
    if not env:
        return s
    for name, val in env.items():
        s = s.replace("${" + name + "}", val)
        s = re.sub(r"\$" + re.escape(name) + r"(?![A-Za-z0-9_])", lambda _m, v=val: v, s)
    return s


def _resolve_globs(s: str) -> str:
    """/???/b??h -> /bin/bash: путь-маска, совпадающая ровно с одним известным бинарём/файлом."""
    def repl(m: re.Match) -> str:
        tok = m.group(0)
        if "?" not in tok and "*" not in tok and "[" not in tok:
            return tok
        hits = [t for t in _GLOB_TARGETS if fnmatch.fnmatchcase(t, tok)]
        return hits[0] if len(hits) == 1 else tok
    return _GLOB_TOKEN.sub(repl, s)


def _try_b64(blob: str) -> str | None:
    blob = blob.strip("=")
    blob += "=" * (-len(blob) % 4)
    try:
        raw = base64.b64decode(blob, validate=True)
    except (binascii.Error, ValueError):
        return None
    if not raw or len(raw) > MAX_B64_DECODED:
        return None
    if raw[:2] == b"\x1f\x8b":          # echo <b64> | base64 -d | gunzip — распаковываем с потолком (защита от zip-бомбы)
        try:
            d = zlib.decompressobj(16 + zlib.MAX_WBITS)
            raw = d.decompress(raw, MAX_GZIP_OUT)
        except zlib.error:
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
    s = _decode_octal_escapes(s)
    s = _ANSI_C.sub(r"\1", s)
    s = _IFS.sub(" ", s)
    s = _QUOTE_SPLIT.sub("", s)
    s = _QUOTE_INNER.sub(r"\2", s)
    s = _BACKSLASH_IN_WORD.sub("", s)
    pre_vars = s
    s = _expand_vars(s)
    # подстановка переменных — обфускация, только если переменные склеиваются ($a$b) или стоят на месте команды
    vars_obf = s != pre_vars and bool(_VAR_TRICK.search(pre_vars))
    pre_glob = s
    s = _resolve_globs(s)
    rev = [m.group(1)[::-1] for m in _REV.finditer(s)][:3]
    decoded = tuple(_extract_b64(s)) + tuple(rev)
    obf = pre_vars != before or vars_obf or s != pre_glob or bool(decoded)
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
