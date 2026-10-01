#!/usr/bin/env python3
"""ioc-extract - memungut indikator serangan (IOC) dari teks bebas.

Masukan berupa teks apa saja (tiket, advisory, chat, badan email, log yang
gagal di-parse SIEM). Keluaran berupa daftar IOC yang sudah divalidasi,
disaring dari sampah, dan bebas duplikat.

Alurnya lima tahap:

  1. refang      hxxp -> http, [.] -> ., [at] -> @
  2. ekstraksi   regex per jenis: IPv4, domain, URL, email, MD5, SHA-1, SHA-256, CVE
  3. validasi    oktet 0-255, TLD terdaftar di IANA, tahun CVE masuk akal
  4. penyaringan nomor versi, nama file, potongan kode, ID sesi, alamat khusus, allowlist
  5. keluaran    dedupe + urut, lalu baris / JSON / CSV (defang kecuali --raw)

Hanya memakai pustaka standar Python. Tidak ada koneksi keluar.
"""

from __future__ import annotations

import argparse
import bisect
import codecs
import csv
import io
import ipaddress
import json
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass
from datetime import date
from functools import lru_cache
from pathlib import Path

__version__ = "1.0.0"

DATA_DIR = Path(__file__).resolve().parent / "data"
TLD_FILE = DATA_DIR / "tlds.txt"
DEFAULT_ALLOWLIST = DATA_DIR / "allowlist.txt"

# Urutan jenis IOC pada keluaran.
TYPES = ("ipv4", "domain", "url", "email", "md5", "sha1", "sha256", "cve")
HASH_BY_LENGTH = {32: "md5", 40: "sha1", 64: "sha256"}

# TLD cadangan RFC 2606: dijamin tidak pernah ada di internet, jadi aman untuk
# sampel dan uji. Tidak tercantum di daftar IANA, maka ditambahkan manual.
RESERVED_TLDS = frozenset({"test", "example", "invalid"})

# TLD resmi yang juga lazim sebagai ekstensi file atau nama properti kode.
# "setup.py", "README.md", "Terminal.app", "user.name" jauh lebih sering muncul
# di tiket daripada domain sungguhan berbentuk dua label dengan TLD ini.
AMBIGUOUS_TLDS = frozenset({
    "zip", "mov", "sh", "py", "md", "pl", "rs", "so", "ps", "app", "java", "cc", "name",
})

# Label pertama yang hampir pasti objek dalam potongan kode, bukan nama host:
# "self.name", "document.cookie", "window.location.host".
CODE_RECEIVERS = frozenset({
    "self", "this", "cls", "obj", "req", "res", "ctx", "args", "kwargs",
    "document", "window", "console", "event", "err",
})


# --------------------------------------------------------------------------
# tahap 1: refang / defang
# --------------------------------------------------------------------------

# Karakter tak terlihat yang sering ikut tersalin dari PDF atau halaman web.
# Kalau dibiarkan, "evil​.com" tidak akan cocok dengan pola domain.
_INVISIBLE = re.compile("[​‌‍⁠﻿­]")

# Semua gaya "penjinakan" yang lazim, dalam satu pola. Tiap cabang diberi nama
# supaya fungsi pengganti tahu harus diganti dengan apa. Lookahead pertama
# adalah saringan cepat: cabang-cabang hanya dicoba di posisi yang huruf
# pertamanya memang mungkin (h, f, kurung, spasi) - sekitar 3x lebih cepat.
_FANG = re.compile(
    r"""
    (?=[hf\[({ \t])
    (?:
      (?P<hxxp>\bhxxp(?P<s>s?)(?=[\[(:]))           # hxxp:// hxxps[:]//
    | (?P<fxp>\bfxp(?=[\[(:]))                      # fxp://  -> ftp://
    | \[(?P<sep>:|://|/)\]                          # [:]  [://]  [/]
    | (?P<dot>\[\s*\.\s*\]|\(\s*\.\s*\)|\{\s*\.\s*\}  # [.]  (.)  {.}
        |[ \t]*[\[({]\s*dot\s*[\])}][ \t]*)         # [dot]  " (dot) "
    | (?P<at>\[\s*@\s*\]|\(\s*@\s*\)                # [@]  (@)
        |[ \t]*[\[({]\s*at\s*[\])}][ \t]*)          # [at]  " (at) "
    )
    """,
    re.IGNORECASE | re.VERBOSE,
)


def _fang_replacement(m: re.Match) -> str:
    if m.group("hxxp") is not None:
        return "http" + m.group("s").lower()
    if m.group("fxp") is not None:
        return "ftp"
    if m.group("sep") is not None:
        return m.group("sep")
    if m.group("dot") is not None:
        return "."
    return "@"


def refang_marked(text: str) -> tuple[str, list[tuple[int, int]]]:
    """Seperti refang(), tetapi juga mencatat posisi setiap penggantian.

    Posisi (awal, akhir) di teks hasil dipakai tahap penyaringan: IOC yang
    ditulis dalam bentuk dijinakkan jelas sengaja ditandai penulisnya sebagai
    indikator, jadi tidak boleh dibuang sebagai "mirip nama file".
    """
    text = _INVISIBLE.sub("", text)
    pieces: list[str] = []
    marks: list[tuple[int, int]] = []
    last = length = 0
    for m in _FANG.finditer(text):
        before = text[last:m.start()]
        replacement = _fang_replacement(m)
        pieces += (before, replacement)
        length += len(before)
        marks.append((length, length + len(replacement)))
        length += len(replacement)
        last = m.end()
    pieces.append(text[last:])
    return "".join(pieces), marks


def refang(text: str) -> str:
    """Mengembalikan teks yang dijinakkan ke bentuk aslinya sebelum diekstrak."""
    return refang_marked(text)[0]


def defang(value: str) -> str:
    """Menjinakkan IOC untuk keluaran supaya aman ditempel ke tiket atau chat.

    Sama persis dengan defang() di eml-triage, supaya dua alat ini
    menghasilkan bentuk yang seragam.
    """
    return value.replace("http://", "hxxp://").replace("https://", "hxxps://").replace(".", "[.]")


class _Marks:
    """Pencarian cepat: apakah rentang teks menyentuh bekas penggantian refang."""

    def __init__(self, marks: list[tuple[int, int]]):
        self.starts = [s for s, _ in marks]
        self.ends = [e for _, e in marks]

    def overlaps(self, start: int, end: int) -> bool:
        # tanda tidak saling tumpang tindih dan sudah terurut, jadi cukup
        # periksa tanda terakhir yang dimulai sebelum `end`
        i = bisect.bisect_left(self.starts, end)
        return i > 0 and self.ends[i - 1] > start


# --------------------------------------------------------------------------
# tahap 2: pola regex
# --------------------------------------------------------------------------

# Satu oktet 0-255 tanpa nol di depan ("010" ditolak, sering berarti oktal/versi).
_OCTET = r"(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])"
# Tidak boleh menempel ke huruf/angka/titik di kiri atau kanan, supaya
# "v1.2.3.4" dan "1.2.3.4.5" (versi, OID) tidak terpotong jadi IP.
IPV4_RE = re.compile(rf"(?<![\w.]){_OCTET}(?:\.{_OCTET}){{3}}(?!\w|\.[0-9])")

# Label domain: 1-63 karakter, tidak diawali/diakhiri tanda hubung.
_LABEL = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
_HOSTNAME = rf"(?:{_LABEL}\.)+(?:xn--[a-z0-9-]{{1,59}}|[a-z]{{2,63}})"
# Lookahead "@" mencegah bagian depan alamat email ("john.doe@") ikut jadi domain.
DOMAIN_RE = re.compile(rf"(?<![\w.-]){_HOSTNAME}(?![\w-]|\.[a-z0-9]|@)", re.IGNORECASE)
EMAIL_RE = re.compile(
    rf"(?<![\w.%+-])[a-z0-9][a-z0-9._%+-]{{0,63}}@({_HOSTNAME})(?![\w-]|\.[a-z0-9])",
    re.IGNORECASE,
)
# URL berhenti di spasi, tanda kutip, dan kurung siku/kurawal. Tanda baca di
# ujung (titik, koma, kurung tutup yang tidak berpasangan) dipangkas belakangan.
URL_RE = re.compile(r"\b(?:https?|ftp)://[^\s<>\"'`|\\^{}\[\]]+", re.IGNORECASE)
# Panjang persis 32/40/64 karena tidak boleh menempel ke huruf atau angka lain.
HASH_RE = re.compile(
    r"(?<![0-9a-z])(?:[0-9a-f]{64}|[0-9a-f]{40}|[0-9a-f]{32})(?![0-9a-z])", re.IGNORECASE
)
# Tanda hubung apa saja: PDF sering mengubah "-" menjadi en dash.
CVE_RE = re.compile(r"\bCVE[-‐-―]([0-9]{4})[-‐-―]([0-9]{4,7})\b", re.IGNORECASE)

# Kata tepat di depan sebuah "IP" yang menandakan itu sebenarnya nomor versi
# ("Chrome 120.0.0.1", "versi 7.2.0.15") atau penomoran bab ("Bagian 2.1.3.4").
_VERSION_BEFORE = re.compile(
    r"(?:\b(?:v|ver|version|versi|build|release|rilis|rev|revision|firmware|fw"
    r"|section|bagian|bab|pasal)\.?"
    r"|\b(?:chrome|chromium|firefox|edge|safari|opera|windows|android|ios|macos"
    r"|openssl|java|python|php|nginx|apache|kernel))"
    r"\s*[:=#/]?\s*$",
    re.IGNORECASE,
)

# Kata kunci tepat di depan string hex yang menandakan itu ID sesi, token,
# atau commit git, bukan hash file: "session_id=...", "X-Request-ID: ...".
_SECRET_BEFORE = re.compile(
    r"\b\w*?(?:session|sess|token|cookie|nonce|csrf|xsrf|trace|correlation|etag|secret"
    r"|signature|commit|guid|uuid|salt|api[-_]?key|request[-_]?id|req[-_]?id)"
    r"[\w-]*[\"']?\s*(?:[:=]|\s)\s*[\"']?$",
    re.IGNORECASE,
)


def _prefix(text: str, start: int, width: int = 60) -> str:
    """Potongan teks di baris yang sama, tepat sebelum posisi `start`."""
    line_start = text.rfind("\n", 0, start) + 1
    return text[max(line_start, start - width):start]


# --------------------------------------------------------------------------
# tahap 3: validasi
# --------------------------------------------------------------------------

@lru_cache(maxsize=1)
def known_tlds() -> frozenset[str] | None:
    """Daftar TLD resmi IANA dari data/tlds.txt (disalin sekali, dibaca offline).

    None berarti berkasnya hilang; validasi lalu jatuh ke aturan longgar.
    """
    try:
        lines = TLD_FILE.read_text(encoding="ascii").splitlines()
    except OSError:
        return None
    tlds = {line.strip().lower() for line in lines if line.strip() and not line.startswith("#")}
    return frozenset(tlds) | RESERVED_TLDS


def valid_tld(tld: str) -> bool:
    tlds = known_tlds()
    if tlds is None:
        return tld.isalpha() or tld.lower().startswith("xn--")
    return tld.lower() in tlds


def valid_domain(domain: str) -> bool:
    """Domain sah = panjang wajar dan TLD-nya benar-benar ada."""
    return len(domain) <= 253 and "." in domain and valid_tld(domain.rsplit(".", 1)[1])


def _nets(*cidrs: str) -> tuple[ipaddress.IPv4Network, ...]:
    return tuple(ipaddress.IPv4Network(c) for c in cidrs)


INTERNAL_NETS = _nets("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "169.254.0.0/16")
DOCUMENTATION_NETS = _nets("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")
SPECIAL_NETS = (
    (ipaddress.IPv4Network("0.0.0.0/8"), "alamat 'this network'"),
    (ipaddress.IPv4Network("127.0.0.0/8"), "loopback"),
    (ipaddress.IPv4Network("224.0.0.0/4"), "multicast"),
    (ipaddress.IPv4Network("240.0.0.0/4"), "alamat cadangan / broadcast"),
)


def ip_scope(value: str) -> str:
    """public / internal / documentation - menentukan boleh tidaknya diblokir di perimeter."""
    ip = ipaddress.IPv4Address(value)
    if any(ip in net for net in INTERNAL_NETS):
        return "internal"
    if any(ip in net for net in DOCUMENTATION_NETS):
        return "documentation"
    return "public"


def ip_problem(value: str) -> str | None:
    """Alasan sebuah IPv4 bukan IOC (netmask, loopback, ...), atau None kalau layak."""
    number = int(ipaddress.IPv4Address(value))
    inverted = ~number & 0xFFFFFFFF
    if number >> 24 == 255 and inverted & (inverted + 1) == 0:
        return "netmask"
    ip = ipaddress.IPv4Address(value)
    for net, reason in SPECIAL_NETS:
        if ip in net:
            return reason
    return None


# --------------------------------------------------------------------------
# tahap 4: allowlist
# --------------------------------------------------------------------------

class Allowlist:
    """Nilai yang sengaja diabaikan. Satu entri per baris, komentar diawali '#':

        perusahaan.co.id   domain beserta semua subdomainnya
        10.20.0.0/16       IP tunggal atau rentang CIDR
        <hash> / CVE-...   nilai persis
    """

    def __init__(self, entries: tuple[str, ...] | list[str] = ()):
        self.domains: set[str] = set()
        self.networks: list[ipaddress.IPv4Network] = []
        self.values: set[str] = set()
        for entry in entries:
            self.add(entry)

    def add(self, entry: str) -> None:
        entry = entry.split("#", 1)[0].strip().lower()
        if not entry:
            return
        try:
            self.networks.append(ipaddress.IPv4Network(entry, strict=False))
            return
        except ValueError:
            pass
        if HASH_RE.fullmatch(entry) or CVE_RE.fullmatch(entry):
            self.values.add(entry)
        else:
            self.domains.add(entry.removeprefix("*.").strip("."))

    def load_file(self, path: str | Path) -> None:
        for line in Path(path).read_text(encoding="utf-8").splitlines():
            self.add(line)

    def match_domain(self, host: str) -> str | None:
        labels = host.lower().split(".")
        for i in range(len(labels)):
            candidate = ".".join(labels[i:])
            if candidate in self.domains:
                return candidate
        return None

    def match_ip(self, value: str) -> str | None:
        ip = ipaddress.IPv4Address(value)
        for net in self.networks:
            if ip in net:
                return str(net.network_address) if net.num_addresses == 1 else str(net)
        return None

    def match_value(self, value: str) -> str | None:
        return "nilai persis" if value.lower() in self.values else None


def default_allowlist() -> Allowlist:
    allow = Allowlist()
    if DEFAULT_ALLOWLIST.exists():
        allow.load_file(DEFAULT_ALLOWLIST)
    return allow


def _allowed(entry: str | None) -> str | None:
    return f"allowlist ({entry})" if entry else None


# --------------------------------------------------------------------------
# ekstraksi: menggabungkan tahap 1-4
# --------------------------------------------------------------------------

@dataclass
class Indicator:
    type: str
    value: str
    count: int = 1
    scope: str = ""  # khusus ipv4: public / internal / documentation


@dataclass
class Dropped:
    type: str
    value: str
    reason: str


@dataclass
class Result:
    indicators: list[Indicator]
    dropped: list[Dropped]

    def values(self, ioc_type: str) -> list[str]:
        return [i.value for i in self.indicators if i.type == ioc_type]


def _sort_key(item: Indicator | Dropped) -> tuple:
    value = item.value
    if item.type == "ipv4":
        key: tuple = (int(ipaddress.IPv4Address(value)),)
    elif item.type == "domain":
        key = tuple(reversed(value.split(".")))  # subdomain berkumpul dengan induknya
    elif item.type == "cve":
        _, year, number = value.split("-")
        key = (int(year), int(number))
    else:
        key = (value,)
    return TYPES.index(item.type), key


class _Collector:
    """Mencatat setiap kemunculan.

    Sebuah nilai dipertahankan kalau MINIMAL SATU kemunculannya lolos saring.
    Alasan buang hanya dilaporkan untuk nilai yang seluruh kemunculannya gugur.
    """

    def __init__(self) -> None:
        self.kept: dict[tuple[str, str], int] = {}
        self.reasons: dict[tuple[str, str], str] = {}

    def add(self, ioc_type: str, value: str, reason: str | None) -> None:
        key = (ioc_type, value)
        if reason is None:
            self.kept[key] = self.kept.get(key, 0) + 1
        else:
            self.reasons.setdefault(key, reason)

    def result(self) -> Result:
        indicators = [
            Indicator(t, v, n, ip_scope(v) if t == "ipv4" else "")
            for (t, v), n in self.kept.items()
        ]
        dropped = [Dropped(t, v, r) for (t, v), r in self.reasons.items() if (t, v) not in self.kept]
        return Result(sorted(indicators, key=_sort_key), sorted(dropped, key=_sort_key))


def _split_url(url: str) -> tuple[str, str, str]:
    scheme, rest = url.split("://", 1)
    authority = re.match(r"[^/?#]*", rest).group(0)
    return scheme, authority, rest[len(authority):]


def _normalize_url(url: str) -> str:
    """Skema dan host ditulis huruf kecil; path dibiarkan (path peka huruf besar)."""
    scheme, authority, tail = _split_url(url)
    return f"{scheme.lower()}://{authority.lower()}{tail}"


def _url_host(url: str) -> str:
    authority = _split_url(url)[1]
    return authority.rsplit("@", 1)[-1].split(":", 1)[0].rstrip(".").lower()


_URL_TRAILING = ".,;:!?*'\"…”’»"


def _trim_url(url: str) -> str:
    """Memangkas tanda baca kalimat yang ikut tertangkap di ujung URL."""
    while url:
        if url[-1] in _URL_TRAILING:
            url = url[:-1]
        elif url[-1] == ")" and url.count(")") > url.count("("):
            url = url[:-1]
        else:
            break
    return url


def _hash_problem(value: str, prefix: str) -> str | None:
    if not (any(c.isdigit() for c in value) and any(c.isalpha() for c in value)):
        return "hanya angka atau hanya huruf (bukan hash)"
    if len(set(value)) < 6:
        return "pola berulang (bukan hash)"
    if _SECRET_BEFORE.search(prefix):
        return "ID sesi / token / commit"
    return None


def _domain_problem(raw: str, labels: list[str], next_char: str) -> str | None:
    """Heuristik untuk domain yang TIDAK punya konteks tegas (bukan host URL,
    bukan domain email, tidak ditulis dijinakkan)."""
    tld_raw = raw.rsplit(".", 1)[1]
    if raw not in (raw.lower(), raw.upper()) and not tld_raw.islower():
        return "TLD berhuruf kapital (gaya namespace/nama, bukan domain)"
    if labels[0] in CODE_RECEIVERS:
        return "mirip potongan kode (objek.properti)"
    if next_char == "(":
        return "mirip pemanggilan fungsi"
    if len(labels) == 2 and labels[1] in AMBIGUOUS_TLDS:
        return "mirip nama file"
    return None


def extract(text: str, allowlist: Allowlist | None = None) -> Result:
    """Inti alat: teks bebas masuk, daftar IOC yang sudah disaring keluar."""
    text, marks = refang_marked(text)
    defanged = _Marks(marks)
    allow = allowlist or Allowlist()
    found = _Collector()

    # URL dan email diproses lebih dulu: host-nya menjadi "konteks tegas" yang
    # membebaskan domain yang sama dari heuristik nama file / potongan kode.
    explicit_hosts: set[str] = set()

    for m in URL_RE.finditer(text):
        url = _normalize_url(_trim_url(m.group(0)))
        host = _url_host(url)
        if not host:
            continue
        if IPV4_RE.fullmatch(host):
            reason = ip_problem(host) or _allowed(allow.match_ip(host))
        elif valid_domain(host):
            explicit_hosts.add(host)
            reason = _allowed(allow.match_domain(host))
        else:
            reason = "host bukan domain publik atau IPv4"
        found.add("url", url, reason)

    for m in EMAIL_RE.finditer(text):
        domain = m.group(1).lower()
        if valid_domain(domain):
            explicit_hosts.add(domain)
            found.add("email", m.group(0).lower(), _allowed(allow.match_domain(domain)))

    for m in IPV4_RE.finditer(text):
        ip = m.group(0)
        reason = ip_problem(ip)
        if reason is None and _VERSION_BEFORE.search(_prefix(text, m.start())):
            reason = "nomor versi atau penomoran"
        found.add("ipv4", ip, reason or _allowed(allow.match_ip(ip)))

    for m in DOMAIN_RE.finditer(text):
        raw = m.group(0)
        domain = raw.lower()
        if not valid_domain(domain):
            continue  # "setup.exe", "kernel32.dll": bukan bentuk domain sama sekali
        reason = None
        if domain not in explicit_hosts and not defanged.overlaps(m.start(), m.end()):
            reason = _domain_problem(raw, domain.split("."), text[m.end():m.end() + 1])
        found.add("domain", domain, reason or _allowed(allow.match_domain(domain)))

    for m in HASH_RE.finditer(text):
        value = m.group(0).lower()
        reason = _hash_problem(value, _prefix(text, m.start()))
        found.add(HASH_BY_LENGTH[len(value)], value, reason or _allowed(allow.match_value(value)))

    this_year = date.today().year
    for m in CVE_RE.finditer(text):
        value = f"CVE-{m.group(1)}-{m.group(2)}"
        if 1999 <= int(m.group(1)) <= this_year + 1:
            reason = _allowed(allow.match_value(value))
        else:
            reason = "tahun CVE tidak masuk akal"
        found.add("cve", value, reason)

    return found.result()


# --------------------------------------------------------------------------
# tahap 5: keluaran
# --------------------------------------------------------------------------

SCOPE_LABEL = {"internal": "internal", "documentation": "dokumentasi"}


def _shown(value: str, raw: bool) -> str:
    return value if raw else defang(value)


def render_lines(result: Result, raw: bool = False, values_only: bool = False) -> str:
    lines = []
    for ind in result.indicators:
        value = _shown(ind.value, raw)
        if values_only:
            lines.append(value)
        else:
            tag = f"  [{SCOPE_LABEL[ind.scope]}]" if ind.scope in SCOPE_LABEL else ""
            lines.append(f"{ind.type:<7} {value}{tag}")
    return "\n".join(lines)


def render_dropped(result: Result, raw: bool = False) -> str:
    return "\n".join(
        f"# dibuang  {d.type:<7} {_shown(d.value, raw)}  <- {d.reason}" for d in result.dropped
    )


def render_json(result: Result, raw: bool = False, show_dropped: bool = False) -> str:
    summary: dict[str, int] = {}
    for ind in result.indicators:
        summary[ind.type] = summary.get(ind.type, 0) + 1
    doc: dict = {
        "tool": "ioc-extract",
        "version": __version__,
        "defanged": not raw,
        "summary": summary,
        "indicators": [
            {"type": i.type, "value": _shown(i.value, raw), "count": i.count,
             **({"scope": i.scope} if i.scope else {})}
            for i in result.indicators
        ],
    }
    if show_dropped:
        doc["dropped"] = [
            {"type": d.type, "value": _shown(d.value, raw), "reason": d.reason} for d in result.dropped
        ]
    return json.dumps(doc, indent=2, ensure_ascii=False)


def render_csv(result: Result, raw: bool = False) -> str:
    # Aman dari formula injection Excel: setiap nilai diawali huruf/angka,
    # tidak pernah "=", "+", "-", atau "@".
    buffer = io.StringIO()
    writer = csv.writer(buffer, lineterminator="\n")
    writer.writerow(["type", "value", "count", "scope"])
    for ind in result.indicators:
        writer.writerow([ind.type, _shown(ind.value, raw), ind.count, ind.scope])
    return buffer.getvalue().rstrip("\n")


def only_types(result: Result, types: list[str]) -> Result:
    return Result(
        [i for i in result.indicators if i.type in types],
        [d for d in result.dropped if d.type in types],
    )


# --------------------------------------------------------------------------
# masukan + CLI
# --------------------------------------------------------------------------

def decode(data: bytes) -> str:
    """Byte -> teks. Menangani UTF-16 ber-BOM (hasil `>` di PowerShell 5.1)."""
    if data.startswith(codecs.BOM_UTF8):
        return data[len(codecs.BOM_UTF8):].decode("utf-8", "replace")
    if data.startswith((codecs.BOM_UTF16_LE, codecs.BOM_UTF16_BE)):
        return data.decode("utf-16", "replace")
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return data.decode("cp1252", "replace")


def read_clipboard() -> str:
    """Membaca clipboard lewat perintah bawaan sistem operasi (tanpa pustaka tambahan)."""
    if sys.platform == "win32":
        command = ["powershell", "-NoProfile", "-NonInteractive", "-Command",
                   "[Console]::OutputEncoding=[Text.Encoding]::UTF8; Get-Clipboard -Raw"]
    elif sys.platform == "darwin":
        command = ["pbpaste"]
    else:
        for candidate in (["wl-paste", "--no-newline"], ["xclip", "-selection", "clipboard", "-o"],
                          ["xsel", "--clipboard", "--output"]):
            if shutil.which(candidate[0]):
                command = candidate
                break
        else:
            raise RuntimeError("clipboard tidak bisa dibaca: pasang wl-paste, xclip, atau xsel")
    try:
        completed = subprocess.run(command, capture_output=True, timeout=15, check=True)
    except (OSError, subprocess.SubprocessError) as exc:
        raise RuntimeError(f"clipboard tidak bisa dibaca lewat {command[0]} ({type(exc).__name__})") from exc
    return decode(completed.stdout)


def read_input(files: list[str], clip: bool) -> str:
    parts = []
    if clip:
        parts.append(read_clipboard())
    for name in files or ([] if clip else ["-"]):
        if name == "-":
            if sys.stdin is None or sys.stdin.isatty():
                raise RuntimeError("tidak ada masukan: beri nama berkas, --clip, atau alirkan lewat stdin")
            parts.append(decode(sys.stdin.buffer.read()))
        else:
            parts.append(decode(Path(name).read_bytes()))
    return "\n".join(parts)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ioc-extract",
        description="Memungut IOC (IPv4, domain, URL, email, MD5/SHA-1/SHA-256, CVE) dari teks bebas. "
                    "Tidak ada koneksi keluar.",
        epilog="Kode keluar: 0 = ada IOC, 1 = tidak ada IOC, 2 = galat.",
    )
    parser.add_argument("files", nargs="*", metavar="BERKAS", help="berkas teks; '-' atau kosong = stdin")
    parser.add_argument("--clip", action="store_true", help="baca dari clipboard")
    fmt = parser.add_mutually_exclusive_group()
    fmt.add_argument("--json", action="store_true", help="keluaran JSON")
    fmt.add_argument("--csv", action="store_true", help="keluaran CSV")
    parser.add_argument("--raw", action="store_true", help="jangan defang keluaran (untuk diolah mesin)")
    parser.add_argument("-t", "--type", metavar="JENIS",
                        help=f"hanya jenis tertentu, dipisah koma: {','.join(TYPES)}")
    parser.add_argument("--values-only", action="store_true", help="cetak nilainya saja, satu per baris")
    parser.add_argument("--allowlist", action="append", default=[], metavar="BERKAS",
                        help="allowlist tambahan (boleh diulang)")
    parser.add_argument("--no-default-allowlist", action="store_true", help="jangan pakai data/allowlist.txt")
    parser.add_argument("--show-dropped", action="store_true",
                        help="tampilkan apa saja yang dibuang beserta alasannya")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(errors="backslashreplace")  # konsol cp1252 tidak ikut mogok

    types = [t.strip().lower() for t in (args.type or "").split(",") if t.strip()]
    unknown = [t for t in types if t not in TYPES]
    if unknown:
        parser.error(f"jenis tidak dikenal: {', '.join(unknown)} (pilihan: {', '.join(TYPES)})")

    try:
        text = read_input(args.files, args.clip)
        allow = Allowlist() if args.no_default_allowlist else default_allowlist()
        for path in args.allowlist:
            allow.load_file(path)
    except (OSError, RuntimeError, subprocess.SubprocessError) as exc:
        print(f"ioc-extract: {exc}", file=sys.stderr)
        return 2

    result = extract(text, allow)
    if types:
        result = only_types(result, types)

    if args.json:
        output = render_json(result, args.raw, args.show_dropped)
    elif args.csv:
        output = render_csv(result, args.raw)
    else:
        output = render_lines(result, args.raw, args.values_only)
    if output:
        print(output)
    sys.stdout.flush()  # supaya daftar buangan (stderr) selalu tampil SETELAH hasil
    if args.show_dropped and not args.json and result.dropped:
        print(render_dropped(result, args.raw), file=sys.stderr)
    return 0 if result.indicators else 1


if __name__ == "__main__":
    sys.exit(main())
