"""Untrusted text handling for scanner exports.

Everything a scanner writes is data about hostile systems, and some of it
(banners, HTTP bodies, plugin output) was written *by* those systems. The
rules applied here are:

* Dropped outright and never stored: plugin output, descriptions, synopses,
  solution text, "see also" links, banners and any other free text. Parsers
  simply do not read those fields.
* Kept after cleaning: hostnames, FQDNs, IP addresses, plugin names, tags and
  operating system labels. Cleaning is allowlist based (characters outside
  the allowlist are removed, not escaped), whitespace is collapsed and the
  result is length capped.
* Identifiers (CVE IDs, plugin IDs, ports, severities, dates) are parsed into
  typed values or rejected.

Nothing here raises on bad input; a value that cannot be cleaned becomes
``None`` (or an empty tuple) and the caller decides whether the record is
still usable.
"""

from __future__ import annotations

import ipaddress
import re
import unicodedata
from datetime import datetime, timedelta, timezone
from typing import Iterable, Optional

# Printable ASCII subset used for names and labels. Quotes, angle brackets,
# backticks, semicolons, braces and dollar signs are deliberately excluded so
# that cleaned names are inert in shells, HTML, JSON and Markdown tables.
_NAME_ALLOWED = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 ._()/:,+-'")
_TAG_ALLOWED = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 ._:/-")

MAX_NAME_LEN = 120
MAX_TAG_LEN = 64
MAX_HOSTNAME_LEN = 253

_CVE_RE = re.compile(r"CVE-(\d{4})-(\d{4,9})", re.IGNORECASE)
_WS_RE = re.compile(r"\s+")
# Fast path for ISO 8601 as Tenable and CISA write it: date, optional time, optional fraction, optional zone.
_ISO_RE = re.compile(r"(\d{4})-(\d{2})-(\d{2})(?:[T ](\d{2}):(\d{2}):(\d{2})(?:\.\d{1,9})?([Zz]|[+-]\d{2}:?\d{2})?)?")
_HOST_LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")

SEVERITY_NAMES = {0: "info", 1: "low", 2: "medium", 3: "high", 4: "critical"}
_SEVERITY_BY_NAME = {v: k for k, v in SEVERITY_NAMES.items()}
_SEVERITY_BY_NAME.update({"informational": 0, "none": 0})

_PROTOCOLS = {"tcp", "udp", "icmp", "sctp"}


_PUNCTUATION_FOLD = str.maketrans(
    {
        "‘": "'",  # left single quotation mark
        "’": "'",  # right single quotation mark
        "“": '"',  # left double quotation mark
        "”": '"',  # right double quotation mark
        "–": "-",  # en dash
        "—": "-",  # em dash
        "−": "-",  # minus sign
        " ": " ",  # no-break space
    }
)


def _as_text(value: object) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        value = value.decode("utf-8", "replace")
    if not isinstance(value, str):
        value = str(value)
    # Typographic punctuation folds to ASCII, then NFKC folds look-alike and
    # full-width characters, before the allowlist is applied.
    return unicodedata.normalize("NFKC", value.translate(_PUNCTUATION_FOLD))


def clean_text(value: object, max_len: int = MAX_NAME_LEN, allowed: Optional[set] = None) -> str:
    """Return ``value`` reduced to an allowlisted character set.

    Characters outside the allowlist are removed. Runs of whitespace collapse
    to one space. The result is stripped and cut at ``max_len``.
    """
    allowed = _NAME_ALLOWED if allowed is None else allowed
    text = _as_text(value)
    kept = "".join(ch if ch in allowed else " " for ch in text)
    kept = _WS_RE.sub(" ", kept).strip()
    if len(kept) > max_len:
        kept = kept[:max_len].rstrip()
    return kept


def clean_name(value: object) -> str:
    """Plugin names, operating system labels and other short labels."""
    return clean_text(value, MAX_NAME_LEN, _NAME_ALLOWED)


def clean_tag(value: object) -> str:
    """Asset tags such as ``group:web-tier`` or ``owner:platform``."""
    return clean_text(value, MAX_TAG_LEN, _TAG_ALLOWED)


def clean_hostname(value: object) -> Optional[str]:
    """Lower-case DNS name made only of valid labels, or ``None``."""
    text = _as_text(value).strip().lower().rstrip(".")
    if not text or len(text) > MAX_HOSTNAME_LEN:
        return None
    if clean_ip(text) is not None:
        return None  # an IP address is not a hostname; callers keep it as an IP
    labels = text.split(".")
    if not all(_HOST_LABEL_RE.match(label) for label in labels):
        return None
    return text


def clean_ip(value: object) -> Optional[str]:
    """Canonical IPv4/IPv6 text, or ``None``."""
    text = _as_text(value).strip()
    if not text or len(text) > 45:
        return None
    try:
        return str(ipaddress.ip_address(text))
    except ValueError:
        return None


def clean_cve(value: object) -> Optional[str]:
    """``CVE-YYYY-NNNN`` in canonical upper-case form, or ``None``."""
    text = _as_text(value).strip()
    match = _CVE_RE.fullmatch(text)
    if not match:
        return None
    year = int(match.group(1))
    if year < 1999 or year > 2100:
        return None
    return f"CVE-{match.group(1)}-{match.group(2)}"


def extract_cves(value: object) -> tuple:
    """Collect canonical CVE IDs from a list, a tuple or a delimited string."""
    found = []
    if isinstance(value, (list, tuple, set)):
        parts: Iterable[object] = value
    else:
        text = _as_text(value)
        parts = [m.group(0) for m in _CVE_RE.finditer(text)]
    for part in parts:
        cve = clean_cve(part)
        if cve and cve not in found:
            found.append(cve)
    found.sort()
    return tuple(found)


def to_int(value: object, lo: int, hi: int) -> Optional[int]:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        number = value
    else:
        text = _as_text(value).strip()
        if not text:
            return None
        try:
            number = int(float(text)) if "." in text else int(text)
        except ValueError:
            return None
    if number < lo or number > hi:
        return None
    return number


def to_float(value: object, lo: float, hi: float) -> Optional[float]:
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        number = float(value)
    else:
        text = _as_text(value).strip()
        if not text:
            return None
        try:
            number = float(text)
        except ValueError:
            return None
    if number != number or number < lo or number > hi:  # NaN or out of range
        return None
    return number


def to_bool(value: object) -> Optional[bool]:
    if isinstance(value, bool):
        return value
    text = _as_text(value).strip().lower()
    if text in {"true", "yes", "1", "y"}:
        return True
    if text in {"false", "no", "0", "n"}:
        return False
    return None


def clean_severity(value: object) -> Optional[int]:
    """Severity as 0..4 from an integer or a Tenable severity name."""
    number = to_int(value, 0, 4)
    if number is not None:
        return number
    text = _as_text(value).strip().lower()
    return _SEVERITY_BY_NAME.get(text)


def clean_protocol(value: object) -> Optional[str]:
    text = _as_text(value).strip().lower()
    return text if text in _PROTOCOLS else None


def clean_port(value: object) -> Optional[int]:
    return to_int(value, 0, 65535)


_DATE_FORMATS = (
    "%Y-%m-%dT%H:%M:%S.%fZ",
    "%Y-%m-%dT%H:%M:%SZ",
    "%Y-%m-%dT%H:%M:%S.%f%z",
    "%Y-%m-%dT%H:%M:%S%z",
    "%Y-%m-%dT%H:%M:%S",
    "%Y-%m-%d %H:%M:%S",
    "%Y-%m-%d",
    "%a %b %d %H:%M:%S %Y",  # Nessus HOST_START / HOST_END
)


def clean_datetime(value: object) -> Optional[str]:
    """UTC timestamp ``YYYY-MM-DDTHH:MM:SSZ`` from common export formats."""
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        seconds = float(value)
        if seconds > 10_000_000_000:  # milliseconds
            seconds /= 1000.0
        if seconds < 0 or seconds > 4_102_444_800:  # 1970 .. 2100
            return None
        return datetime.fromtimestamp(seconds, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    text = _as_text(value).strip()
    if not text or len(text) > 40:
        return None
    if text.isdigit():
        return clean_datetime(int(text))
    fast = _ISO_RE.fullmatch(text)
    if fast:
        year, month, day = int(fast.group(1)), int(fast.group(2)), int(fast.group(3))
        hour, minute, second = int(fast.group(4) or 0), int(fast.group(5) or 0), int(fast.group(6) or 0)
        if 1970 <= year <= 2100:
            try:
                parsed = datetime(year, month, day, hour, minute, second, tzinfo=timezone.utc)
            except ValueError:
                return None
            offset = fast.group(7)
            if offset and offset not in ("Z", "z"):
                sign = -1 if offset[0] == "-" else 1
                parsed -= sign * timedelta(hours=int(offset[1:3]), minutes=int(offset[4:6]))
            return parsed.strftime("%Y-%m-%dT%H:%M:%SZ")
        return None
    for fmt in _DATE_FORMATS:
        try:
            parsed = datetime.strptime(text, fmt)
        except ValueError:
            continue
        if parsed.tzinfo is not None:
            parsed = parsed.astimezone(timezone.utc)
        if parsed.year < 1970 or parsed.year > 2100:
            return None
        return parsed.strftime("%Y-%m-%dT%H:%M:%SZ")
    return None


def clean_date(value: object) -> Optional[str]:
    """``YYYY-MM-DD`` (UTC) or ``None``."""
    stamp = clean_datetime(value)
    return stamp[:10] if stamp else None
