"""Untrusted-text handling for scanner exports.

Scanner exports carry free text written by plugins, services and whoever
named the asset. None of it is trusted. Plugin output, synopsis, description
and solution fields are never read at all. The few names we keep (plugin
name, hostname, tag values) pass through these functions first.
"""

from __future__ import annotations

import re
import unicodedata

_SAFE_TEXT = re.compile(r"[^A-Za-z0-9 .,:;_/()+#&'\-]")
_SPACES = re.compile(r"\s+")
_HOST = re.compile(r"^(?=.{1,253}$)[A-Za-z0-9](?:[A-Za-z0-9-]{0,62})(?:\.[A-Za-z0-9-]{1,63})*$")
_IPV4 = re.compile(r"^(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}$")
_CVE = re.compile(r"^CVE-\d{4}-\d{4,7}$")
_TAG = re.compile(r"[^A-Za-z0-9 ._\-]")


def clean_text(value: object, limit: int = 120) -> str:
    """Return a short, plain, single-line rendering of untrusted text."""
    if value is None:
        return ""
    text = unicodedata.normalize("NFKC", str(value))
    text = "".join(ch if ch.isprintable() else " " for ch in text)
    text = _SAFE_TEXT.sub(" ", text)
    text = _SPACES.sub(" ", text).strip()
    if len(text) > limit:
        text = text[: limit - 1].rstrip() + "…"
    return text


def clean_host(value: object) -> str | None:
    """Return a syntactically valid hostname, or None."""
    if not isinstance(value, str):
        return None
    value = value.strip().rstrip(".").lower()
    return value if _HOST.match(value) else None


def clean_ipv4(value: object) -> str | None:
    if isinstance(value, str) and _IPV4.match(value.strip()):
        return value.strip()
    return None


def clean_cve(value: object) -> str | None:
    if isinstance(value, str):
        value = value.strip().upper()
        if _CVE.match(value):
            return value
    return None


def clean_tag(value: object, limit: int = 40) -> str:
    text = _TAG.sub("", unicodedata.normalize("NFKC", str(value or "")))
    return text.strip()[:limit]
