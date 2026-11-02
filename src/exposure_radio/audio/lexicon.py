"""Spoken-form lexicon.

Turns the written narration into text a speech engine says well: CVE ids
read as letters and digit groups, years as "twenty twenty-six", vendor and
product names with their house pronunciations, acronyms spelled out. The
mapping is data (``data/lexicon.json``) so a listener can tune it without
touching code. The WebVTT transcript keeps the written form; only the audio
uses the spoken form.
"""

from __future__ import annotations

import json
import os
import re
from typing import Dict, List, Optional

DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))), "data")
DEFAULT_LEXICON = os.path.join(DATA_DIR, "lexicon.json")

_DIGITS = ["zero", "one", "two", "three", "four", "five", "six", "seven", "eight", "nine"]
_TEENS = ["ten", "eleven", "twelve", "thirteen", "fourteen", "fifteen", "sixteen", "seventeen", "eighteen", "nineteen"]
_TENS = ["", "", "twenty", "thirty", "forty", "fifty", "sixty", "seventy", "eighty", "ninety"]

_CVE_RE = re.compile(r"\bCVE-(\d{4})-(\d{4,9})\b")
_MONTHS = "January|February|March|April|May|June|July|August|September|October|November|December"
_DATE_RE = re.compile(r"\b(\d{1,2}) (" + _MONTHS + r") (\d{4})\b")


def two_digits(n: int) -> str:
    if n < 10:
        return _DIGITS[n]
    if n < 20:
        return _TEENS[n - 10]
    tens, ones = divmod(n, 10)
    return _TENS[tens] + ("-" + _DIGITS[ones] if ones else "")


def spoken_year(year: int) -> str:
    """1999 -> nineteen ninety-nine, 2007 -> two thousand seven, 2026 -> twenty twenty-six."""
    if 2000 <= year <= 2009:
        return "two thousand" + ("" if year == 2000 else " " + _DIGITS[year - 2000])
    high, low = divmod(year, 100)
    if low == 0:
        return two_digits(high) + " hundred"
    if low < 10:
        return two_digits(high) + " oh " + _DIGITS[low]
    return two_digits(high) + " " + two_digits(low)


def digit_groups(digits: str) -> List[str]:
    """Split a digit string into speakable groups of two or three."""
    n = len(digits)
    if n <= 3:
        return [digits]
    if n == 4:
        return [digits[:2], digits[2:]]
    if n == 5:
        return [digits[:2], digits[2:]]
    head = n % 3
    groups = [digits[:head]] if head else []
    groups.extend(digits[i : i + 3] for i in range(head, n, 3))
    return groups


def spoken_digits(digits: str) -> str:
    return ", ".join(" ".join(_DIGITS[int(ch)] for ch in group) for group in digit_groups(digits))


def spoken_cve(cve: str) -> str:
    match = _CVE_RE.fullmatch(cve.strip())
    if not match:
        return cve
    return f"C V E {spoken_year(int(match.group(1)))}, {spoken_digits(match.group(2))}"


def load_lexicon(path: Optional[str] = None) -> Dict[str, str]:
    path = path or DEFAULT_LEXICON
    if not os.path.isfile(path):
        return {}
    with open(path, "r", encoding="utf-8") as handle:
        data = json.load(handle)
    terms = data.get("terms") if isinstance(data, dict) else None
    if not isinstance(terms, dict):
        return {}
    return {str(k): str(v) for k, v in terms.items() if k and isinstance(v, str)}


def spoken_form(sentence: str, lexicon: Optional[Dict[str, str]] = None) -> str:
    """Written narration -> text for the speech engine."""
    text = _CVE_RE.sub(lambda m: spoken_cve(m.group(0)), sentence)
    text = _DATE_RE.sub(lambda m: f"{m.group(1)} {m.group(2)} {spoken_year(int(m.group(3)))}", text)
    for term, spoken in sorted((lexicon or {}).items(), key=lambda kv: -len(kv[0])):
        text = re.sub(r"(?<![A-Za-z0-9])" + re.escape(term) + r"(?![A-Za-z0-9])", spoken, text)
    return re.sub(r"\s+", " ", text).strip()
