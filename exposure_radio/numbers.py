"""Numbers written as digits or words ("20", "twenty", "twenty-one", "no")."""

from __future__ import annotations

import re

_UNITS = {w: i for i, w in enumerate(
    "zero one two three four five six seven eight nine ten eleven twelve thirteen fourteen fifteen "
    "sixteen seventeen eighteen nineteen".split())}
_TENS = {w: 10 * i for i, w in enumerate("_ _ twenty thirty forty fifty sixty seventy eighty ninety".split()) if i > 1}
_ALIASES = {"no": 0, "none": 0, "a": 1, "an": 1, "single": 1, "a single": 1, "one single": 1,
            "a dozen": 12, "dozen": 12, "a couple of": 2, "a couple": 2, "couple": 2, "both": 2}


def to_int(text: str) -> int | None:
    s = text.strip().lower().replace(",", "")
    if re.fullmatch(r"\d+", s):
        return int(s)
    if s in _ALIASES:
        return _ALIASES[s]
    words = re.split(r"[\s-]+(?:and[\s-]+)?", s)
    total, current = 0, 0
    seen = False
    for w in words:
        if w in _UNITS:
            current += _UNITS[w]
        elif w in _TENS:
            current += _TENS[w]
        elif w == "hundred" and seen:
            current *= 100
        elif w == "thousand" and seen:
            total += current * 1000
            current = 0
        else:
            return None
        seen = True
    return total + current if seen else None


_WORD = r"(?:zero|one|two|three|four|five|six|seven|eight|nine|ten|eleven|twelve|thirteen|fourteen|fifteen|" \
        r"sixteen|seventeen|eighteen|nineteen|twenty|thirty|forty|fifty|sixty|seventy|eighty|ninety|hundred|" \
        r"thousand|dozen|no|none|both|single)"
NUMBER_RE = re.compile(rf"\b(?:\d[\d,]*|{_WORD}(?:[\s-]+(?:and[\s-]+)?{_WORD})*)\b", re.IGNORECASE)


def find_numbers(text: str) -> list[int]:
    out = []
    for m in NUMBER_RE.finditer(text):
        value = to_int(m.group(0))
        if value is not None:
            out.append(value)
    return out


_SPOKEN_UNITS = list(_UNITS)
_SPOKEN_TENS = {v: k for k, v in _TENS.items()}


def spoken(n: int) -> str:
    """Integer to words, for speech."""
    if n < 20:
        return _SPOKEN_UNITS[n]
    if n < 100:
        tens, unit = divmod(n, 10)
        return _SPOKEN_TENS[tens * 10] + (f"-{_SPOKEN_UNITS[unit]}" if unit else "")
    if n < 1000:
        hundreds, rest = divmod(n, 100)
        return f"{_SPOKEN_UNITS[hundreds]} hundred" + (f" {spoken(rest)}" if rest else "")
    thousands, rest = divmod(n, 1000)
    return f"{spoken(thousands)} thousand" + (f" {spoken(rest)}" if rest else "")
