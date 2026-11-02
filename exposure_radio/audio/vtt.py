"""WebVTT transcript with one cue per gate-approved sentence."""

from __future__ import annotations

from typing import Iterable, List, Optional, Sequence, Tuple

Cue = Tuple[float, float, str]


def format_timestamp(seconds: float) -> str:
    if seconds < 0:
        seconds = 0.0
    whole = int(seconds)
    millis = int(round((seconds - whole) * 1000))
    if millis == 1000:
        whole += 1
        millis = 0
    hours, rem = divmod(whole, 3600)
    minutes, secs = divmod(rem, 60)
    return f"{hours:02d}:{minutes:02d}:{secs:02d}.{millis:03d}"


def build_vtt(cues: Sequence[Cue], notes: Optional[Iterable[str]] = None) -> str:
    lines: List[str] = ["WEBVTT", ""]
    for note in notes or ():
        safe = str(note).replace("-->", "- >").strip()
        if safe:
            lines.append(f"NOTE {safe}")
            lines.append("")
    for index, (start, end, text) in enumerate(cues, start=1):
        if end <= start:
            end = start + 0.5
        safe_text = " ".join(str(text).replace("-->", "- >").split())
        lines.append(str(index))
        lines.append(f"{format_timestamp(start)} --> {format_timestamp(end)}")
        lines.append(safe_text)
        lines.append("")
    return "\n".join(lines)


def parse_vtt(text: str) -> List[Cue]:
    """Minimal parser for our own output (used by tests and the site builder)."""
    cues: List[Cue] = []
    blocks = [b for b in text.replace("\r\n", "\n").split("\n\n") if b.strip()]
    for block in blocks:
        lines = block.strip().split("\n")
        if lines[0].startswith("WEBVTT") or lines[0].startswith("NOTE"):
            continue
        timing = lines[1] if len(lines) > 1 and "-->" in lines[1] else (lines[0] if "-->" in lines[0] else None)
        if timing is None:
            continue
        start_text, end_text = [p.strip() for p in timing.split("-->")]
        body_index = 2 if timing == lines[1] else 1
        cues.append((_to_seconds(start_text), _to_seconds(end_text), " ".join(lines[body_index:])))
    return cues


def _to_seconds(stamp: str) -> float:
    parts = stamp.split(":")
    seconds = 0.0
    for part in parts:
        seconds = seconds * 60 + float(part)
    return seconds
