"""Loudness measurement and normalisation through ffmpeg.

Targets follow common podcast practice: integrated loudness -16 LUFS,
true peak at or below -1 dBTP. ``measure`` runs ``ebur128`` and parses the
summary; ``normalise`` runs the two-pass ``loudnorm`` filter in linear mode
so timing is untouched (the WebVTT cue times stay valid).
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
from typing import Dict, List, Optional

TARGET_I = -16.0
TARGET_TP = -1.0
TARGET_LRA = 11.0

_SUMMARY_RE = {
    "integrated_lufs": re.compile(r"^\s*I:\s*(-?[\d.]+)\s*LUFS", re.MULTILINE),
    "threshold_lufs": re.compile(r"^\s*Threshold:\s*(-?[\d.]+)\s*LUFS", re.MULTILINE),
    "lra_lu": re.compile(r"^\s*LRA:\s*(-?[\d.]+)\s*LU", re.MULTILINE),
    "true_peak_dbtp": re.compile(r"^\s*Peak:\s*(-?[\d.]+)\s*dBFS", re.MULTILINE),
}


class FfmpegMissing(RuntimeError):
    pass


def ffmpeg_path() -> str:
    path = shutil.which("ffmpeg")
    if not path:
        raise FfmpegMissing("ffmpeg is not installed; it is needed only for loudness normalisation and MP3 encoding")
    return path


def _run(args: List[str]) -> subprocess.CompletedProcess:
    return subprocess.run(args, capture_output=True, text=True, check=False)


def parse_ebur128_summary(stderr: str) -> Dict[str, float]:
    """Parse the ``ebur128`` summary block printed by ffmpeg."""
    summary_start = stderr.rfind("Summary:")
    block = stderr[summary_start:] if summary_start >= 0 else stderr
    out: Dict[str, float] = {}
    for key, pattern in _SUMMARY_RE.items():
        match = pattern.search(block)
        if match:
            out[key] = float(match.group(1))
    if "integrated_lufs" not in out:
        raise ValueError("could not find an integrated loudness value in ffmpeg output")
    return out


def measure(path: str) -> Dict[str, float]:
    result = _run([ffmpeg_path(), "-nostats", "-hide_banner", "-i", path, "-af", "ebur128=peak=true", "-f", "null", "-"])
    if result.returncode != 0:
        raise RuntimeError(f"ffmpeg ebur128 failed: {result.stderr[-500:]}")
    return parse_ebur128_summary(result.stderr)


def parse_loudnorm_json(stderr: str) -> Dict[str, str]:
    start = stderr.rfind("{")
    end = stderr.rfind("}")
    if start < 0 or end < 0:
        raise ValueError("loudnorm did not print its measurement JSON")
    data = json.loads(stderr[start : end + 1])
    return {str(k): str(v) for k, v in data.items()}


def normalise(src: str, dst: str, target_i: float = TARGET_I, target_tp: float = TARGET_TP, target_lra: float = TARGET_LRA) -> Dict[str, str]:
    """Two-pass loudnorm (linear) from ``src`` to a 24 kHz mono 16-bit WAV ``dst``."""
    ffmpeg = ffmpeg_path()
    first = _run(
        [ffmpeg, "-nostats", "-hide_banner", "-i", src, "-af", f"loudnorm=I={target_i}:TP={target_tp}:LRA={target_lra}:print_format=json", "-f", "null", "-"]
    )
    if first.returncode != 0:
        raise RuntimeError(f"loudnorm pass 1 failed: {first.stderr[-500:]}")
    measured = parse_loudnorm_json(first.stderr)
    filter_spec = (
        f"loudnorm=I={target_i}:TP={target_tp}:LRA={target_lra}:measured_I={measured['input_i']}:measured_TP={measured['input_tp']}"
        f":measured_LRA={measured['input_lra']}:measured_thresh={measured['input_thresh']}:offset={measured['target_offset']}"
        f":linear=true:print_format=json"
    )
    second = _run([ffmpeg, "-nostats", "-hide_banner", "-y", "-i", src, "-af", filter_spec, "-ar", "24000", "-ac", "1", "-sample_fmt", "s16", dst])
    if second.returncode != 0:
        raise RuntimeError(f"loudnorm pass 2 failed: {second.stderr[-500:]}")
    return measured


def encode_mp3(src: str, dst: str, bitrate: str = "64k") -> None:
    ffmpeg = ffmpeg_path()
    result = _run([ffmpeg, "-nostats", "-hide_banner", "-y", "-i", src, "-codec:a", "libmp3lame", "-b:a", bitrate, "-ac", "1", "-ar", "24000", dst])
    if result.returncode != 0:
        raise RuntimeError(f"mp3 encode failed: {result.stderr[-500:]}")


def within_targets(measurement: Dict[str, float], tolerance_lu: float = 1.0, target_i: float = TARGET_I, target_tp: float = TARGET_TP) -> bool:
    integrated = measurement.get("integrated_lufs")
    peak = measurement.get("true_peak_dbtp")
    if integrated is None or peak is None:
        return False
    return abs(integrated - target_i) <= tolerance_lu and peak <= target_tp + 1e-9


def duration_seconds(path: str) -> Optional[float]:
    probe = shutil.which("ffprobe")
    if not probe:
        return None
    result = _run([probe, "-v", "error", "-show_entries", "format=duration", "-of", "default=noprint_wrappers=1:nokey=1", path])
    try:
        return float(result.stdout.strip())
    except ValueError:
        return None
