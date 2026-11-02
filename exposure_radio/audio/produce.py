"""Produce the episode audio: gate receipt in, MP3 + WebVTT + measurements out.

Refuses to synthesise anything the gate did not approve: the receipt must
be a pass and its hash must match the sentences about to be spoken.
"""

from __future__ import annotations

import json
import os
import sys
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from ..pipeline import Episode, run_episode
from . import loudness
from .lexicon import load_lexicon, spoken_form
from .tts import SAMPLE_RATE, KokoroSynth, TtsUnavailable, env_default, write_wav
from .vtt import build_vtt

GAP_SECONDS = 0.45
SECTION_GAP_SECONDS = 0.9


def produce(
    episode: Episode,
    out_dir: str,
    synth: KokoroSynth,
    bitrate: str = "64k",
    lexicon_path: Optional[str] = None,
    sample_name: str = "sample",
) -> Dict[str, Any]:
    if not episode.gate.passed:
        raise RuntimeError("the gate did not pass; no audio is produced for an unapproved script")
    sentences = list(episode.sentences)
    receipt = episode.gate.receipt
    if not receipt.covers(sentences):
        raise RuntimeError("receipt hash does not cover these sentences; refusing to speak them")
    os.makedirs(out_dir, exist_ok=True)
    np = synth.np
    lexicon = load_lexicon(lexicon_path)

    chunks: List[Any] = []
    cues: List[tuple] = []
    spoken_forms: List[str] = []
    clock = 0.0
    for index, sentence in enumerate(sentences):
        spoken = spoken_form(sentence, lexicon)
        spoken_forms.append(spoken)
        audio = synth.synthesize(spoken)
        duration = audio.size / SAMPLE_RATE
        cues.append((clock, clock + duration, sentence))
        chunks.append(audio)
        gap = SECTION_GAP_SECONDS if index in (0, len(sentences) - 2) else GAP_SECONDS
        chunks.append(np.zeros(int(gap * SAMPLE_RATE), dtype=np.float32))
        clock += duration + gap

    raw_path = os.path.join(out_dir, "episode_raw.wav")
    norm_path = os.path.join(out_dir, "episode.wav")
    mp3_path = os.path.join(out_dir, f"{sample_name}.mp3")
    vtt_path = os.path.join(out_dir, f"{sample_name}.vtt")
    write_wav(raw_path, np.concatenate(chunks) if chunks else np.zeros(0, dtype=np.float32), np)
    measured_before = loudness.measure(raw_path)
    loudness.normalise(raw_path, norm_path)
    loudness.encode_mp3(norm_path, mp3_path, bitrate=bitrate)
    measured_mp3 = loudness.measure(mp3_path)
    measured_wav = loudness.measure(norm_path)

    notes = [
        f"Exposure Radio episode {episode.facts.value('episode', 'export_date')}",
        f"gate receipt sha256 {receipt.script_sha256}",
        "Every cue is a gate-approved sentence; see transcript.json for the cited facts.",
    ]
    with open(vtt_path, "w", encoding="utf-8") as handle:
        handle.write(build_vtt(cues, notes))

    report: Dict[str, Any] = {
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "episode_date": episode.facts.value("episode", "export_date"),
        "receipt_sha256": receipt.script_sha256,
        "receipt_passed": receipt.passed,
        "sentences": len(sentences),
        "duration_seconds": round(clock, 2),
        "mp3": {"path": mp3_path, "bytes": os.path.getsize(mp3_path), "bitrate": bitrate},
        "loudness": {
            "targets": {"integrated_lufs": loudness.TARGET_I, "true_peak_dbtp": loudness.TARGET_TP},
            "raw": measured_before,
            "normalised_wav": measured_wav,
            "mp3": measured_mp3,
            "mp3_within_targets": loudness.within_targets(measured_mp3),
        },
        "synth": synth.describe(),
        "spoken_forms": spoken_forms,
        "cues": [{"start": round(s, 3), "end": round(e, 3), "text": t} for s, e, t in cues],
    }
    with open(os.path.join(out_dir, "measurements.json"), "w", encoding="utf-8") as handle:
        json.dump(report, handle, indent=2)
        handle.write("\n")
    with open(os.path.join(out_dir, "spoken_script.txt"), "w", encoding="utf-8") as handle:
        handle.write("\n".join(spoken_forms) + "\n")
    return report


def produce_cli(args: Any) -> int:
    model_path = env_default("EXPOSURE_RADIO_KOKORO_MODEL", getattr(args, "model_path", None))
    voices_dir = env_default("EXPOSURE_RADIO_KOKORO_VOICES", getattr(args, "voices_dir", None))
    if not model_path or not voices_dir:
        print(
            "audio needs Kokoro weights: pass --model-path and --voices-dir or set EXPOSURE_RADIO_KOKORO_MODEL / EXPOSURE_RADIO_KOKORO_VOICES",
            file=sys.stderr,
        )
        return 2
    try:
        synth = KokoroSynth(model_path, voices_dir, voice=getattr(args, "voice", "af_heart"))
    except TtsUnavailable as exc:
        print(f"audio unavailable: {exc}", file=sys.stderr)
        return 2
    try:
        loudness.ffmpeg_path()
    except loudness.FfmpegMissing as exc:
        print(f"audio unavailable: {exc}", file=sys.stderr)
        return 2
    episode = run_episode(args.current, None if getattr(args, "no_previous", False) else args.previous, data_dir=args.data_dir, synthetic_note=not getattr(args, "no_synthetic_note", False))
    if not episode.gate.passed:
        print("gate did not pass; refusing to synthesise", file=sys.stderr)
        return 1
    report = produce(episode, args.out, synth, bitrate=getattr(args, "mp3_bitrate", "64k"))
    mp3 = report["loudness"]["mp3"]
    print(f"wrote {report['mp3']['path']} ({report['mp3']['bytes']} bytes, {report['duration_seconds']}s, {report['sentences']} cues)")
    print(f"loudness (mp3): integrated {mp3.get('integrated_lufs')} LUFS, true peak {mp3.get('true_peak_dbtp')} dBTP, LRA {mp3.get('lra_lu')} LU")
    print(f"targets met: {report['loudness']['mp3_within_targets']}")
    return 0 if report["loudness"]["mp3_within_targets"] else 1
