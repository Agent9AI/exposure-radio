"""Receipt-verified, local speech rendering and measured browser audio."""
from __future__ import annotations

import html
import json
import math
import subprocess
import tempfile
import wave
from pathlib import Path

from .gate import gate_script, receipt_matches


class AudioError(RuntimeError):
    pass


def verify_speech(lines, receipt, ledger):
    """Re-audit the exact text; a caller-supplied digest is not authorization."""
    if not isinstance(lines, list) or not lines or not isinstance(receipt, dict):
        raise AudioError("missing script or receipt")
    if any(not isinstance(line, dict) or line.get('voice') not in ('ANCHOR', 'ANALYST')
           or not isinstance(line.get('text'), str) or not line['text'].strip()
           for line in lines):
        raise AudioError("invalid voice or empty speech")
    report = gate_script(lines, ledger)
    if (not report.passed or any(not verdicts for verdicts in report.lines)
            or not receipt_matches(receipt, lines, ledger) or receipt != report.receipt()):
        raise AudioError("script failed fresh gate or receipt does not match")
    return report


def _run(args):
    return subprocess.run(args, check=True, capture_output=True, text=True)


def _stamp(seconds):
    ms = round(seconds * 1000)
    return f'{ms // 3600000:02}:{ms // 60000 % 60:02}:{ms // 1000 % 60:02}.{ms % 1000:03}'


def render(lines, receipt, ledger, output, model, voices):
    """Create MP3, VTT and measurement JSON; requires kokoro-onnx and ffmpeg.

    All TTS calls occur only after a fresh strict ledger check and receipt match.
    """
    report = verify_speech(lines, receipt, ledger)
    # Imported after verification, so rejected text never reaches the engine.
    from kokoro_onnx import Kokoro
    import numpy as np
    import soundfile as sf

    output = Path(output)
    output.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='exposure-radio-audio-') as tmp:
        tmp = Path(tmp)
        engine = Kokoro(str(model), str(voices))
        pieces, cues, elapsed, rate = [], [], 0.0, None
        for line in lines:
            samples, sample_rate = engine.create(line['text'], voice={'ANCHOR': 'am_michael', 'ANALYST': 'af_heart'}[line['voice']], speed=1.0, lang='en-us')
            samples = np.asarray(samples, dtype=np.float32).reshape(-1)
            if not len(samples) or not np.isfinite(samples).all() or (rate is not None and rate != sample_rate):
                raise AudioError('invalid speech samples or inconsistent sample rate')
            rate = sample_rate
            end = elapsed + len(samples) / rate
            cues.append((elapsed, end, line['voice'], line['text']))
            pieces.extend((samples, np.zeros(round(rate * .25), dtype=np.float32)))
            elapsed = end + .25
        source = tmp / 'speech.wav'
        sf.write(source, np.concatenate(pieces), rate, subtype='PCM_16')
        # Two-pass EBU R128 normalization; measure the encoded output afterwards.
        first = _run(['ffmpeg', '-hide_banner', '-nostats', '-i', str(source), '-af',
                      'loudnorm=I=-16:TP=-1.5:LRA=11:print_format=json', '-f', 'null', '-'])
        measurement = json.loads(first.stderr[first.stderr.rfind('{'):first.stderr.rfind('}') + 1])
        filt = ('loudnorm=I=-16:TP=-1.5:LRA=11:linear=true:print_format=json:' +
                ':'.join(f'measured_{k}={measurement["input_" + k]}' for k in ('i', 'tp', 'lra', 'thresh')) +
                ':offset=' + measurement['target_offset'])
        mp3 = tmp / 'episode.mp3'
        _run(['ffmpeg', '-hide_banner', '-loglevel', 'error', '-y', '-i', str(source), '-af', filt,
              '-codec:a', 'libmp3lame', '-b:a', '128k', str(mp3)])
        measured = _run(['ffmpeg', '-hide_banner', '-nostats', '-i', str(mp3), '-af',
                         'loudnorm=I=-16:TP=-1:LRA=11:print_format=json', '-f', 'null', '-'])
        metrics = json.loads(measured.stderr[measured.stderr.rfind('{'):measured.stderr.rfind('}') + 1])
        loudness, peak = float(metrics['input_i']), float(metrics['input_tp'])
        if not math.isfinite(loudness) or not math.isfinite(peak) or not -17 <= loudness <= -15 or peak > -1:
            raise AudioError(f'encoded audio outside target: {loudness} LUFS, {peak} dBTP')
        vtt = ['WEBVTT', '']
        for start, end, voice, text in cues:
            vtt.extend([f'{_stamp(start)} --> {_stamp(end)}', f'<v {voice}>{html.escape(text)}', ''])
        (output / 'episode.mp3').write_bytes(mp3.read_bytes())
        (output / 'episode.vtt').write_text('\n'.join(vtt), encoding='utf-8')
        result = {'receipt': report.receipt(), 'integrated_lufs': loudness, 'true_peak_dbtp': peak,
                  'duration_seconds': round(elapsed, 3), 'sample_rate_hz': rate,
                  'codec': 'mp3', 'voices': {'ANCHOR': 'am_michael', 'ANALYST': 'af_heart'},
                  'cues': [{'start': round(a, 3), 'end': round(b, 3), 'voice': v, 'text': t} for a, b, v, t in cues]}
        (output / 'audio.json').write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8')
        return result
