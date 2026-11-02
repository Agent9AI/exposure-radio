#!/usr/bin/env python3
"""Make a short, receipt-verified briefing from a previously rendered episode."""
import argparse
import hashlib
import html
import json
import math
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from exposure_radio.audio import verify_speech
from exposure_radio.gate import gate_script
from exposure_radio.pipeline import run_cycle

INDICES = [0, 1, 2, 3, 4, 6, 44, 45, 46, 47, 48, 49, 50, 52]


def run(args):
    return subprocess.run(args, check=True, capture_output=True, text=True)


def measure(path):
    result = run(['ffmpeg', '-hide_banner', '-nostats', '-i', str(path), '-af',
                  'loudnorm=I=-16:TP=-1.5:LRA=11:print_format=json', '-f', 'null', '-'])
    return json.loads(result.stderr[result.stderr.rfind('{'):result.stderr.rfind('}') + 1])


def stamp(seconds):
    ms = round(seconds * 1000)
    return f'{ms // 3600000:02}:{ms // 60000 % 60:02}:{ms // 1000 % 60:02}.{ms % 1000:03}'


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--source', required=True, type=Path)
    p.add_argument('--manifest', required=True, type=Path)
    p.add_argument('--source-sha256', required=True, help='Expected SHA-256 of the verified full episode')
    p.add_argument('--output', required=True, type=Path)
    args = p.parse_args()
    digest = hashlib.sha256(args.source.read_bytes()).hexdigest()
    if digest != args.source_sha256.lower():
        raise ValueError('source audio hash mismatch')
    manifest = json.loads(args.manifest.read_text())
    cycle = run_cycle(commit=False)
    lines = cycle.episode.lines
    verify_speech(lines, manifest['receipt'], cycle.ledger)
    source_cues = manifest['cues']
    if len(source_cues) != len(lines):
        raise ValueError('source cue count does not match full script')
    prev = 0.0
    for line, cue in zip(lines, source_cues):
        a, b = cue['start'], cue['end']
        if (cue['text'] != line['text'] or cue['voice'] != line['voice'] or
            not all(isinstance(n, (int, float)) and math.isfinite(n) for n in (a, b)) or
            a < prev or b <= a or b > manifest['duration_seconds']):
            raise ValueError('source cue does not match full script or timeline')
        prev = b
    selected = [lines[i] for i in INDICES]
    report = gate_script(selected, cycle.ledger)
    if not report.passed:
        raise ValueError('selected script failed gate')
    verify_speech(selected, report.receipt(), cycle.ledger)
    cues, elapsed = [], 0.0
    filters = []
    for n, index in enumerate(INDICES):
        cue = source_cues[index]
        duration = cue['end'] - cue['start']
        start = elapsed
        end = start + duration
        cues.append({'start': round(start, 3), 'end': round(end, 3),
                     'voice': cue['voice'], 'text': cue['text']})
        elapsed = end + .25
        filters.append(f"[0:a]atrim=start={cue['start']}:end={cue['end']},asetpts=PTS-STARTPTS,apad=pad_dur=0.25[s{n}]")
    filters.append(''.join(f'[s{n}]' for n in range(len(INDICES))) + f'concat=n={len(INDICES)}:v=0:a=1[out]')
    if elapsed > 90:
        raise ValueError('selected speech exceeds 90 seconds')
    with tempfile.TemporaryDirectory(prefix='priority-break-') as td:
        td = Path(td)
        wav, mp3 = td / 'joined.wav', td / 'briefing.mp3'
        run(['ffmpeg', '-hide_banner', '-loglevel', 'error', '-y', '-i', str(args.source),
             '-filter_complex', ';'.join(filters), '-map', '[out]', '-c:a', 'pcm_s16le', str(wav)])
        first = measure(wav)
        filt = ('loudnorm=I=-16:TP=-1.5:LRA=11:linear=true:' +
                ':'.join(f'measured_{k}={first["input_" + k]}' for k in ('i', 'tp', 'lra', 'thresh')) +
                ':offset=' + first['target_offset'])
        run(['ffmpeg', '-hide_banner', '-loglevel', 'error', '-y', '-i', str(wav), '-af', filt,
             '-c:a', 'libmp3lame', '-b:a', '128k', str(mp3)])
        m = measure(mp3)
        loudness, peak = float(m['input_i']), float(m['input_tp'])
        duration = float(run(['ffprobe', '-v', 'error', '-show_entries', 'format=duration',
                              '-of', 'default=noprint_wrappers=1:nokey=1', str(mp3)]).stdout)
        if (not all(map(math.isfinite, (duration, loudness, peak))) or duration > 90 or
            not -17 <= loudness <= -15 or peak > -1):
            raise ValueError(f'output failed duration or loudness: {duration}s {loudness} LUFS {peak} dBTP')
        data = mp3.read_bytes()
        result = {'receipt': report.receipt(), 'source_receipt': manifest['receipt'],
                  'source_audio_sha256': digest, 'audio_sha256': hashlib.sha256(data).hexdigest(),
                  'line_indices': INDICES, 'duration_seconds': round(duration, 3),
                  'integrated_lufs': loudness, 'true_peak_dbtp': peak,
                  'sample_rate_hz': int(json.loads(run(['ffprobe', '-v', 'error', '-show_entries', 'stream=sample_rate', '-of', 'json', str(mp3)]).stdout)['streams'][0]['sample_rate']),
                  'voices': manifest.get('voices', {}), 'codec': 'mp3', 'cues': cues}
        vtt = ['WEBVTT', '']
        for cue in cues:
            vtt += [f"{stamp(cue['start'])} --> {stamp(cue['end'])}",
                    f"<v {cue['voice']}>{html.escape(cue['text'])}", '']
        args.output.mkdir(parents=True, exist_ok=True)
        (args.output / 'briefing.mp3').write_bytes(data)
        (args.output / 'briefing.vtt').write_text('\n'.join(vtt), encoding='utf-8')
        (args.output / 'audio.json').write_text(json.dumps(result, indent=2) + '\n')
        (args.output / 'cues.json').write_text(json.dumps(cues, indent=2) + '\n')
        print(json.dumps({k: v for k, v in result.items() if k != 'cues'}, indent=2))


if __name__ == '__main__':
    main()
