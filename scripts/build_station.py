#!/usr/bin/env python3
"""Build a station rundown and render it: web/station/station.json plus audio.

Exposure segments come from the gated briefing (tenant evidence). Weather, news
and Learn come from public sources. Speech is local Kokoro by default; run this
script with a Python that has kokoro-onnx, numpy and soundfile, plus FFmpeg.

    python scripts/build_station.py --model kokoro.onnx --voices voices.bin
    python scripts/build_station.py --offline ...   # reuse saved public snapshots
    python scripts/build_station.py --plan-only     # station.json without audio
"""
from __future__ import annotations

import argparse
import hashlib
import html
import json
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from exposure_radio import __version__  # noqa: E402
from exposure_radio.desks import (fetch_news, fetch_weather, geocode, ident_segment, learn_segment,  # noqa: E402
                                  learn_topics, news_segment, weather_segment)
from exposure_radio.onair import HOSTS, build_segments, verify_segment  # noqa: E402
from exposure_radio.pipeline import run_cycle  # noqa: E402

WEB = ROOT / "web"
OUT = WEB / "station"
GAP_SAME, GAP_SWITCH = 0.22, 0.38


def run(args, **kw):
    return subprocess.run(args, check=True, capture_output=True, text=True, **kw)


def stamp(seconds: float) -> str:
    ms = round(seconds * 1000)
    return f"{ms // 3600000:02}:{ms // 60000 % 60:02}:{ms // 1000 % 60:02}.{ms % 1000:03}"


def loudnorm(src: Path, dst: Path, target: float = -16.0) -> dict:
    first = run(["ffmpeg", "-hide_banner", "-nostats", "-i", str(src), "-af",
                 f"loudnorm=I={target}:TP=-1.5:LRA=11:print_format=json", "-f", "null", "-"])
    m = json.loads(first.stderr[first.stderr.rfind("{"):first.stderr.rfind("}") + 1])
    filt = (f"loudnorm=I={target}:TP=-1.5:LRA=11:linear=true:" +
            ":".join(f"measured_{k}={m['input_' + k]}" for k in ("i", "tp", "lra", "thresh")) +
            f":offset={m['target_offset']}")
    run(["ffmpeg", "-hide_banner", "-loglevel", "error", "-y", "-i", str(src), "-af", filt,
         "-ar", "44100", "-ac", "2", "-codec:a", "libmp3lame", "-b:a", "128k", str(dst)])
    check = run(["ffmpeg", "-hide_banner", "-nostats", "-i", str(dst), "-af",
                 "loudnorm=I=-16:TP=-1:LRA=11:print_format=json", "-f", "null", "-"])
    c = json.loads(check.stderr[check.stderr.rfind("{"):check.stderr.rfind("}") + 1])
    return {"integrated_lufs": float(c["input_i"]), "true_peak_dbtp": float(c["input_tp"])}


def duration(path: Path) -> float:
    out = run(["ffprobe", "-v", "error", "-show_entries", "format=duration", "-of", "json", str(path)])
    return round(float(json.loads(out.stdout)["format"]["duration"]), 2)


class Voice:
    def __init__(self, model: str, voices: str, speed: float):
        from kokoro_onnx import Kokoro  # imported only after the caller's gate checks
        self.engine, self.speed = Kokoro(model, voices), speed

    def speak(self, host: str, text: str):
        import numpy as np
        samples, rate = self.engine.create(text, voice=HOSTS[host]["kokoro"], speed=self.speed, lang="en-us")
        return np.asarray(samples, dtype=np.float32).reshape(-1), rate


def render_segment(seg: dict, index: int, voice: Voice, music: dict, work: Path) -> None:
    import numpy as np
    import soundfile as sf
    pieces, cursor, rate, prev = [], 0.0, None, None
    lead_in = 0.0
    for turn in seg["turns"]:
        samples, rate = voice.speak(turn["host"], turn["text"])
        if prev is not None:
            gap = GAP_SAME if prev == turn["host"] else GAP_SWITCH
            pieces.append(np.zeros(round(rate * gap), dtype=np.float32))
            cursor += gap
        turn["start"] = round(cursor, 3)
        cursor += len(samples) / rate
        turn["end"] = round(cursor, 3)
        pieces.append(samples)
        prev = turn["host"]
    speech = work / f"speech-{index}.wav"
    sf.write(speech, np.concatenate(pieces + [np.zeros(round(rate * 0.4), dtype=np.float32)]), rate,
             subtype="PCM_16")
    mixed = work / f"mix-{index}.wav"
    stinger = {s["id"]: s for s in music.get("stingers", [])}.get("ident")
    beds = {b["id"].removeprefix("bed-"): b for b in music.get("beds", [])}
    bed = beds.get({"news": "news", "learn": "learn", "weather": "news",
                    "wins": "learn", "blindspots": "news", "exposure": "news"}.get(seg["kind"], ""))
    if seg["kind"] == "ident" and stinger:
        lead_in = 2.6
        run(["ffmpeg", "-hide_banner", "-loglevel", "error", "-y", "-i", str(WEB / stinger["audio"]), "-i", str(speech),
             "-filter_complex",
             f"[1:a]aresample=44100,adelay={int(lead_in * 1000)}:all=1,volume=1.0[v];"
             "[0:a]aresample=44100,volume=0.55[s];[s][v]amix=inputs=2:normalize=0:duration=longest[o]",
             "-map", "[o]", "-ac", "2", str(mixed)])
    elif bed:
        total = cursor + 1.6
        lead_in = 1.2
        run(["ffmpeg", "-hide_banner", "-loglevel", "error", "-y", "-stream_loop", "-1", "-i", str(WEB / bed["audio"]),
             "-i", str(speech), "-filter_complex",
             f"[0:a]aresample=44100,atrim=0:{total + lead_in:.2f},volume=0.6,"
             f"afade=t=in:d=0.8,afade=t=out:st={total + lead_in - 1.4:.2f}:d=1.4[b];"
             f"[1:a]aresample=44100,adelay={int(lead_in * 1000)}:all=1,volume=1.0[v];"
             "[b][v]amix=inputs=2:normalize=0:duration=longest[o]", "-map", "[o]", "-ac", "2", str(mixed)])
    else:
        mixed = speech
    for turn in seg["turns"]:
        turn["start"] = round(turn["start"] + lead_in, 3)
        turn["end"] = round(turn["end"] + lead_in, 3)
    name = f"seg-{index:02}"
    mp3 = OUT / "audio" / f"{name}.mp3"
    seg["measure"] = loudnorm(mixed, mp3)
    seg["audio"] = f"station/audio/{name}.mp3"
    seg["duration"] = duration(mp3)
    seg["sha256"] = hashlib.sha256(mp3.read_bytes()).hexdigest()
    vtt = ["WEBVTT", ""]
    for t in seg["turns"]:
        vtt += [f"{stamp(t['start'])} --> {stamp(t['end'])}",
                f"<v {HOSTS[t['host']]['name']}>{html.escape(t['caption'])}", ""]
    (OUT / "audio" / f"{name}.vtt").write_text("\n".join(vtt), encoding="utf-8")
    seg["captions"] = f"station/audio/{name}.vtt"


def main() -> None:
    global OUT
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--model", help="Kokoro ONNX model")
    p.add_argument("--voices", help="Kokoro voices file")
    p.add_argument("--speed", type=float, default=1.04)
    p.add_argument("--voice", choices=("kokoro", "gemini"), default="kokoro",
                   help="gemini uses GEMINI_API_KEY; Kokoro still voices anything Gemini cannot")
    p.add_argument("--gemini-tier", choices=("free", "paid"), default="free",
                   help="free keeps exposure segments on Kokoro (free-tier content may train Google models)")
    p.add_argument("--synthetic-sample", action="store_true",
                   help="allow a free-tier cloud voice for exposure segments because the tenant is synthetic")
    p.add_argument("--cloud-seconds", type=float, default=900, help="cap on cloud-voiced seconds for this build")
    p.add_argument("--address", default="1600 Pennsylvania Ave NW, Washington, DC 20500",
                   help="US street address for weather and local alerts")
    p.add_argument("--offline", action="store_true", help="reuse web/station/data snapshots")
    p.add_argument("--plan-only", action="store_true", help="write station.json without rendering audio")
    p.add_argument("--out", type=Path, default=ROOT / "web" / "station", help="output directory (default web/station)")
    args = p.parse_args()
    OUT = args.out
    if not args.plan_only and not (args.model and args.voices):
        p.error("--model and --voices are required unless --plan-only")

    (OUT / "audio").mkdir(parents=True, exist_ok=True)
    (OUT / "data").mkdir(parents=True, exist_ok=True)
    cycle = run_cycle(edition="executive", commit=False)
    today = cycle.ledger.clock.date()
    exposure = build_segments(cycle.episode.lines, cycle.ledger, cycle.kev, cycle.decision.kind, today=today)
    items = {i["cve"]: i for i in cycle.episode.card["items"]}

    snap_w, snap_n = OUT / "data" / "weather.json", OUT / "data" / "news.json"
    if args.offline:
        weather, news = json.loads(snap_w.read_text()), json.loads(snap_n.read_text())
    else:
        place = geocode(args.address)
        weather = fetch_weather(place["lat"], place["lon"])
        weather["label"] = place["label"]
        news = fetch_news()
        snap_w.write_text(json.dumps(weather, indent=2) + "\n", encoding="utf-8")
        snap_n.write_text(json.dumps(news, indent=2) + "\n", encoding="utf-8")

    tracks_file = OUT / "music" / "tracks.json"
    music = json.loads(tracks_file.read_text()) if tracks_file.exists() else {"tracks": []}
    tracks = music.get("tracks", [])
    topics = learn_topics()

    def music_seg(i: int) -> dict | None:
        if i >= len(tracks):
            return None
        t = tracks[i]
        return {"kind": "music", "title": t["title"], "subtitle": t.get("artist", ""), "track": t["id"],
                "audio": t["audio"], "duration": t.get("duration"), "turns": [], "sources": []}

    by_title = {s["title"]: s for s in exposure}
    lead = cycle.decision.lead
    rundown = [
        ident_segment("You're tuned to Exposure Radio. What changed on our network, what to fix first, "
                      "and a little music while you work.", subtitle="Morning edition"),
        by_title.get("Priority: needs action today") or by_title.get("Exposure briefing"),
        music_seg(0),
        by_title.get("The watch list"),
        weather_segment(weather, weather.get("label") or weather["place"]),
        learn_segment(topics[0]),
        music_seg(1),
        news_segment(news),
        by_title.get("Wins: verified fixed"),
        by_title.get("Blind spots and coverage"),
        learn_segment(topics[1]),
        music_seg(2),
        ident_segment("That's the hour on Exposure Radio. The next exposure briefing airs after the next scan, "
                      "and anything on CISA's exploited list interrupts the music.", title="Sign-off",
                      subtitle="Back after the next scan"),
    ]
    rundown = [s for s in rundown if s]
    for i, seg in enumerate(rundown, 1):
        seg["id"] = f"seg-{i:02}"
        seg.setdefault("priority", False)
        seg.setdefault("subtitle", "")
        seg.setdefault("sources", [])
        seg.setdefault("track", None)
        if seg["kind"] in ("exposure", "wins", "blindspots"):
            cves = list(dict.fromkeys(t["subject"] for t in seg["turns"] if t.get("subject")))
            if seg.get("priority") and lead:
                cves = [lead] + [c for c in cves if c != lead]
            seg["card"] = items.get(cves[0]) if cves else None
            seg["watch"] = [items[c] for c in cves[1:] if c in items]
            seg["sources"] = [{"label": "CISA KEV catalog", "url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"},
                              {"label": "FIRST EPSS", "url": "https://www.first.org/epss/"},
                              {"label": "Evidence ledger (synthetic tenant)", "url": "data/facts.json"}]
            if not seg["subtitle"]:
                seg["subtitle"] = "Exposure desk · synthetic Tenable exports"
        else:
            seg.setdefault("card", None)

    if not args.plan_only:
        local = Voice(args.model, args.voices, args.speed)
        cloud = None
        if args.voice == "gemini":
            import os
            from exposure_radio.gemini import GeminiVoice
            cloud = GeminiVoice(os.environ.get("GEMINI_API_KEY", ""),
                                {k: v["gemini"] for k, v in HOSTS.items()}, max_seconds=args.cloud_seconds)
        with tempfile.TemporaryDirectory(prefix="exposure-station-") as tmp:
            for i, seg in enumerate(rundown, 1):
                if seg["kind"] == "music":
                    continue
                tenant = seg["kind"] in ("exposure", "wins", "blindspots")
                if tenant:
                    verify_segment(seg, cycle.ledger, cycle.kev, today)   # fresh gate right before TTS
                use_cloud = cloud is not None and (not tenant or args.gemini_tier == "paid" or args.synthetic_sample)
                seg["voice"] = "Kokoro (local)"
                if use_cloud:
                    from exposure_radio.gemini import GeminiError
                    try:
                        render_segment(seg, i, cloud, music, Path(tmp))
                        seg["voice"] = "Gemini 3.8 Flash TTS"
                    except GeminiError as exc:
                        print(f"{seg['id']}: {exc}; using Kokoro", flush=True)
                        use_cloud = False
                if not use_cloud:
                    render_segment(seg, i, local, music, Path(tmp))
                print(f"{seg['id']} {seg['kind']:<10} {seg['duration']:>6.1f}s {seg['voice']} {seg['measure']}",
                      flush=True)

    providers = [
        {"id": "tenable", "label": "Tenable Vulnerability Management", "status": "sample",
         "detail": "Bundled synthetic exports. Add API keys on the station host to go live."},
        {"id": "gemini", "label": "Google Gemini", "status": "available",
         "detail": "Optional. Broadcast voices and Learn topic suggestions with your own API key."},
        {"id": "youtube", "label": "YouTube", "status": "available",
         "detail": "Optional. Your own playlists in the official embedded player, video visible."},
        {"id": "nws", "label": "National Weather Service", "status": "connected",
         "detail": f"Keyless public data for {weather.get('label') or weather['place']}."},
        {"id": "cisa", "label": "CISA KEV and advisories", "status": "connected",
         "detail": f"Public feeds, catalog {news.get('catalog_version')}."},
        {"id": "lyria", "label": "Google Lyria music", "status": "off",
         "detail": "Optional, paid per song. House beats play by default."},
    ]
    doc = {
        "version": 1,
        "generator": f"exposure-radio {__version__}",
        "station": {"name": "Exposure Radio", "tagline": "Your team's security station",
                    "edition": "Synthetic sample", "as_of": cycle.ledger.clock.strftime("%Y-%m-%d %H:%M UTC"),
                    "location": {"label": weather.get("label") or weather["place"]}},
        "hosts": [{"id": k, "name": v["name"], "role": v["role"],
                   "voice": f"Gemini {v['gemini']}" if args.voice == "gemini" else f"Kokoro {v['kokoro']}"}
                  for k, v in HOSTS.items()],
        "providers": providers,
        "rundown": rundown,
        "music": music,
        "learn": {"topics": [{"id": t["id"], "title": t["title"], "status": t.get("status", "queued")}
                             for t in topics]},
    }
    (OUT / "station.json").write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")
    total = sum(s.get("duration") or 0 for s in rundown)
    print(f"station.json: {len(rundown)} segments, {total / 60:.1f} minutes")


if __name__ == "__main__":
    main()
