#!/usr/bin/env python3
"""Build the static listen page (site/index.html) from the demo episode.

Runs the pipeline on the bundled synthetic estate, the planted-case gate
demo and the recorded analyst replay, then embeds the results into a
self-contained HTML page: press-play sample, transcript synced to the
WebVTT cues, a citations drawer, the CISO edition toggle (fail-closed), the
zero-PII alert preview, the gate receipt and the sources ledger. No
external scripts, fonts or network calls; the page works from file://.

Audio is taken from ``out/audio`` (``make audio``) when present, otherwise
the already committed ``site/sample.mp3`` and ``site/sample.vtt`` are kept.
The page refuses to pair audio with a script whose gate receipt hash does
not match the audio's recorded receipt.
"""

from __future__ import annotations

import json
import os
import shutil
import sys
from datetime import datetime, timezone

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from exposure_radio import __version__  # noqa: E402
from exposure_radio.agent import ReplayTransport, load_trace, run_agent  # noqa: E402
from exposure_radio.gate_demo import run as run_gate_demo  # noqa: E402
from exposure_radio.pipeline import run_episode  # noqa: E402

FIXTURES = os.path.join(ROOT, "data", "fixtures")
SITE = os.path.join(ROOT, "site")
AUDIO_OUT = os.path.join(ROOT, "out", "audio")
TRACE = os.path.join(ROOT, "data", "replay", "analyst_trace.json")
BENCH = os.path.join(ROOT, "out", "bench.json")


def collect(site_dir: str = SITE, audio_dir: str = AUDIO_OUT) -> dict:
    episode = run_episode(os.path.join(FIXTURES, "current.json"), os.path.join(FIXTURES, "previous.json"))
    ok, cases = run_gate_demo(episode)
    agent_summary = None
    if os.path.isfile(TRACE):
        outcome = run_agent(episode, ReplayTransport(load_trace(TRACE)))
        agent_summary = {
            "mode": outcome.mode,
            "reason": outcome.reason,
            "calls": outcome.calls,
            "tokens": outcome.tokens,
            "retries": outcome.retries,
            "caps": outcome.trace.get("caps"),
            "recorded_transport": load_trace(TRACE).get("transport"),
            "events": [
                e for e in outcome.trace.get("events", []) if e["type"] in ("gate", "tool_call", "final", "abort")
            ],
            "model_text": [
                next((b.get("text") for b in e["response"].get("content", []) if b.get("type") == "text"), "")
                for e in outcome.trace.get("events", [])
                if e["type"] == "response"
            ],
            "items": outcome.items,
            "angle": outcome.angle,
            "break_in": outcome.break_in,
        }

    os.makedirs(site_dir, exist_ok=True)
    audio = None
    measurements_path = os.path.join(audio_dir, "measurements.json")
    if os.path.isfile(os.path.join(audio_dir, "sample.mp3")) and os.path.isfile(measurements_path):
        shutil.copyfile(os.path.join(audio_dir, "sample.mp3"), os.path.join(site_dir, "sample.mp3"))
        shutil.copyfile(os.path.join(audio_dir, "sample.vtt"), os.path.join(site_dir, "sample.vtt"))
        shutil.copyfile(measurements_path, os.path.join(site_dir, "measurements.json"))
    if os.path.isfile(os.path.join(site_dir, "measurements.json")):
        with open(os.path.join(site_dir, "measurements.json"), encoding="utf-8") as handle:
            measurements = json.load(handle)
        audio = {
            "duration_seconds": measurements.get("duration_seconds"),
            "receipt_sha256": measurements.get("receipt_sha256"),
            "loudness": measurements.get("loudness", {}).get("mp3"),
            "targets": measurements.get("loudness", {}).get("targets"),
            "within_targets": measurements.get("loudness", {}).get("mp3_within_targets"),
            "synth": measurements.get("synth"),
            "bytes": measurements.get("mp3", {}).get("bytes"),
        }
    vtt_text = ""
    if os.path.isfile(os.path.join(site_dir, "sample.vtt")):
        with open(os.path.join(site_dir, "sample.vtt"), encoding="utf-8") as handle:
            vtt_text = handle.read()
    audio_matches = bool(audio and audio.get("receipt_sha256") == episode.gate.receipt.script_sha256)

    bench = None
    if os.path.isfile(BENCH):
        with open(BENCH, encoding="utf-8") as handle:
            bench = json.load(handle)

    return {
        "built_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "version": __version__,
        "episode_date": episode.facts.value("episode", "export_date"),
        "previous_date": episode.facts.value("episode", "previous_export_date"),
        "held": episode.held,
        "decision": episode.decision.to_dict() if episode.decision else None,
        "transcript": episode.transcript(),
        "receipt": episode.gate.receipt.to_dict(),
        "sources": episode.sources,
        "delta": episode.delta.summary(),
        "trend": episode.memory_trend,
        "alert": episode.alert,
        "packet_full": episode.packet_full,
        "packet_ciso": episode.packet_ciso,
        "pii_audit": {k: [i.to_dict() for i in v] for k, v in episode.pii_issues.items()},
        "gate_demo": {"ok": ok, "cases": [c.to_dict() for c in cases]},
        "agent": agent_summary,
        "audio": audio,
        "audio_matches_receipt": audio_matches,
        "vtt": vtt_text,
        "bench": bench,
        "identifier_count": len(episode.forbidden.identifiers),
    }


def render(data: dict) -> str:
    payload = json.dumps(data, ensure_ascii=False).replace("</", "<\\/")
    return TEMPLATE.replace("__DATA__", payload)


def main() -> int:
    data = collect()
    with open(os.path.join(SITE, "episode.json"), "w", encoding="utf-8") as handle:
        json.dump(data, handle, indent=1, ensure_ascii=False)
        handle.write("\n")
    with open(os.path.join(SITE, "index.html"), "w", encoding="utf-8") as handle:
        handle.write(render(data))
    print(f"site/index.html written ({len(data['transcript'])} cues, audio {'matches receipt' if data['audio_matches_receipt'] else 'MISSING or stale'})")
    return 0 if data["audio_matches_receipt"] else 1


TEMPLATE = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Exposure Radio</title>
<meta name="description" content="A verified spoken exposure briefing built from two Tenable exports. Every sentence cites a fact.">
<style>
:root{color-scheme:light dark;--bg:#f6f7f9;--panel:#ffffff;--ink:#16181d;--muted:#5d6472;--line:#dfe3ea;--accent:#1f5eff;--accent-ink:#ffffff;--ok:#1b8f4a;--warn:#b45309;--bad:#c62828;--chip:#eef2ff;--mono:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;--sans:system-ui,-apple-system,"Segoe UI",Roboto,Helvetica,Arial,sans-serif}
@media (prefers-color-scheme:dark){:root:not([data-theme="light"]){--bg:#0f1115;--panel:#171a21;--ink:#e8eaf0;--muted:#9aa3b2;--line:#2a2f3a;--accent:#7aa2ff;--accent-ink:#0f1115;--ok:#4ade80;--warn:#fbbf24;--bad:#f87171;--chip:#1e2433}}
:root[data-theme="dark"]{--bg:#0f1115;--panel:#171a21;--ink:#e8eaf0;--muted:#9aa3b2;--line:#2a2f3a;--accent:#7aa2ff;--accent-ink:#0f1115;--ok:#4ade80;--warn:#fbbf24;--bad:#f87171;--chip:#1e2433}
*{box-sizing:border-box}html,body{margin:0}body{background:var(--bg);color:var(--ink);font:16px/1.5 var(--sans);padding:0 16px 48px}
a{color:var(--accent)}h1,h2,h3{line-height:1.2;margin:0 0 8px}h1{font-size:28px}h2{font-size:19px}h3{font-size:16px}
.wrap{max-width:1180px;margin:0 auto}header{padding:28px 0 12px}.tag{color:var(--muted);margin:0}
.badges{display:flex;flex-wrap:wrap;gap:8px;margin:12px 0 0}.badge{background:var(--chip);border:1px solid var(--line);border-radius:999px;padding:3px 10px;font-size:13px}
.badge.ok{border-color:var(--ok)}.badge.bad{border-color:var(--bad)}.badge.warn{border-color:var(--warn)}
.grid{display:grid;grid-template-columns:minmax(0,1.5fr) minmax(0,1fr);gap:16px;align-items:start}@media (max-width:900px){.grid{grid-template-columns:1fr}}
.panel{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:16px;margin:0 0 16px}
.player{display:flex;gap:12px;align-items:center;flex-wrap:wrap}.play{background:var(--accent);color:var(--accent-ink);border:0;border-radius:999px;width:56px;height:56px;font-size:22px;cursor:pointer}
.play:focus-visible{outline:3px solid var(--warn)}.time{font-family:var(--mono);color:var(--muted);font-size:14px}audio{width:100%;margin-top:8px}
.transcript{list-style:none;margin:12px 0 0;padding:0;max-height:520px;overflow:auto;border-top:1px solid var(--line)}
.transcript li{padding:8px 10px;border-bottom:1px solid var(--line);cursor:pointer;display:grid;grid-template-columns:52px 1fr auto;gap:8px;align-items:baseline}
.transcript li:hover{background:var(--chip)}.transcript li.active{background:var(--chip);box-shadow:inset 3px 0 0 var(--accent)}
.transcript .t{font-family:var(--mono);font-size:12px;color:var(--muted)}.transcript .cites{font-size:12px;color:var(--muted);white-space:nowrap}
.drawer{border-top:1px solid var(--line);margin-top:12px;padding-top:12px}.drawer h3{margin-bottom:4px}
.cite{font-family:var(--mono);font-size:13px;padding:6px 8px;border:1px solid var(--line);border-radius:8px;margin:6px 0;background:var(--bg)}
.cite .src{color:var(--muted)}.muted{color:var(--muted)}.kv{display:grid;grid-template-columns:auto 1fr;gap:4px 12px;font-size:14px}.kv dt{color:var(--muted)}.kv dd{margin:0}
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(120px,1fr));gap:8px}.stat{border:1px solid var(--line);border-radius:10px;padding:10px;background:var(--bg)}
.stat b{display:block;font-size:22px}.stat span{font-size:12px;color:var(--muted)}
.phone{border:1px solid var(--line);border-radius:16px;padding:12px;background:var(--bg);max-width:360px}.phone .app{font-size:12px;color:var(--muted)}.phone .body{margin:4px 0}
.toggle{display:inline-flex;border:1px solid var(--line);border-radius:999px;overflow:hidden}.toggle button{border:0;background:transparent;color:var(--ink);padding:6px 14px;cursor:pointer}.toggle button[aria-pressed="true"]{background:var(--accent);color:var(--accent-ink)}
.card{border:1px solid var(--line);border-radius:10px;padding:12px;margin:10px 0;background:var(--bg)}.card h3{display:flex;justify-content:space-between;gap:8px;flex-wrap:wrap}
pre{white-space:pre-wrap;word-break:break-word;font:13px/1.45 var(--mono);background:var(--panel);border:1px solid var(--line);border-radius:8px;padding:10px;margin:8px 0 0;max-height:360px;overflow:auto}
table{width:100%;border-collapse:collapse;font-size:13px}th,td{text-align:left;padding:6px 8px;border-bottom:1px solid var(--line);vertical-align:top}th{color:var(--muted);font-weight:600}
.pill{display:inline-block;border-radius:6px;padding:1px 7px;font-size:12px;font-weight:600}.pill.ok{background:var(--ok);color:#06240f}.pill.bad{background:var(--bad);color:#fff}.pill.warn{background:var(--warn);color:#1a1200}
.notice{border-left:4px solid var(--warn);padding:8px 12px;background:var(--chip);border-radius:8px;margin:0 0 12px}.notice.bad{border-left-color:var(--bad)}
details summary{cursor:pointer;color:var(--accent)}footer{color:var(--muted);font-size:13px;margin-top:24px}
.sr{position:absolute;left:-9999px}
</style>
</head>
<body>
<div class="wrap">
<header>
  <h1>Exposure Radio</h1>
  <p class="tag">Two Tenable exports in, one verified priority briefing out. Every sentence below cites a fact; the gate receipt hash is burned into the audio's transcript.</p>
  <div class="badges" id="badges"></div>
</header>
<div id="notices"></div>
<div class="grid">
  <main>
    <section class="panel" aria-labelledby="listen-h">
      <h2 id="listen-h">Listen</h2>
      <div class="player">
        <button class="play" id="play" aria-label="Play the sample">&#9654;</button>
        <div><div id="episode-line"></div><div class="time" id="time">0:00 / 0:00</div></div>
      </div>
      <audio id="audio" controls preload="metadata" src="sample.mp3"></audio>
      <ol class="transcript" id="transcript" aria-label="Transcript"></ol>
      <div class="drawer" id="drawer"><h3>Citations</h3><p class="muted">Select a sentence to see the facts it cites, each with its source in the ledger.</p></div>
    </section>
    <section class="panel" aria-labelledby="cards-h">
      <h2 id="cards-h">Action cards</h2>
      <p class="muted">Ticket-ready text per priority item. The CISO edition withholds asset identifiers and is audited before it is written; if that audit fails, the edition is withheld rather than shown.</p>
      <div class="toggle" role="group" aria-label="Edition">
        <button id="ed-full" aria-pressed="true">Full edition</button>
        <button id="ed-ciso" aria-pressed="false">CISO edition</button>
      </div>
      <div id="cards"></div>
    </section>
    <section class="panel" aria-labelledby="gate-h">
      <h2 id="gate-h">The gate</h2>
      <div id="receipt"></div>
      <h3 style="margin-top:12px">Planted false claims (make gate-demo)</h3>
      <div id="gate-cases"></div>
    </section>
    <section class="panel" aria-labelledby="agent-h">
      <h2 id="agent-h">Analyst agent replay</h2>
      <div id="agent"></div>
    </section>
  </main>
  <aside>
    <section class="panel" aria-labelledby="decision-h"><h2 id="decision-h">Decision</h2><div id="decision"></div></section>
    <section class="panel" aria-labelledby="delta-h"><h2 id="delta-h">What changed</h2><div id="delta"></div></section>
    <section class="panel" aria-labelledby="alert-h"><h2 id="alert-h">Alert preview (zero PII)</h2><div id="alert"></div></section>
    <section class="panel" aria-labelledby="audio-h"><h2 id="audio-h">Audio</h2><div id="audio-info"></div></section>
    <section class="panel" aria-labelledby="sources-h"><h2 id="sources-h">Sources ledger</h2><div id="sources"></div></section>
    <section class="panel" aria-labelledby="bench-h"><h2 id="bench-h">Prep time</h2><div id="bench"></div></section>
  </aside>
</div>
<footer id="footer"></footer>
</div>
<script id="episode-data" type="application/json">__DATA__</script>
<script>
(function(){
  const data = JSON.parse(document.getElementById('episode-data').textContent);
  const $ = (id) => document.getElementById(id);
  function el(tag, attrs, children){
    const node = document.createElement(tag);
    if (attrs) for (const k in attrs){ if (k === 'text') node.textContent = attrs[k]; else if (k === 'class') node.className = attrs[k]; else node.setAttribute(k, attrs[k]); }
    (children || []).forEach(c => node.appendChild(typeof c === 'string' ? document.createTextNode(c) : c));
    return node;
  }
  function fmt(s){ s = Math.max(0, s|0); return Math.floor(s/60) + ':' + String(s%60).padStart(2,'0'); }
  function parseVtt(text){
    const cues = []; if (!text) return cues;
    text.replace(/\r\n/g,'\n').split('\n\n').forEach(block => {
      const lines = block.trim().split('\n'); if (!lines.length || /^(WEBVTT|NOTE)/.test(lines[0])) return;
      const idx = lines.findIndex(l => l.includes('-->')); if (idx < 0) return;
      const [a, b] = lines[idx].split('-->').map(x => x.trim());
      const sec = t => t.split(':').reduce((acc, p) => acc * 60 + parseFloat(p), 0);
      cues.push({start: sec(a), end: sec(b), text: lines.slice(idx+1).join(' ')});
    });
    return cues;
  }
  const cues = parseVtt(data.vtt);
  const audioOk = data.audio_matches_receipt && cues.length === data.transcript.length;

  // Badges and notices
  const badges = $('badges');
  badges.appendChild(el('span', {class: 'badge ' + (data.receipt.passed ? 'ok' : 'bad'), text: 'Gate ' + (data.receipt.passed ? 'PASS' : 'FAIL') + ': ' + data.receipt.claims_accepted + '/' + data.receipt.claims_total + ' claims'}));
  badges.appendChild(el('span', {class: 'badge', text: 'Episode ' + data.episode_date + (data.previous_date ? ' vs ' + data.previous_date : '')}));
  if (data.decision) badges.appendChild(el('span', {class: 'badge ' + (data.decision.kind === 'BREAK_IN' ? 'warn' : ''), text: 'Decision ' + data.decision.kind}));
  if (data.audio && data.audio.loudness) badges.appendChild(el('span', {class: 'badge ' + (data.audio.within_targets ? 'ok' : 'warn'), text: data.audio.loudness.integrated_lufs + ' LUFS, ' + data.audio.loudness.true_peak_dbtp + ' dBTP'}));
  badges.appendChild(el('span', {class: 'badge', text: 'Synthetic estate, ' + data.identifier_count + ' identifiers audited'}));
  if (!audioOk) $('notices').appendChild(el('div', {class: 'notice bad', text: 'The audio file does not match this script\'s gate receipt (' + (data.audio ? 'stale audio' : 'no audio') + '). Playback is disabled until make audio and make site are rerun.'}));
  if (data.held) $('notices').appendChild(el('div', {class: 'notice', text: 'This episode is HELD: the export is incomplete, so no closure is reported.'}));

  // Player and transcript
  const audio = $('audio'); const play = $('play');
  $('episode-line').textContent = 'Episode for ' + data.episode_date + ' (' + data.transcript.length + ' sentences' + (data.audio ? ', ' + fmt(data.audio.duration_seconds) + ')' : ')');
  if (!audioOk) { audio.removeAttribute('src'); play.disabled = true; }
  play.addEventListener('click', () => { if (audio.paused) audio.play(); else audio.pause(); });
  audio.addEventListener('play', () => { play.innerHTML = '&#10074;&#10074;'; play.setAttribute('aria-label', 'Pause'); });
  audio.addEventListener('pause', () => { play.innerHTML = '&#9654;'; play.setAttribute('aria-label', 'Play the sample'); });
  const list = $('transcript'); const rows = [];
  data.transcript.forEach((row, i) => {
    const cue = cues[i];
    const li = el('li', {tabindex: '0', 'data-i': String(i)}, [
      el('span', {class: 't', text: cue ? fmt(cue.start) : ''}),
      el('span', {text: row.text}),
      el('span', {class: 'cites', text: row.cites.length ? row.cites.map(c => c.fact).join(' ') : (row.template.startsWith('intro') || row.template.startsWith('outro') ? 'fixed intro' : '')})
    ]);
    li.addEventListener('click', () => { select(i); if (cue && audioOk) { audio.currentTime = cue.start + 0.01; audio.play(); } });
    li.addEventListener('keydown', e => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); li.click(); } });
    list.appendChild(li); rows.push(li);
  });
  const sourcesById = {}; data.sources.forEach(s => sourcesById[s.id] = s);
  function select(i){
    rows.forEach((r, j) => r.classList.toggle('active', j === i));
    const row = data.transcript[i]; const d = $('drawer'); d.textContent = '';
    d.appendChild(el('h3', {text: 'Citations for sentence ' + (i+1)}));
    d.appendChild(el('p', {class: 'muted', text: 'Template ' + row.template + (row.cites.length ? '' : ' (fixed sentence, no claim)')}));
    row.cites.forEach(c => {
      const src = sourcesById[c.source] || {};
      d.appendChild(el('div', {class: 'cite'}, [
        el('div', {text: c.fact + '  ' + c.subject + '  ' + c.predicate + ' = ' + JSON.stringify(c.value)}),
        el('div', {class: 'src', text: 'source ' + c.source + (src.title ? ' | ' + src.title : '') + (src.version ? ' ' + src.version : '') + (src.sha256 ? ' | sha256 ' + src.sha256.slice(0, 12) : '')})
      ]));
    });
    rows[i].scrollIntoView({block: 'nearest'});
  }
  let current = -1;
  audio.addEventListener('timeupdate', () => {
    $('time').textContent = fmt(audio.currentTime) + ' / ' + fmt(audio.duration || 0);
    const t = audio.currentTime; let idx = -1;
    for (let i = 0; i < cues.length; i++) { if (t >= cues[i].start - 0.05 && t < cues[i].end + 0.3) { idx = i; break; } }
    if (idx >= 0 && idx !== current) { current = idx; select(idx); }
  });
  audio.addEventListener('loadedmetadata', () => { $('time').textContent = '0:00 / ' + fmt(audio.duration); });

  // Decision, delta, alert
  const dec = $('decision');
  if (data.decision) {
    dec.appendChild(el('p', {}, [el('span', {class: 'pill ' + (data.decision.kind === 'BREAK_IN' ? 'warn' : 'ok'), text: data.decision.kind}), ' ', data.decision.lead ? 'lead ' + data.decision.lead : '']));
    const ul = el('ul'); data.decision.reasons.forEach(r => ul.appendChild(el('li', {text: r}))); data.decision.health.forEach(h => ul.appendChild(el('li', {class: 'muted', text: 'health: ' + h}))); dec.appendChild(ul);
  }
  const delta = data.delta; const stats = el('div', {class: 'stats'});
  [['critical_closed','criticals closed'],['new_exposure','new exposure'],['new_visibility','new visibility'],['unverified_absence','unverified absences'],['assets_rescanned','assets rescanned'],['assets_not_rescanned','assets not rescanned'],['assets_newly_in_scope','new in scope']].forEach(([k, label]) => {
    stats.appendChild(el('div', {class: 'stat'}, [el('b', {text: String(delta[k] == null ? 0 : delta[k])}), el('span', {text: label})]));
  });
  $('delta').appendChild(stats);
  if (data.trend && data.trend.length) {
    const t = el('table'); t.appendChild(el('tr', {}, [el('th', {text: 'episode'}), el('th', {text: 'assets'}), el('th', {text: 'open critical'}), el('th', {text: 'open high'}), el('th', {text: 'KEV CVEs'})]));
    data.trend.forEach(r => t.appendChild(el('tr', {}, [el('td', {text: r.episode_date}), el('td', {text: String(r.assets)}), el('td', {text: String(r.open_critical)}), el('td', {text: String(r.open_high)}), el('td', {text: String(r.kev_open_cves)})])));
    $('delta').appendChild(el('div', {style: 'margin-top:10px'}, [t]));
  }
  const alert = data.alert; const phone = el('div', {class: 'phone'});
  phone.appendChild(el('div', {class: 'app', text: 'now'}));
  phone.appendChild(el('div', {}, [el('b', {text: alert.title})]));
  phone.appendChild(el('div', {class: 'body', text: alert.suppressed ? '(suppressed: ' + alert.reason + ')' : alert.body}));
  phone.appendChild(el('div', {class: 'app', text: 'ref ' + alert.reference}));
  $('alert').appendChild(phone);
  $('alert').appendChild(el('p', {class: 'muted', text: 'No hostnames, asset ids or CVE ids are allowed in the alert; the audit that enforces it ran clean: ' + (data.pii_audit.alert.length === 0 ? 'yes' : 'NO')}));

  // Cards with edition toggle
  function renderCards(edition){
    const packet = edition === 'full' ? data.packet_full : data.packet_ciso; const box = $('cards'); box.textContent = '';
    $('ed-full').setAttribute('aria-pressed', String(edition === 'full')); $('ed-ciso').setAttribute('aria-pressed', String(edition === 'ciso'));
    if (packet.withheld) { box.appendChild(el('div', {class: 'notice bad', text: 'CISO edition withheld: ' + packet.reason + '. Nothing is shown rather than something that leaks.'})); return; }
    box.appendChild(el('p', {class: 'muted', text: edition === 'ciso' ? 'Identifiers withheld; counts and groups only. Audit: ' + (data.pii_audit.ciso_packet.length === 0 ? 'clean' : 'LEAK') : 'Full edition: affected assets listed (synthetic names).'}));
    (packet.items || []).forEach(item => {
      const card = el('div', {class: 'card'});
      card.appendChild(el('h3', {}, [el('span', {text: '#' + item.rank + ' ' + item.cve + ' (' + item.severity + (item.kev ? ', KEV-listed' : '') + ')'}), el('span', {class: 'pill ' + (item.kev ? 'warn' : 'ok'), text: 'SLA ' + item.deadline.internal_sla})]));
      const dl = el('dl', {class: 'kv'});
      [['Owner', item.owner], ['Open on', item.open_asset_count + ' asset(s)'], ['KEV added', item.kev ? item.kev.date_added : 'not listed'], ['Catalogue dueDate', item.kev && item.kev.catalogue_due_date ? item.kev.catalogue_due_date + ' (CISA field)' : 'n/a'], ['EPSS', item.epss ? (item.epss.score * 100).toFixed(1) + '%' : 'not in snapshot'], ['Assets', item.assets.length ? item.assets.join(', ') : 'withheld in this edition']].forEach(([k, v]) => { dl.appendChild(el('dt', {text: k})); dl.appendChild(el('dd', {text: String(v)})); });
      card.appendChild(dl);
      const det = el('details'); det.appendChild(el('summary', {text: 'Ticket text (copyable Markdown) and evidence'})); det.appendChild(el('pre', {text: item.ticket_markdown})); card.appendChild(det);
      box.appendChild(card);
    });
  }
  $('ed-full').addEventListener('click', () => renderCards('full')); $('ed-ciso').addEventListener('click', () => renderCards('ciso'));
  renderCards('full');

  // Gate receipt and planted cases
  const rec = data.receipt; const rbox = $('receipt');
  rbox.appendChild(el('p', {}, [el('span', {class: 'pill ' + (rec.passed ? 'ok' : 'bad'), text: rec.passed ? 'PASS' : 'FAIL'}), ' ' + rec.sentence_count + ' sentences, ' + rec.claims_accepted + ' of ' + rec.claims_total + ' claims validated, ' + rec.templates_used.length + ' templates. Script sha256 ' + rec.script_sha256.slice(0, 16) + '…']));
  const cl = el('ul'); Object.entries(rec.checks).forEach(([k, v]) => cl.appendChild(el('li', {text: (v ? '✓ ' : '✗ ') + k}))); rbox.appendChild(cl);
  const gt = el('table'); gt.appendChild(el('tr', {}, [el('th', {text: 'planted'}), el('th', {text: 'result'}), el('th', {text: 'codes'})]));
  data.gate_demo.cases.forEach(c => gt.appendChild(el('tr', {}, [el('td', {text: c.planted}), el('td', {}, [el('span', {class: 'pill ' + (c.ok ? 'ok' : 'bad'), text: c.ok ? 'BLOCKED' : 'MISSED'})]), el('td', {text: c.codes.join(', ')})])));
  $('gate-cases').appendChild(gt);

  // Agent replay
  const ag = $('agent');
  if (!data.agent) ag.appendChild(el('p', {class: 'muted', text: 'No recorded replay.'}));
  else {
    ag.appendChild(el('p', {text: 'Recorded with the ' + data.agent.recorded_transport + ' transport and replayed through a live gate: ' + data.agent.mode + ' edition, ' + data.agent.calls + ' calls, ' + data.agent.tokens + ' tokens, ' + data.agent.retries + ' rewrite(s). Caps: ' + JSON.stringify(data.agent.caps)}));
    const ul = el('ul');
    data.agent.events.forEach(e => {
      if (e.type === 'gate') ul.appendChild(el('li', {}, [el('span', {class: 'pill ' + (e.accepted ? 'ok' : 'bad'), text: e.accepted ? 'gate accepted' : 'gate rejected'}), ' ' + (e.accepted ? 'the proposal airs' : e.reasons.map(r => r.code + ': ' + r.detail).join('; '))]));
      else if (e.type === 'tool_call') ul.appendChild(el('li', {text: 'tool ' + e.tool}));
      else if (e.type === 'final') ul.appendChild(el('li', {text: 'final: ' + e.mode + (e.items ? ' items ' + e.items.join(', ') + ', angle ' + e.angle + ', break-in ' + e.break_in : '')}));
      else if (e.type === 'abort') ul.appendChild(el('li', {text: 'abort: ' + e.reason}));
    });
    ag.appendChild(ul);
    const q = el('details'); q.appendChild(el('summary', {text: 'What the model said each turn'}));
    const ol = el('ol'); data.agent.model_text.forEach(t => ol.appendChild(el('li', {text: t}))); q.appendChild(ol); ag.appendChild(q);
  }

  // Audio info
  const ai = $('audio-info');
  if (data.audio) {
    const dl = el('dl', {class: 'kv'});
    [['Engine', data.audio.synth ? data.audio.synth.engine + ', voice ' + data.audio.synth.voice : 'n/a'], ['Integrated', data.audio.loudness.integrated_lufs + ' LUFS (target ' + data.audio.targets.integrated_lufs + ')'], ['True peak', data.audio.loudness.true_peak_dbtp + ' dBTP (limit ' + data.audio.targets.true_peak_dbtp + ')'], ['Duration', fmt(data.audio.duration_seconds)], ['Receipt', (data.audio.receipt_sha256 || '').slice(0, 16) + (data.audio_matches_receipt ? ' (matches script)' : ' (STALE)')]].forEach(([k, v]) => { dl.appendChild(el('dt', {text: k})); dl.appendChild(el('dd', {text: String(v)})); });
    ai.appendChild(dl);
  } else ai.appendChild(el('p', {class: 'muted', text: 'No audio built yet (make audio).'}));

  // Sources
  const st = el('table'); st.appendChild(el('tr', {}, [el('th', {text: 'id'}), el('th', {text: 'what'}), el('th', {text: 'sha256'})]));
  data.sources.forEach(s => st.appendChild(el('tr', {}, [el('td', {text: s.id}), el('td', {text: s.title + (s.version ? ' ' + s.version : '') + (s.coverage ? ' (' + s.coverage + ')' : '')}), el('td', {text: (s.sha256 || '').slice(0, 12)})])));
  $('sources').appendChild(st);

  // Bench
  const bb = $('bench');
  if (data.bench) {
    const b = data.bench; const dl = el('dl', {class: 'kv'});
    [['Fixture', b.counts.raw_rows_both_exports + ' rows, ' + b.counts.assets_current + ' assets'], ['Pipeline', b.pipeline_seconds.median + ' s median of ' + b.runs], ['Manual model', Math.round(b.manual_total_seconds / 60) + ' min'], ['Saved', Math.round(b.prep_time_saved_seconds / 60) + ' min per episode (prep time, not remediation)']].forEach(([k, v]) => { dl.appendChild(el('dt', {text: k})); dl.appendChild(el('dd', {text: String(v)})); });
    bb.appendChild(dl);
  } else bb.appendChild(el('p', {class: 'muted', text: 'Run make bench to fill this in.'}));

  $('footer').textContent = 'Exposure Radio ' + data.version + ' · page built ' + data.built_at + ' · synthetic tenant, real CISA KEV and FIRST EPSS snapshots · no external resources, no tracking.';
  if (data.transcript.length) select(0);
})();
</script>
</body>
</html>
"""

if __name__ == "__main__":
    raise SystemExit(main())
