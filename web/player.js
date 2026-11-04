'use strict';
/* Exposure Radio listener. Reads station/station.json (docs/STATION.md). No data is
   written with innerHTML; everything from the document goes through textContent. */
(() => {
  const STATION_URL = 'station/station.json';
  const DEMO_KEY = 'exposure-radio.demo.v1';
  const VOLUME_KEY = 'exposure-radio.volume';
  const NOW_KEY = 'exposure-radio.nowplaying';
  const KIND = {
    ident: 'STATION', exposure: 'EXPOSURE', learn: 'LEARN', weather: 'WEATHER',
    news: 'NEWS', music: 'MUSIC', wins: 'WINS', blindspots: 'BLIND SPOTS'
  };
  const BAND_ORDER = ['exposure', 'wins', 'blindspots', 'learn', 'weather', 'news', 'music'];

  const $ = id => document.getElementById(id);
  const el = (tag, cls, text) => {
    const n = document.createElement(tag);
    if (cls) n.className = cls;
    if (text != null) n.textContent = text;
    return n;
  };
  const kindLabel = k => KIND[k] || String(k || 'segment').toUpperCase();
  const clock = s => {
    if (!Number.isFinite(s) || s < 0) s = 0;
    const m = Math.floor(s / 60), r = Math.floor(s % 60);
    return `${String(m).padStart(2, '0')}:${String(r).padStart(2, '0')}`;
  };
  const reducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)');

  const audio = $('audio');
  const state = {
    doc: null, sig: '', rundown: [], hosts: {}, tracks: {},
    index: 0, started: false, playing: false, errors: 0,
    volume: 80, muted: false, turn: -1, prefetch: null, switching: false
  };

  /* ---------------- data ---------------- */
  function readDemo() {
    try { return JSON.parse(localStorage.getItem(DEMO_KEY) || 'null'); } catch (_) { return null; }
  }
  function buildRundown(doc) {
    let list = Array.isArray(doc.rundown) ? doc.rundown.filter(s => s && s.id) : [];
    const demo = readDemo();
    if (demo && demo.queue && Array.isArray(demo.queue.extra)) {
      list = list.concat(demo.queue.extra.filter(x => x && x.id && x.youtube && !list.some(s => s.id === x.id)));
    }
    if (demo && demo.queue && Array.isArray(demo.queue.order)) {
      const byId = new Map(list.map(s => [s.id, s]));
      const removed = new Set(demo.queue.removed || []);
      const ordered = demo.queue.order.map(id => byId.get(id)).filter(Boolean);
      const rest = list.filter(s => !demo.queue.order.includes(s.id) && !removed.has(s.id));
      const merged = ordered.concat(rest);
      if (merged.length) list = merged;
    }
    if (demo && demo.settings && demo.settings.segments) {
      const seg = demo.settings.segments;
      const kept = list.filter(s => s.kind === 'ident' || !seg[s.kind] || seg[s.kind].enabled !== false);
      if (kept.length) list = kept;
    }
    return list;
  }
  async function fetchDoc() {
    const res = await fetch(STATION_URL, { cache: 'no-cache', credentials: 'same-origin' });
    if (!res.ok) throw new Error(`station.json ${res.status}`);
    return res.json();
  }
  function applyDoc(doc, keepId) {
    const demo = readDemo();
    const demoName = demo && demo.settings && demo.settings.station && demo.settings.station.name;
    if (demoName) doc = Object.assign({}, doc, { station: Object.assign({}, doc.station, { name: demoName }) });
    state.doc = doc;
    state.hosts = Object.fromEntries((doc.hosts || []).map(h => [h.id, h]));
    state.tracks = Object.fromEntries(((doc.music && doc.music.tracks) || []).map(t => [t.id, t]));
    state.rundown = buildRundown(doc);
    if (keepId) {
      const i = state.rundown.findIndex(s => s.id === keepId);
      state.index = i >= 0 ? i : Math.min(state.index, Math.max(0, state.rundown.length - 1));
    }
    state.sig = JSON.stringify([doc.rundown, readDemo()]);
    renderStation();
    renderRundown();
    renderBands();
  }
  async function refreshDoc() {
    try {
      const doc = await fetchDoc();
      const sig = JSON.stringify([doc.rundown, readDemo()]);
      if (sig === state.sig) return;
      const cur = current();
      applyDoc(doc, cur && cur.id);
      updateNow(false);
    } catch (_) { /* keep playing what we have */ }
  }

  const current = () => state.rundown[state.index];
  function audioUrl(seg) {
    if (!seg) return '';
    if (seg.audio) return seg.audio;
    const t = seg.track && state.tracks[seg.track];
    return t && t.audio ? t.audio : '';
  }
  function segDuration(seg) {
    if (!seg) return 0;
    if (Number.isFinite(seg.duration)) return seg.duration;
    const t = seg.track && state.tracks[seg.track];
    return t && Number.isFinite(t.duration) ? t.duration : 0;
  }

  /* ---------------- render ---------------- */
  function renderStation() {
    const st = state.doc.station || {};
    $('station-name').textContent = (st.name || 'Exposure Radio').toUpperCase();
    $('station-tagline').textContent = st.tagline || "Your team's security station";
    document.title = `${st.name || 'Exposure Radio'} · ${st.tagline || "your team's security station"}`;
    const ed = $('edition');
    ed.textContent = st.edition || '';
    ed.hidden = !st.edition;
    const parts = [];
    if (st.as_of) parts.push(`AS OF ${String(st.as_of).replace('T', ' ')}`);
    $('asof').textContent = parts.join(' · ');
    const loc = st.location && st.location.label;
    $('foot-loc').textContent = [loc, st.as_of ? `DATA AS OF ${String(st.as_of).replace('T', ' ')}` : ''].filter(Boolean).join(' · ');
    const total = state.rundown.reduce((a, s) => a + segDuration(s), 0);
    $('rundown-total').textContent = `${state.rundown.length} SEGMENTS · ${clock(total)}`;
  }

  function renderRundown() {
    const list = $('rundown');
    const tl = $('timeline');
    list.replaceChildren();
    tl.replaceChildren();
    const total = state.rundown.reduce((a, s) => a + Math.max(segDuration(s), 1), 0) || 1;
    state.rundown.forEach((seg, i) => {
      const li = el('li');
      const b = el('button', 'rd');
      b.type = 'button';
      b.dataset.index = String(i);
      if (seg.priority) b.classList.add('is-priority');
      const num = el('span', 'rd-num', String(i + 1).padStart(2, '0'));
      const kind = el('span', 'rd-kind');
      const tag = el('span', seg.priority ? 'tag tag-priority' : (seg.kind === 'music' || seg.kind === 'ident' ? 'tag tag-quiet' : 'tag'), seg.priority ? 'PRIORITY' : kindLabel(seg.kind));
      kind.append(tag);
      const text = el('span', 'rd-text');
      text.append(el('span', 'rd-title', seg.title || 'Untitled segment'));
      const track = seg.track && state.tracks[seg.track];
      const sub = seg.subtitle || (track ? track.artist : '');
      if (sub) text.append(el('span', 'rd-sub', sub));
      const dur = el('span', 'rd-dur');
      dur.append(el('span', 'rd-now', 'NOW'), el('span', null, clock(segDuration(seg))));
      b.append(num, kind, text, dur);
      b.setAttribute('aria-label', `${i + 1}. ${seg.priority ? 'Priority ' : ''}${kindLabel(seg.kind).toLowerCase()}: ${seg.title || 'Untitled'}. ${clock(segDuration(seg))}. Play now.`);
      b.addEventListener('click', () => jump(i));
      li.append(b);
      list.append(li);

      const t = el('li', `k-${seg.kind}${seg.priority ? ' priority' : ''}`);
      t.style.flexGrow = String(Math.max(segDuration(seg), 1) / total * 100);
      t.append(el('span'));
      tl.append(t);
    });
    markRundown();
  }

  function markRundown() {
    document.querySelectorAll('#rundown .rd').forEach(b => {
      const i = Number(b.dataset.index);
      if (i === state.index && state.started) b.setAttribute('aria-current', 'true');
      else b.removeAttribute('aria-current');
      b.classList.toggle('played', state.started && i < state.index);
    });
    document.querySelectorAll('#timeline li').forEach((t, i) => {
      t.classList.toggle('played', state.started && i < state.index);
      const fill = t.firstChild;
      if (fill && i !== state.index) fill.style.width = (state.started && i < state.index) ? '100%' : '0';
    });
  }

  function renderBands() {
    const box = $('bands');
    box.replaceChildren();
    const present = new Set(state.rundown.map(s => s.kind));
    BAND_ORDER.filter(k => present.has(k)).forEach(k => {
      const b = el('button', 'band', kindLabel(k));
      b.type = 'button';
      b.dataset.kind = k;
      b.setAttribute('aria-pressed', 'false');
      b.title = `Jump to the next ${kindLabel(k).toLowerCase()} segment`;
      b.addEventListener('click', () => tuneBand(k));
      box.append(b);
    });
  }

  function updateNow(fresh = true) {
    const seg = current();
    const total = state.rundown.length;
    if (!seg) return;
    const pri = !!seg.priority;
    $('now-kind').textContent = kindLabel(seg.kind);
    $('now-kind').className = seg.kind === 'music' || seg.kind === 'ident' ? 'tag tag-quiet' : 'tag';
    $('now-priority').hidden = !pri;
    $('now-index').textContent = `${String(state.index + 1).padStart(2, '0')} / ${String(total).padStart(2, '0')}`;
    $('now-title').textContent = seg.title || 'Untitled segment';
    const track = seg.track && state.tracks[seg.track];
    $('now-sub').textContent = seg.subtitle || (track ? `${track.title} · ${track.artist}` : '');
    $('now').classList.toggle('is-priority', pri);
    $('screen').classList.toggle('is-priority', pri);
    $('tune').classList.toggle('is-priority', pri);
    $('screen-priority').hidden = !pri;
    $('screen-kind').textContent = kindLabel(seg.kind);
    $('screen-seg').textContent = `SEG ${String(state.index + 1).padStart(2, '0')}/${String(total).padStart(2, '0')}`;
    $('t-total').textContent = isYouTube(seg) && !segDuration(seg) ? '--:--' : clock(segDuration(seg));
    const details = $('details');
    const hasTurns = Array.isArray(seg.turns) && seg.turns.length;
    details.hidden = !(seg.card || hasTurns || (seg.sources && seg.sources.length) || (seg.watch && seg.watch.length));
    details.textContent = seg.card ? 'Open action card' : 'Transcript & sources';
    document.querySelectorAll('#bands .band').forEach(b => b.setAttribute('aria-pressed', String(state.started && b.dataset.kind === seg.kind)));
    if (fresh) {
      state.turn = -2;
      setMic(null);
      if (isYouTube(seg)) {
        setCaption(`On YouTube: ${seg.youtube.title || seg.title || 'video'}. It plays in the official player in the signal window.`, true);
      } else if (seg.kind === 'music') {
        setCaption(track ? `Now spinning: ${track.title} · ${track.artist}` : 'Music break', true);
      } else if (!hasTurns) {
        setCaption(seg.subtitle || seg.title || '', true);
      } else {
        setCaption(state.started ? (seg.subtitle || seg.title || '') : 'Press Tune In to start the station.', true);
      }
    }
    markRundown();
    syncTime();
    viz.mode(pri);
  }

  function setMic(turn) {
    const mic = $('mic');
    if (!turn) {
      const seg = current();
      const track = seg && seg.track && state.tracks[seg.track];
      $('mic-name').textContent = isYouTube(seg) ? 'YouTube' : seg && seg.kind === 'music' ? (track ? track.artist : 'Music') : 'Nobody yet';
      $('mic-role').textContent = '';
      mic.classList.remove('speaking');
      return;
    }
    const h = state.hosts[turn.host] || { name: turn.host || 'Host' };
    $('mic-name').textContent = h.name || turn.host;
    $('mic-role').textContent = h.role ? `· ${h.role}` : '';
  }
  function setCaption(text, dim) {
    const c = $('caption');
    if (c.textContent !== text) c.textContent = text;
    c.classList.toggle('dim', !!dim);
  }

  function syncTime() {
    const seg = current();
    if (!seg) return;
    const ytOn = isYouTube(seg) && yt.player && yt.ready;
    const t = !state.started ? 0 : ytOn ? (yt.player.getCurrentTime() || 0) : (audio.currentTime || 0);
    const md = ytOn ? yt.player.getDuration() : audio.duration;
    const d = (Number.isFinite(md) && md > 0 && state.started) ? md : segDuration(seg);
    if (ytOn && Number.isFinite(md) && md > 0) $('t-total').textContent = clock(md);
    const pct = d ? Math.min(100, t / d * 100) : 0;
    $('progress-bar').style.width = `${pct}%`;
    $('t-elapsed').textContent = clock(t);
    $('screen-time').textContent = `${clock(t)} / ${clock(d)}`;
    const fill = $('timeline').children[state.index];
    if (fill && fill.firstChild) fill.firstChild.style.width = state.started ? `${pct}%` : '0';
    if (!state.started) return;
    const turns = Array.isArray(seg.turns) ? seg.turns : [];
    let idx = -1;
    for (let i = 0; i < turns.length; i++) if (turns[i].start <= t + 0.05) idx = i;
    const speaking = idx >= 0 && t < turns[idx].end + 0.05;
    $('mic').classList.toggle('speaking', speaking && state.playing);
    if (idx !== state.turn && idx >= 0) {
      state.turn = idx;
      const turn = turns[idx];
      setMic(turn);
      setCaption(turn.caption || turn.text || '', false);
    }
  }

  function setAir(mode, text) {
    const pill = $('air-pill');
    pill.className = `pill pill-${mode}`;
    $('air-text').textContent = text;
  }
  function setStatus(text) { $('status').textContent = text; }
  /* Lets the console in this same browser show what is on air (demo convenience). */
  function publishNow() {
    const seg = current();
    if (!seg || !state.started) return;
    try { localStorage.setItem(NOW_KEY, JSON.stringify({ id: seg.id, title: seg.title || '', playing: state.playing, ts: Date.now() })); } catch (_) {}
  }
  setInterval(() => { if (state.playing) publishNow(); }, 10000);
  function setPlayingUI() {
    const tune = $('tune');
    tune.classList.toggle('is-playing', state.playing);
    tune.setAttribute('aria-label', state.playing ? 'Pause' : 'Tune in');
    $('tune-label').textContent = state.playing ? 'PAUSE' : 'TUNE IN';
    if (state.playing) setAir('live', 'ON AIR');
    else setAir('standby', 'STANDBY');
    if ('mediaSession' in navigator) navigator.mediaSession.playbackState = state.playing ? 'playing' : 'paused';
    publishNow();
  }

  /* ---------------- playback ---------------- */
  let graph = null;
  function ensureGraph() {
    if (graph !== null) {
      if (graph && graph.ctx.state === 'suspended') graph.ctx.resume().catch(() => {});
      return;
    }
    try {
      const Ctx = window.AudioContext || window.webkitAudioContext;
      if (!Ctx) throw new Error('no WebAudio');
      const ctx = new Ctx();
      const src = ctx.createMediaElementSource(audio);
      const analyser = ctx.createAnalyser();
      analyser.fftSize = 512;
      analyser.smoothingTimeConstant = 0.82;
      const gain = ctx.createGain();
      src.connect(analyser);
      analyser.connect(gain);
      gain.connect(ctx.destination);
      graph = { ctx, analyser, gain, freq: new Uint8Array(analyser.frequencyBinCount), wave: new Uint8Array(analyser.fftSize) };
      viz.attach(graph);
    } catch (_) {
      graph = false;
    }
    applyVolume();
  }
  function applyVolume() {
    const v = state.muted ? 0 : state.volume / 100;
    if (graph) { audio.volume = 1; graph.gain.gain.setTargetAtTime(v, graph.ctx.currentTime, 0.03); }
    else audio.volume = v;
    if (yt.player && yt.ready) {
      try { yt.player.setVolume(state.volume); if (state.muted) yt.player.mute(); else yt.player.unMute(); } catch (_) {}
    }
  }

  /* ---------------- YouTube (official IFrame Player API) ----------------
     Loaded only when a YouTube item comes up. The video replaces the visualizer,
     stays visible at 200x200 px or more with nothing drawn over it, starts only when
     more than half of it is on screen, and never passes through WebAudio. */
  const yt = { player: null, ready: false, api: null, visible: false, want: false, timer: 0, observer: null };
  const isYouTube = seg => !!(seg && seg.youtube && seg.youtube.videoId);
  function youTubeApi() {
    if (window.YT && window.YT.Player) return Promise.resolve(window.YT);
    if (yt.api) return yt.api;
    yt.api = new Promise((resolve, reject) => {
      const prev = window.onYouTubeIframeAPIReady;
      window.onYouTubeIframeAPIReady = () => { if (typeof prev === 'function') prev(); resolve(window.YT); };
      const tag = document.createElement('script');
      tag.src = 'https://www.youtube.com/iframe_api';
      tag.async = true;
      tag.onerror = () => { yt.api = null; tag.remove(); reject(new Error('YouTube player unavailable')); };
      document.head.append(tag);
    });
    return yt.api;
  }
  function ytTryPlay() {
    if (!yt.player || !yt.ready || !yt.want) return;
    if (!yt.visible) { setStatus('Scroll the video window into view and it will start.'); return; }
    try { yt.player.playVideo(); } catch (_) {}
  }
  function enterYouTube(seg, autoplay) {
    state.switching = false;
    audio.pause();
    audio.removeAttribute('src');
    audio.load();
    const screen = $('screen'), mount = $('yt-host');
    screen.classList.add('is-youtube');
    mount.hidden = false;
    const target = el('div');
    mount.replaceChildren(target);
    yt.want = !!autoplay;
    yt.ready = false;
    if (!yt.observer && window.IntersectionObserver) {
      yt.observer = new IntersectionObserver(entries => {
        for (const e of entries) yt.visible = e.isIntersecting && e.intersectionRatio > 0.5;
        if (yt.visible && yt.player && yt.ready) {
          const st = yt.player.getPlayerState();
          if (yt.want && st !== 1 && st !== 3) ytTryPlay();
        }
      }, { threshold: [0, 0.5, 0.51, 0.75, 1] });
    }
    if (yt.observer) yt.observer.observe(mount); else yt.visible = true;
    setStatus('Loading the YouTube player…');
    youTubeApi().then(YT => {
      if (current() !== seg) return;
      yt.player = new YT.Player(target, {
        width: '100%', height: '100%', videoId: seg.youtube.videoId,
        playerVars: { enablejsapi: 1, origin: location.origin, playsinline: 1, rel: 0 },
        events: {
          onReady: () => { yt.ready = true; applyVolume(); setStatus(`${seg.youtube.title || seg.title || 'YouTube video'} is ready.`); ytTryPlay(); },
          onStateChange: e => {
            if (current() !== seg) return;
            if (e.data === 1) { state.playing = true; state.errors = 0; setPlayingUI(); setStatus(`On air from YouTube: ${seg.youtube.title || seg.title}.`); }
            else if (e.data === 2) { state.playing = false; yt.want = false; setPlayingUI(); setStatus('Paused. Press Tune In to pick up where you left off.'); }
            else if (e.data === 3) setAir('warn', 'TUNING');
            else if (e.data === 0) { next(true); }
          },
          onError: () => { if (current() === seg) { leaveYouTube(); onSegmentError(); } }
        }
      });
      clearInterval(yt.timer);
      yt.timer = setInterval(syncTime, 500);
    }).catch(() => { if (current() === seg) { leaveYouTube(); onSegmentError(); } });
  }
  function leaveYouTube() {
    clearInterval(yt.timer);
    if (yt.observer) yt.observer.disconnect();
    if (yt.player) { try { yt.player.destroy(); } catch (_) {} }
    yt.player = null; yt.ready = false; yt.want = false;
    const mount = $('yt-host');
    mount.replaceChildren();
    mount.hidden = true;
    $('screen').classList.remove('is-youtube');
  }

  function load(i, autoplay) {
    if (!state.rundown.length) return;
    state.index = (i + state.rundown.length) % state.rundown.length;
    const seg = current();
    const url = audioUrl(seg);
    if (yt.player || $('screen').classList.contains('is-youtube')) leaveYouTube();
    updateNow(true);
    setMeta(seg);
    publishNow();
    if (isYouTube(seg)) {
      enterYouTube(seg, autoplay);
      prefetchNext();
      refreshDoc();
      return;
    }
    if (!url) { onSegmentError(); return; }
    state.switching = autoplay;
    audio.src = url;
    if (autoplay) play();
    prefetchNext();
    refreshDoc();
  }
  function play() {
    ensureGraph();
    const p = audio.play();
    if (p && p.catch) p.catch(err => {
      state.switching = false;
      if (err && err.name === 'NotAllowedError') setStatus('Your browser blocked autoplay. Press Tune In to listen.');
    });
  }
  function prefetchNext() {
    if (state.prefetch) state.prefetch.abort();
    const next = state.rundown[(state.index + 1) % state.rundown.length];
    const url = audioUrl(next);
    if (!url || url === audioUrl(current()) || !window.AbortController) return;
    const ctl = new AbortController();
    state.prefetch = ctl;
    fetch(url, { signal: ctl.signal, priority: 'low' }).then(r => r.ok ? r.blob() : null).catch(() => {});
  }
  function next(auto) {
    if (!state.rundown.length) return;
    const wrap = state.index + 1 >= state.rundown.length;
    if (auto && wrap) setStatus('End of the rundown. Back to the top of the hour.');
    load(state.index + 1, state.started);
  }
  function back() {
    if (isYouTube(current()) && yt.ready) {
      if (yt.player.getCurrentTime() > 3) { yt.player.seekTo(0, true); syncTime(); return; }
    } else if (audio.currentTime > 3) { audio.currentTime = 0; syncTime(); return; }
    load(state.index - 1, state.started);
  }
  function jump(i) {
    state.started = true;
    state.errors = 0;
    load(i, true);
  }
  function tuneBand(kind) {
    const n = state.rundown.length;
    for (let k = 1; k <= n; k++) {
      const i = (state.index + (state.started ? k : k - 1)) % n;
      if (state.rundown[i].kind === kind) {
        setStatus(`Tuned to ${kindLabel(kind).toLowerCase()}: ${state.rundown[i].title}.`);
        jump(i);
        return;
      }
    }
  }
  function toggle() {
    if (!state.rundown.length) return;
    if (!state.started) {
      state.started = true;
      state.errors = 0;
      load(state.index, true);
      return;
    }
    if (isYouTube(current())) {
      const st = yt.player && yt.ready ? yt.player.getPlayerState() : -1;
      if (st === 1 || st === 3) { yt.want = false; yt.player.pauseVideo(); }
      else { yt.want = true; ytTryPlay(); }
      return;
    }
    if (audio.paused) play(); else audio.pause();
  }
  function onSegmentError() {
    state.switching = false;
    state.errors += 1;
    if (state.errors >= state.rundown.length) {
      state.playing = false;
      setPlayingUI();
      setAir('off', 'OFF AIR');
      setStatus('Station audio is unavailable right now. The rundown and transcripts are still below.');
      return;
    }
    setStatus(`“${(current() && current().title) || 'Segment'}” is unavailable. Skipping ahead.`);
    setTimeout(() => next(false), 900);
  }

  audio.addEventListener('playing', () => {
    state.switching = false;
    state.playing = true; state.errors = 0; setPlayingUI();
    const seg = current();
    if (seg) setStatus(`${seg.priority ? 'Priority break' : 'On air'}: ${seg.title || kindLabel(seg.kind)}.`);
  });
  audio.addEventListener('pause', () => {
    if (audio.ended || state.switching || isYouTube(current())) return;
    state.playing = false; setPlayingUI();
    if (state.started) setStatus('Paused. Press Tune In to pick up where you left off.');
  });
  audio.addEventListener('waiting', () => { if (state.playing) setAir('warn', 'TUNING'); });
  audio.addEventListener('ended', () => next(true));
  audio.addEventListener('timeupdate', syncTime);
  audio.addEventListener('error', () => { if (state.started && audio.getAttribute('src')) onSegmentError(); });

  /* ---------------- media session ---------------- */
  function setMeta(seg) {
    if (!('mediaSession' in navigator) || !seg) return;
    const st = (state.doc && state.doc.station) || {};
    try {
      navigator.mediaSession.metadata = new MediaMetadata({
        title: seg.title || kindLabel(seg.kind),
        artist: `${st.name || 'Exposure Radio'} · ${seg.priority ? 'PRIORITY ' : ''}${kindLabel(seg.kind)}`,
        album: st.edition ? `${st.edition} edition` : 'Exposure Radio',
        artwork: [{ src: new URL('icon.svg', location.href).href, sizes: '512x512', type: 'image/svg+xml' }]
      });
    } catch (_) { /* older browsers */ }
  }
  if ('mediaSession' in navigator) {
    const ms = navigator.mediaSession;
    const handlers = {
      play: () => { if (!state.started || isYouTube(current())) toggle(); else play(); },
      pause: () => { if (isYouTube(current())) { if (state.playing) toggle(); } else audio.pause(); },
      nexttrack: () => next(false),
      previoustrack: () => back()
    };
    for (const [k, fn] of Object.entries(handlers)) { try { ms.setActionHandler(k, fn); } catch (_) {} }
  }

  /* ---------------- volume knob ---------------- */
  const knob = $('knob');
  const ticks = $('knob-ticks');
  const TICKS = 27;
  for (let i = 0; i < TICKS; i++) {
    const t = el('i');
    t.style.transform = `rotate(${-135 + i * (270 / (TICKS - 1))}deg)`;
    ticks.append(t);
  }
  function setVolume(v, persist = true) {
    state.volume = Math.round(Math.max(0, Math.min(100, v)));
    const deg = -135 + state.volume * 2.7;
    $('knob-cap').style.transform = `rotate(${deg}deg)`;
    [...ticks.children].forEach((t, i) => t.classList.toggle('on', i / (TICKS - 1) * 100 <= state.volume + 0.01 && state.volume > 0));
    knob.setAttribute('aria-valuenow', String(state.volume));
    knob.setAttribute('aria-valuetext', state.muted ? `${state.volume} percent, muted` : `${state.volume} percent`);
    $('vol-text').textContent = `${state.volume}%`;
    applyVolume();
    if (persist) { try { localStorage.setItem(VOLUME_KEY, String(state.volume)); } catch (_) {} }
  }
  function setMuted(m) {
    state.muted = m;
    $('mute').setAttribute('aria-pressed', String(m));
    $('mute').setAttribute('aria-label', m ? `Unmute, volume ${state.volume} percent` : `Mute, volume ${state.volume} percent`);
    knob.classList.toggle('is-muted', m);
    setVolume(state.volume, false);
  }
  function angleToVolume(e) {
    const r = knob.getBoundingClientRect();
    const dx = e.clientX - (r.left + r.width / 2), dy = e.clientY - (r.top + r.height / 2);
    let deg = Math.atan2(dx, -dy) * 180 / Math.PI;
    deg = Math.max(-135, Math.min(135, deg));
    return (deg + 135) / 2.7;
  }
  let dragging = false;
  knob.addEventListener('pointerdown', e => {
    dragging = true; knob.setPointerCapture(e.pointerId); knob.focus({ preventScroll: true });
    if (state.muted) setMuted(false);
    setVolume(angleToVolume(e));
    e.preventDefault();
  });
  knob.addEventListener('pointermove', e => { if (dragging) setVolume(angleToVolume(e)); });
  const endDrag = () => { dragging = false; };
  knob.addEventListener('pointerup', endDrag);
  knob.addEventListener('pointercancel', endDrag);
  knob.addEventListener('wheel', e => { e.preventDefault(); if (state.muted) setMuted(false); setVolume(state.volume + (e.deltaY < 0 ? 2 : -2)); }, { passive: false });
  knob.addEventListener('keydown', e => {
    const step = { ArrowUp: 5, ArrowRight: 5, ArrowDown: -5, ArrowLeft: -5, PageUp: 10, PageDown: -10 }[e.key];
    if (step != null) setVolume(state.volume + step);
    else if (e.key === 'Home') setVolume(0);
    else if (e.key === 'End') setVolume(100);
    else return;
    if (state.muted) setMuted(false);
    e.preventDefault();
  });
  $('mute').addEventListener('click', () => setMuted(!state.muted));

  /* ---------------- drawer ---------------- */
  const drawer = $('drawer');
  function block(title) {
    const s = el('section', 'block');
    s.append(el('h3', 'label', title));
    return s;
  }
  function cardText(seg) {
    const c = seg.card || {};
    const st = (state.doc && state.doc.station) || {};
    const lines = [
      `${(st.name || 'Exposure Radio').toUpperCase()} · ACTION CARD`,
      `${st.edition || ''}${st.as_of ? ` · As of ${st.as_of}` : ''}`.replace(/^ · /, ''),
      '',
      `${c.cve || seg.title}${c.name ? ` · ${c.name}` : ''}`
    ];
    if (c.severity) lines.push(`Severity: ${c.severity}`);
    if (c.open_assets != null) lines.push(`Open assets: ${c.open_assets}`);
    if (c.why_now && c.why_now.length) lines.push(`Why now: ${c.why_now.join('; ')}`);
    if (c.internal_deadline) lines.push(`Internal deadline: ${c.internal_deadline}`);
    if (c.owners) lines.push(`Owner: ${c.owners.length ? c.owners.join(', ') : 'unassigned'}`);
    if (c.next_steps && c.next_steps.length) { lines.push('Next steps:'); c.next_steps.forEach(s => lines.push(`  - ${s}`)); }
    if (c.evidence && c.evidence.length) lines.push(`Evidence: ${c.evidence.join(', ')}`);
    const watch = Array.isArray(seg.watch) ? seg.watch.filter(Boolean) : [];
    if (watch.length) {
      lines.push('', 'Also on the watch list:');
      watch.forEach(w => lines.push(`  - ${w.cve || w.id || ''}${w.name ? ` · ${w.name}` : ''}${w.open_assets != null ? ` · ${w.open_assets} open` : ''}${w.internal_deadline ? ` · due ${w.internal_deadline}` : ''}`));
      lines.push('');
    }
    (seg.sources || []).forEach(s => lines.push(`Source: ${s.label}${s.url ? ` ${s.url}` : ''}`));
    return lines.join('\n') + '\n';
  }
  async function copyText(text) {
    try { await navigator.clipboard.writeText(text); return true; } catch (_) { /* fall through */ }
    const ta = el('textarea');
    ta.value = text; ta.setAttribute('readonly', ''); ta.className = 'visually-hidden';
    drawer.append(ta); ta.select();
    let ok = false;
    try { ok = document.execCommand('copy'); } catch (_) { ok = false; }
    ta.remove();
    return ok;
  }
  function openDrawer() {
    const seg = current();
    if (!seg) return;
    const body = $('drawer-body');
    body.replaceChildren();
    $('drawer-kind').textContent = kindLabel(seg.kind);
    $('drawer-priority').hidden = !seg.priority;
    drawer.classList.toggle('is-priority', !!seg.priority);
    const c = seg.card;
    $('drawer-title').textContent = c ? 'Action card' : (seg.title || 'Segment');
    if (c) {
      const head = el('section');
      head.append(el('p', 'card-id', c.cve || seg.title || ''));
      if (c.name) head.append(el('p', 'card-name', c.name));
      body.append(head);
      const dl = el('dl', 'facts');
      const fact = (k, v, big) => { const d = el('div'); d.append(el('dt', null, k), el('dd', big ? 'big' : null, v)); dl.append(d); };
      fact('Open assets', c.open_assets != null ? String(c.open_assets) : '—', true);
      fact('Severity', c.severity ? String(c.severity).toUpperCase() : '—');
      fact('Internal deadline', c.internal_deadline || '—');
      fact('Owner', c.owners && c.owners.length ? c.owners.join(', ') : 'Unassigned');
      body.append(dl);
      if (c.why_now && c.why_now.length) {
        const b = block('Why now'); const ul = el('ul');
        c.why_now.forEach(w => ul.append(el('li', null, w)));
        if (c.kev && c.kev.catalog_due_date) ul.append(el('li', null, `CISA KEV catalog due date ${c.kev.catalog_due_date}${c.kev.known_ransomware_use ? ' · known ransomware use' : ''}`));
        b.append(ul); body.append(b);
      }
      if (c.next_steps && c.next_steps.length) {
        const b = block('Next steps'); const ol = el('ol');
        c.next_steps.forEach(s => ol.append(el('li', null, s)));
        b.append(ol); body.append(b);
      }
      if (c.evidence && c.evidence.length) {
        const b = block(`Evidence · ${c.evidence.length} ledger entries`); const ids = el('div', 'ids');
        c.evidence.forEach(id => ids.append(el('span', null, id)));
        b.append(ids); body.append(b);
      }
    }
    const watch = Array.isArray(seg.watch) ? seg.watch.filter(Boolean) : [];
    if (watch.length) {
      const b = block(`Also on the watch list · ${watch.length}`); const ul = el('ul', 'watch');
      watch.forEach(w => {
        const li = el('li');
        const top = el('p', 'watch-top');
        top.append(el('span', 'watch-id', w.cve || w.id || ''), document.createTextNode(w.name ? ` ${w.name}` : ''));
        li.append(top);
        const meta = [];
        if (w.severity) meta.push(String(w.severity).toUpperCase());
        if (w.open_assets != null) meta.push(`${w.open_assets} open asset${w.open_assets === 1 ? '' : 's'}`);
        if (w.why_now && w.why_now.length) meta.push(w.why_now.join('; '));
        if (w.internal_deadline) meta.push(`due ${w.internal_deadline}`);
        if (meta.length) li.append(el('p', 'watch-meta', meta.join(' · ')));
        ul.append(li);
      });
      b.append(ul); body.append(b);
    }
    if (seg.sources && seg.sources.length) {
      const b = block('Sources'); const ul = el('ul', 'sources');
      seg.sources.forEach(s => {
        const li = el('li');
        if (s.url && /^https?:\/\//i.test(s.url)) {
          const a = el('a', null, `${s.label || s.url} ↗`); a.href = s.url; a.rel = 'noopener noreferrer'; a.target = '_blank'; li.append(a);
        } else li.append(document.createTextNode(s.label || ''));
        ul.append(li);
      });
      b.append(ul); body.append(b);
    }
    if (Array.isArray(seg.turns) && seg.turns.length) {
      const b = block('What was said'); const ol = el('ol', 'transcript');
      seg.turns.forEach(t => {
        const li = el('li');
        const h = state.hosts[t.host];
        li.append(el('span', 'who', h ? h.name : t.host));
        const p = el('p', null, t.caption || t.text || '');
        if (t.cites && t.cites.length) p.append(el('span', 'cites', `Evidence ${t.cites.join(', ')}`));
        li.append(p); ol.append(li);
      });
      b.append(ol); body.append(b);
    }
    const row = el('div', 'copy-row');
    if (c) {
      const copy = el('button', 'btn btn-primary', 'Copy card');
      copy.type = 'button';
      const status = el('span', 'copy-status');
      status.setAttribute('role', 'status');
      copy.addEventListener('click', async () => {
        status.textContent = (await copyText(cardText(seg))) ? 'Card copied as plain text.' : 'Copy is unavailable in this browser.';
      });
      row.append(copy, status);
    }
    if (seg.captions) {
      const a = el('a', 'btn btn-small', 'Captions (.vtt)'); a.href = seg.captions; a.setAttribute('download', '');
      row.append(a);
    }
    const ev = el('a', 'btn btn-small', 'Evidence & claim gate'); ev.href = 'briefing.html';
    row.append(ev);
    body.append(row);
    if (typeof drawer.showModal === 'function') drawer.showModal(); else drawer.setAttribute('open', '');
    $('drawer-close').focus();
  }
  $('details').addEventListener('click', openDrawer);
  $('drawer-close').addEventListener('click', () => drawer.close());
  drawer.addEventListener('click', e => { if (e.target === drawer) drawer.close(); });

  /* ---------------- visualizer ---------------- */
  const viz = (() => {
    const canvas = $('viz');
    const ctx2d = canvas.getContext('2d');
    let g = null, w = 0, h = 0, dpr = 1, raf = 0, last = 0, priority = false;
    const COLS = 32, ROWS = 12;
    const levels = new Float32Array(COLS), raw = new Float32Array(COLS);
    function size() {
      const r = canvas.getBoundingClientRect();
      dpr = Math.min(window.devicePixelRatio || 1, 2);
      w = Math.max(1, Math.round(r.width * dpr)); h = Math.max(1, Math.round(r.height * dpr));
      if (canvas.width !== w || canvas.height !== h) { canvas.width = w; canvas.height = h; }
      frame(performance.now(), true);
    }
    function sample(t) {
      const live = g && state.playing;
      let energy = 0;
      if (live) {
        g.analyser.getByteFrequencyData(g.freq);
        const bins = g.freq.length * 0.7;
        for (let c = 0; c < COLS; c++) {
          const a = Math.floor(Math.pow(c / COLS, 1.6) * bins), b = Math.max(a + 1, Math.floor(Math.pow((c + 1) / COLS, 1.6) * bins));
          let s = 0; for (let i = a; i < b; i++) s += g.freq[i];
          raw[c] = s / (b - a) / 255; energy += raw[c];
        }
        if (energy / COLS >= 0.02) for (let c = 0; c < COLS; c++) levels[c] = levels[c] * 0.6 + raw[c] * 0.4;
      }
      // carrier: a calm idle pattern, also blended in under quiet/silent audio
      const idle = state.playing ? 0.2 : 0.13;
      if (!live || energy / COLS < 0.02) {
        for (let c = 0; c < COLS; c++) {
          const x = c / (COLS - 1);
          const hill = 0.45 + 1.1 * Math.exp(-((x - 0.28) ** 2) / 0.05) + 0.5 * Math.exp(-((x - 0.7) ** 2) / 0.03);
          const v = idle * hill * (0.7 + 0.3 * Math.sin(t / 1300 + c * 0.45) * Math.sin(t / 2700 + c * 0.13));
          levels[c] = levels[c] * 0.9 + Math.max(0.02, v) * 0.1;
        }
      }
    }
    function frame(t, force) {
      if (!force && t - last < 33) return;
      if (canvas.parentNode.classList.contains('is-youtube')) return;
      last = t;
      sample(t);
      const W = w, H = h;
      ctx2d.clearRect(0, 0, W, H);
      const padX = 22 * dpr, padTop = 52 * dpr, padBot = 80 * dpr;
      const gw = W - padX * 2, gh = H - padTop - padBot;
      const gap = Math.max(2, 3 * dpr);
      const cw = (gw - gap * (COLS - 1)) / COLS, ch = (gh - gap * (ROWS - 1)) / ROWS;
      const hot = priority ? [240, 103, 92] : [71, 196, 176];
      const peak = priority ? [255, 170, 150] : [142, 236, 201];
      const live = g && state.playing && levels.some(v => v > 0.22);
      const sweep = reducedMotion.matches ? -99 : ((t / 160) % (COLS + 16)) - 8;
      for (let c = 0; c < COLS; c++) {
        const L = Math.min(1, levels[c] * 1.2) * ROWS;
        const scan = Math.exp(-((c - sweep) ** 2) / 5) * 0.07;
        for (let r = 0; r < ROWS; r++) {
          const x = padX + c * (cw + gap), y = padTop + gh - (r + 1) * ch - r * gap;
          const f = Math.max(0, Math.min(1, L - r));
          let fill;
          if (live && f > 0.5 && r === Math.ceil(L) - 1 && L > 2) fill = `rgba(${peak[0]},${peak[1]},${peak[2]},0.9)`;
          else {
            const a = 0.04 + scan * (1 - r / ROWS) + f * (0.22 + 0.5 * (r / ROWS));
            fill = `rgba(${hot[0]},${hot[1]},${hot[2]},${a.toFixed(3)})`;
          }
          ctx2d.fillStyle = fill;
          ctx2d.fillRect(x, y, cw, ch);
        }
      }
      // waveform trace along the baseline
      const base = padTop + gh + 20 * dpr;
      ctx2d.strokeStyle = priority ? 'rgba(240,103,92,0.55)' : 'rgba(142,236,201,0.45)';
      ctx2d.lineWidth = Math.max(1, 1.25 * dpr);
      ctx2d.beginPath();
      if (g && state.playing) {
        g.analyser.getByteTimeDomainData(g.wave);
        const n = g.wave.length;
        for (let i = 0; i < n; i += 2) {
          const x = padX + gw * i / (n - 1);
          const v = (g.wave[i] - 128) / 128;
          const y = base + v * 12 * dpr + Math.sin(t / 500 + i / 30) * 1.2 * dpr;
          if (i === 0) ctx2d.moveTo(x, y); else ctx2d.lineTo(x, y);
        }
      } else {
        for (let i = 0; i <= 120; i++) {
          const x = padX + gw * i / 120;
          const y = base + Math.sin(t / 900 + i / 7) * 2.2 * dpr;
          if (i === 0) ctx2d.moveTo(x, y); else ctx2d.lineTo(x, y);
        }
      }
      ctx2d.stroke();
    }
    function loop(t) {
      raf = 0;
      frame(t, false);
      if (!reducedMotion.matches && !document.hidden) raf = requestAnimationFrame(loop);
    }
    function start() { if (!raf && !reducedMotion.matches) raf = requestAnimationFrame(loop); else frame(performance.now(), true); }
    if (window.ResizeObserver) new ResizeObserver(size).observe(canvas); else window.addEventListener('resize', size);
    document.addEventListener('visibilitychange', () => { if (!document.hidden) start(); });
    reducedMotion.addEventListener && reducedMotion.addEventListener('change', start);
    size(); start();
    return {
      attach(graph) { g = graph; },
      mode(p) { priority = p; if (reducedMotion.matches) frame(performance.now(), true); }
    };
  })();

  /* ---------------- boot ---------------- */
  $('tune').addEventListener('click', toggle);
  $('skip').addEventListener('click', () => { state.started = true; next(false); });
  $('back').addEventListener('click', () => { state.started = true; back(); });
  window.addEventListener('storage', e => { if (e.key === DEMO_KEY) refreshDoc(); });

  let savedVol = 80;
  try { const v = Number(localStorage.getItem(VOLUME_KEY)); if (localStorage.getItem(VOLUME_KEY) !== null && Number.isFinite(v)) savedVol = v; } catch (_) {}
  setVolume(savedVol, false);
  setMuted(false);

  fetchDoc().then(doc => {
    applyDoc(doc);
    if (!state.rundown.length) {
      setStatus('The rundown is empty. Add segments on the station host.');
      $('tune').disabled = true;
      return;
    }
    updateNow(true);
    setStatus(`Station ready · ${state.rundown.length} segments in this hour. Press Tune In.`);
  }).catch(() => {
    setAir('off', 'OFF AIR');
    $('now-title').textContent = 'Station feed unavailable';
    $('now-sub').textContent = 'station/station.json could not be loaded.';
    setCaption('Serve this folder over HTTP from the station host, then reload.', true);
    setStatus('The station document could not be loaded.');
    $('tune').disabled = true;
    ['skip', 'back'].forEach(id => { $(id).disabled = true; });
  });
})();
