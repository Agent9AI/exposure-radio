'use strict';
/* Exposure Radio station console. Talks to the station host API (docs/STATION.md);
   falls back to a demo on the bundled station.json with edits kept in localStorage.
   Secrets are never read back, rendered, or stored in the browser. */
(() => {
  const DEMO_KEY = 'exposure-radio.demo.v1';
  const NOW_KEY = 'exposure-radio.nowplaying';
  const TOKEN_KEY = 'exposure-radio.admin-token';
  const KIND = {
    ident: 'STATION', exposure: 'EXPOSURE', learn: 'LEARN', weather: 'WEATHER',
    news: 'NEWS', music: 'MUSIC', wins: 'WINS', blindspots: 'BLIND SPOTS'
  };
  const SEGMENTS = [
    ['exposure', 'Exposure', 'Changed findings from Tenable, checked against the evidence ledger.', 2],
    ['wins', 'Wins', 'What the team fixed since the last report.', 1],
    ['blindspots', 'Blind spots', 'Assets that have not been scanned recently.', 1],
    ['learn', 'Learn', 'Short explainers on the topics you queue.', 1],
    ['weather', 'Weather & local', 'Forecast and local notes for the station address.', 1],
    ['news', 'News', 'Security news from public advisories.', 1],
    ['music', 'Music', 'Breaks between segments.', 3]
  ];
  const SUGGESTIONS = [
    'Why KEV listings change your patch order',
    'Passkeys for a small IT team',
    'Reading a vendor advisory in five minutes'
  ];
  /* Field paths are into the settings document (PUT /api/settings). Secret fields are
     never part of it: they go to POST /api/keys and come back only as {configured}. */
  const CONNECTIONS = [
    { id: 'tenable', title: 'Tenable Vulnerability Management', blurb: 'Pulls exposure exports for the briefings.',
      fields: [{ secret: 'tenable', key: 'access_key', label: 'Access key' }, { secret: 'tenable', key: 'secret_key', label: 'Secret key' }],
      hint: 'Pull export now: on the station host, run', code: 'python3 -m exposure_radio station pull' },
    { id: 'gemini', title: 'Google Gemini', blurb: 'Trending Learn topics and cloud voices. Bring your own key.',
      fields: [
        { path: 'gemini.tier', label: 'Tier', type: 'select', options: [['free', 'Free tier'], ['paid', 'Paid project']] },
        { path: 'voices.cloud_seconds_per_day', label: 'Cloud voice seconds per day', type: 'number', min: 0, max: 86400, step: 60 },
        { secret: 'gemini', key: 'api_key', label: 'API key' }],
      note: 'Free-tier content may be used by Google to improve its products, so exposure segments stay on local voices unless this is a paid project.' },
    { id: 'youtube', title: 'YouTube', blurb: 'Your own videos in the official embedded player. The video stays visible while it plays.',
      fields: [], hint: 'Add a video from On air › Add a YouTube item. Nothing is downloaded or played in the background.' },
    { id: 'nws', title: 'National Weather Service', blurb: 'Public forecast API. No key needed.',
      fields: [{ path: 'station.address', label: 'Station address', type: 'text', placeholder: 'Street, city or ZIP' }] },
    { id: 'lyria', title: 'Lyria music', blurb: 'Optional generated instrumentals. Paid per song.',
      fields: [{ path: 'lyria.enabled', label: 'Generate music with Lyria', type: 'toggle' }],
      note: 'Uses your Gemini key. Billed per song by Google with no free tier, so it stays off unless you turn it on.' }
  ];
  const getPath = (o, path) => path.split('.').reduce((v, k) => (v == null ? undefined : v[k]), o);
  const setPath = (o, path, value) => {
    const keys = path.split('.'); let cur = o;
    keys.slice(0, -1).forEach(k => { if (!cur[k] || typeof cur[k] !== 'object') cur[k] = {}; cur = cur[k]; });
    cur[keys[keys.length - 1]] = value;
    return o;
  };

  const $ = id => document.getElementById(id);
  const el = (tag, cls, text) => {
    const n = document.createElement(tag);
    if (cls) n.className = cls;
    if (text != null) n.textContent = text;
    return n;
  };
  const kindLabel = k => KIND[k] || String(k || '').toUpperCase();
  const clock = s => { s = Number(s) || 0; return `${String(Math.floor(s / 60)).padStart(2, '0')}:${String(Math.floor(s % 60)).padStart(2, '0')}`; };
  const clone = o => JSON.parse(JSON.stringify(o));

  const app = { mode: 'connecting', doc: null, settings: null, rundown: [], topics: [], providers: {} };

  /* ---------------- storage ---------------- */
  function readDemo() { try { return JSON.parse(localStorage.getItem(DEMO_KEY) || '{}') || {}; } catch (_) { return {}; } }
  function writeDemo(patch) {
    const d = Object.assign(readDemo(), patch);
    try { localStorage.setItem(DEMO_KEY, JSON.stringify(d)); return true; } catch (_) { return false; }
  }
  function nowPlaying() {
    try {
      const n = JSON.parse(localStorage.getItem(NOW_KEY) || 'null');
      return n && Date.now() - n.ts < 45000 ? n : null;
    } catch (_) { return null; }
  }

  /* ---------------- host API ---------------- */
  async function getJSON(url) {
    const r = await fetch(url, { cache: 'no-store', credentials: 'same-origin', headers: { Accept: 'application/json' } });
    if (!r.ok) throw new Error(`${url} ${r.status}`);
    const type = r.headers.get('content-type') || '';
    if (!type.includes('json')) throw new Error(`${url} is not JSON`);
    return r.json();
  }
  function askToken() {
    return new Promise(resolve => {
      const dlg = $('token-dialog'), input = $('token-input');
      input.value = '';
      const done = ok => {
        $('token-form').removeEventListener('submit', onSubmit);
        dlg.close();
        const v = ok ? input.value.trim() : '';
        input.value = '';
        resolve(v || null);
      };
      const onSubmit = e => { e.preventDefault(); done(!!(e.submitter && e.submitter.value === 'ok')); };
      $('token-form').addEventListener('submit', onSubmit);
      dlg.addEventListener('cancel', () => done(false), { once: true });
      dlg.showModal();
      input.focus();
    });
  }
  async function write(method, url, body, retry = true) {
    let token = sessionStorage.getItem(TOKEN_KEY);
    if (!token) {
      token = await askToken();
      if (!token) throw new Error('An admin token is required to change the station.');
      sessionStorage.setItem(TOKEN_KEY, token);
    }
    const r = await fetch(url, {
      method, credentials: 'same-origin', cache: 'no-store',
      headers: { 'Content-Type': 'application/json', 'X-Admin-Token': token },
      body: JSON.stringify(body)
    });
    if ((r.status === 401 || r.status === 403) && retry) {
      sessionStorage.removeItem(TOKEN_KEY);
      return write(method, url, body, false);
    }
    const text = await r.text();
    if (!r.ok) {
      let msg = '';
      try { const j = JSON.parse(text); if (j && typeof j.error === 'string') msg = j.error; } catch (_) {}
      throw new Error(r.status === 401 || r.status === 403 ? 'The admin token was not accepted.' : (msg ? `The station host said: ${msg}` : `The station host answered ${r.status}.`));
    }
    try { return text ? JSON.parse(text) : {}; } catch (_) { return {}; }
  }

  /* ---------------- settings model ---------------- */
  function defaultSettings(doc) {
    const st = (doc && doc.station) || {};
    return {
      station: { name: st.name || 'Exposure Radio', address: (st.location && st.location.label) || '' },
      hosts: clone((doc && doc.hosts) || []),
      segments: Object.fromEntries(SEGMENTS.map(([k, , , n]) => [k, { enabled: true, per_hour: n }])),
      quiet_hours: { start: '22:00', end: '07:00' },
      priority_interrupts: true,
      gemini: { tier: 'free' },
      voices: { cloud_seconds_per_day: 900 },
      lyria: { enabled: false },
      keys: { tenable: { configured: false }, gemini: { configured: false } }
    };
  }
  function merge(base, over) {
    if (!over || typeof over !== 'object' || Array.isArray(over)) return over === undefined ? base : over;
    const out = Array.isArray(base) ? [] : Object.assign({}, base);
    for (const [k, v] of Object.entries(over)) out[k] = (base && typeof base[k] === 'object' && !Array.isArray(base[k])) ? merge(base[k], v) : v;
    return out;
  }
  /* The browser only ever keeps {configured: bool} for keys, whatever it was handed. */
  function scrub(settings) {
    const s = clone(settings);
    const keys = {};
    for (const [prov, v] of Object.entries(s.keys || {})) keys[prov] = { configured: !!(v && v.configured === true) };
    s.keys = keys;
    return s;
  }

  /* ---------------- boot ---------------- */
  async function boot() {
    let doc = null, settings = null;
    try {
      doc = await getJSON('/api/station');
      settings = await getJSON('/api/settings');
      app.mode = 'host';
    } catch (_) {
      app.mode = 'demo';
    }
    if (app.mode === 'demo') {
      try { doc = await getJSON('station/station.json'); } catch (_) {
        $('load-error').textContent = 'Neither the station host nor station/station.json could be loaded. Serve this folder over HTTP and reload.';
        $('load-error').hidden = false;
        setMode('off', 'OFFLINE');
        return;
      }
      const demo = readDemo();
      settings = merge(defaultSettings(doc), demo.settings ? scrub(demo.settings) : {});
    } else {
      settings = scrub(merge(defaultSettings(doc), settings));
    }
    app.doc = doc;
    app.settings = settings;
    app.providers = Object.fromEntries((doc.providers || []).map(p => [p.id, p]));
    setMode(app.mode === 'host' ? 'live' : 'warn', app.mode === 'host' ? 'HOST CONNECTED' : 'DEMO MODE');
    $('demo-banner').hidden = app.mode !== 'demo';
    $('secret-note').hidden = app.mode !== 'demo';
    $('queue-reset').hidden = app.mode !== 'demo';
    renderAll();
  }
  function setMode(kind, text) {
    $('mode-pill').className = `pill pill-${kind}`;
    $('mode-text').textContent = text;
  }
  function renderAll() {
    const st = app.doc.station || {};
    $('console-station').textContent = [app.settings.station.name || st.name || 'Exposure Radio', st.edition].filter(Boolean).join(' · ');
    $('foot-asof').textContent = st.as_of ? `DATA AS OF ${String(st.as_of).replace('T', ' ')}` : '';
    buildRundown();
    renderOnAir();
    renderSegments();
    renderLearn();
    renderConnections();
    renderSettings();
  }

  /* ---------------- On air ---------------- */
  function buildRundown() {
    let list = (app.doc.rundown || []).filter(s => s && s.id);
    if (app.mode === 'demo') {
      const q = readDemo().queue;
      if (q && Array.isArray(q.extra)) list = list.concat(q.extra.filter(x => x && x.id && !list.some(s => s.id === x.id)));
      if (q && Array.isArray(q.order)) {
        const byId = new Map(list.map(s => [s.id, s]));
        const removed = new Set(q.removed || []);
        list = q.order.map(id => byId.get(id)).filter(Boolean)
          .concat(list.filter(s => !q.order.includes(s.id) && !removed.has(s.id)));
      }
    }
    app.rundown = list;
  }
  function renderOnAir() {
    const np = nowPlaying();
    const cur = np && app.rundown.find(s => s.id === np.id);
    const seg = cur || app.rundown[0];
    $('now-label').textContent = cur ? (np.playing ? 'ON AIR NOW' : 'PAUSED ON') : 'TOP OF THE RUNDOWN';
    $('now-where').textContent = cur ? 'LISTENER IN THIS BROWSER' : `${app.rundown.length} QUEUED`;
    if (seg) {
      $('now-kind').textContent = kindLabel(seg.kind);
      $('now-pri').hidden = !seg.priority;
      $('now-title').textContent = seg.title || 'Untitled';
      $('now-sub').textContent = [seg.subtitle, seg.duration ? clock(seg.duration) : ''].filter(Boolean).join(' · ');
    } else {
      $('now-title').textContent = 'The queue is empty';
      $('now-sub').textContent = '';
    }
    const q = $('queue');
    q.replaceChildren();
    app.rundown.forEach((s, i) => {
      const li = el('li', `q-row${s.priority ? ' is-priority' : ''}${cur && s.id === cur.id ? ' is-now' : ''}`);
      li.append(el('span', 'q-num mono', String(i + 1).padStart(2, '0')));
      const tag = el('span', s.priority ? 'tag tag-priority' : (s.kind === 'music' || s.kind === 'ident' ? 'tag tag-quiet' : 'tag'), s.priority ? 'PRIORITY' : kindLabel(s.kind));
      const kind = el('span', 'q-kind'); kind.append(tag); li.append(kind);
      const text = el('span', 'q-text');
      text.append(el('span', 'q-title', s.title || 'Untitled'));
      if (s.subtitle) text.append(el('span', 'q-sub', s.subtitle));
      li.append(text);
      const act = el('span', 'q-actions');
      const name = s.title || s.id;
      act.append(
        iconButton('Play next', `Play ${name} next`, () => queueAction('play_next', s.id), 'play-next'),
        iconButton('↑', `Move ${name} up`, () => queueAction('move', s.id, i - 1), 'up', i === 0),
        iconButton('↓', `Move ${name} down`, () => queueAction('move', s.id, i + 1), 'down', i === app.rundown.length - 1),
        iconButton('✕', `Remove ${name} from the queue`, () => queueAction('remove', s.id), 'remove', app.rundown.length <= 1)
      );
      li.append(act);
      q.append(li);
    });
    const total = app.rundown.reduce((a, s) => a + (Number(s.duration) || 0), 0);
    $('queue-meta').textContent = `${app.rundown.length} SEGMENTS · ${clock(total)}`;
  }
  function iconButton(text, label, fn, kind, disabled) {
    const b = el('button', `btn btn-small q-btn q-${kind}`, text);
    b.type = 'button';
    b.setAttribute('aria-label', label);
    b.title = label;
    b.disabled = !!disabled;
    b.addEventListener('click', fn);
    return b;
  }
  async function queueAction(action, id, to) {
    const status = $('onair-status');
    const seg = app.rundown.find(s => s.id === id);
    const name = (seg && seg.title) || id;
    const focusKey = `${action}:${id}`;
    try {
      if (app.mode === 'host') {
        const body = { action, id };
        if (action === 'move') body.to = to;
        await write('POST', '/api/queue', body);
        app.doc = await getJSON('/api/station');
      } else {
        const order = app.rundown.map(s => s.id);
        const removed = new Set((readDemo().queue || {}).removed || []);
        const from = order.indexOf(id);
        if (from < 0) return;
        order.splice(from, 1);
        if (action === 'remove') removed.add(id);
        else if (action === 'move') order.splice(Math.max(0, Math.min(order.length, to)), 0, id);
        else if (action === 'play_next') {
          const np = nowPlaying();
          const at = np ? order.indexOf(np.id) : -1;
          order.splice(at + 1, 0, id);
        }
        writeDemo({ queue: { order, removed: [...removed], extra: (readDemo().queue || {}).extra || [] } });
      }
      buildRundown();
      renderOnAir();
      status.textContent = action === 'remove' ? `Removed “${name}”.` : action === 'move' ? `Moved “${name}” to position ${to + 1}.` : `“${name}” plays next.`;
      restoreFocus(focusKey, id);
    } catch (err) {
      status.textContent = err.message || 'That change did not go through.';
    }
  }
  function restoreFocus(key, id) {
    const [action] = key.split(':');
    const rows = [...$('queue').children];
    if (!rows.length) return;
    const idx = app.rundown.findIndex(s => s.id === id);
    const row = rows[idx >= 0 ? idx : Math.min(rows.length - 1, Math.max(0, lastIndex))];
    const want = { move: lastClass, play_next: 'q-play-next' }[action];
    const target = (want && row.querySelector(`.${want}:not(:disabled)`)) || row.querySelector('button:not(:disabled)');
    if (target) target.focus();
  }
  let lastIndex = 0, lastClass = 'q-up';
  $('queue').addEventListener('click', e => {
    const b = e.target.closest('button');
    if (!b) return;
    lastIndex = [...$('queue').children].indexOf(b.closest('li'));
    lastClass = b.classList.contains('q-down') ? 'q-down' : 'q-up';
  }, true);
  /* A YouTube item: accepted as an 11-character video ID or a youtube.com / youtu.be link. */
  function videoIdFrom(text) {
    const t = text.trim();
    if (/^[A-Za-z0-9_-]{11}$/.test(t)) return t;
    try {
      const u = new URL(t);
      const host = u.hostname.replace(/^www\.|^m\./, '');
      let id = null;
      if (host === 'youtu.be') id = u.pathname.slice(1);
      else if (host === 'youtube.com' || host === 'youtube-nocookie.com') id = u.searchParams.get('v') || (u.pathname.match(/^\/(?:embed|shorts|live)\/([^/?#]+)/) || [])[1];
      return id && /^[A-Za-z0-9_-]{11}$/.test(id) ? id : null;
    } catch (_) { return null; }
  }
  $('yt-form').addEventListener('submit', async e => {
    e.preventDefault();
    const status = $('onair-status');
    const videoId = videoIdFrom($('yt-id').value);
    if (!videoId) { status.textContent = 'That is not a YouTube video ID. It is 11 letters, digits, - or _.'; $('yt-id').focus(); return; }
    const title = $('yt-title').value.trim().replace(/\s+/g, ' ') || 'YouTube video';
    try {
      if (app.mode === 'host') {
        await write('POST', '/api/queue', { action: 'add_youtube', videoId, title });
        app.doc = await getJSON('/api/station');
      } else {
        const q = readDemo().queue || {};
        const order = app.rundown.map(s => s.id);
        const id = `yt-${videoId}`;
        const extra = (q.extra || []).filter(x => x.id !== id);
        extra.push({ id, kind: 'music', title, subtitle: 'YouTube', youtube: { videoId, title }, duration: null, priority: false, turns: [],
          sources: [{ label: 'YouTube', url: `https://www.youtube.com/watch?v=${videoId}` }], card: null, track: null });
        writeDemo({ queue: { order: order.filter(x => x !== id).concat(id), removed: (q.removed || []).filter(x => x !== id), extra } });
      }
      buildRundown(); renderOnAir();
      $('yt-id').value = ''; $('yt-title').value = '';
      status.textContent = `Added “${title}” to the end of the queue. Use Play next to hear it sooner.`;
    } catch (err) { status.textContent = err.message || 'The video was not added.'; }
  });
  $('cue').addEventListener('click', () => {
    const lead = app.rundown.find(s => s.kind === 'exposure' && s.priority) || app.rundown.find(s => s.kind === 'exposure');
    if (!lead) { $('onair-status').textContent = 'There is no exposure briefing in the queue to cue.'; return; }
    queueAction('play_next', lead.id);
  });
  $('queue-reset').addEventListener('click', () => {
    writeDemo({ queue: null });
    buildRundown(); renderOnAir();
    $('onair-status').textContent = 'The original rundown is back.';
  });
  window.addEventListener('storage', e => {
    if (!app.doc) return;
    if (e.key === NOW_KEY || e.key === DEMO_KEY) { buildRundown(); renderOnAir(); }
  });
  setInterval(() => { if (app.doc && !document.hidden) renderOnAirHeader(); }, 15000);
  function renderOnAirHeader() {
    const active = document.activeElement;
    if (active && $('queue').contains(active)) return;
    renderOnAir();
  }

  /* ---------------- Segments ---------------- */
  function switchButton(on, labelId) {
    const b = el('button', 'switch');
    b.type = 'button';
    b.setAttribute('role', 'switch');
    b.setAttribute('aria-checked', String(!!on));
    if (labelId) b.setAttribute('aria-labelledby', labelId);
    b.append(el('span'));
    b.addEventListener('click', () => b.setAttribute('aria-checked', String(b.getAttribute('aria-checked') !== 'true')));
    return b;
  }
  function renderSegments() {
    const list = $('seg-list');
    list.replaceChildren();
    const segs = app.settings.segments || {};
    for (const [k, title, sub] of SEGMENTS) {
      const cfg = segs[k] || { enabled: true, per_hour: 1 };
      const li = el('li', 'row');
      li.dataset.kind = k;
      const text = el('div', 'row-text');
      const t = el('span', 'row-title', title); t.id = `seg-${k}-label`;
      text.append(t, el('span', 'row-sub', sub));
      const ctl = el('div', 'row-ctl');
      const step = el('div', 'stepper');
      const minus = el('button', 'step', '−'); minus.type = 'button'; minus.setAttribute('aria-label', `Fewer ${title} segments per hour`);
      const input = el('input', 'step-input mono');
      input.type = 'number'; input.min = '0'; input.max = '12'; input.step = '1'; input.inputMode = 'numeric';
      input.value = String(Number.isFinite(cfg.per_hour) ? cfg.per_hour : 1);
      input.setAttribute('aria-label', `${title} segments per hour`);
      input.name = `per-hour-${k}`;
      const plus = el('button', 'step', '+'); plus.type = 'button'; plus.setAttribute('aria-label', `More ${title} segments per hour`);
      const bump = d => { input.value = String(Math.max(0, Math.min(12, (parseInt(input.value, 10) || 0) + d))); };
      minus.addEventListener('click', () => bump(-1));
      plus.addEventListener('click', () => bump(1));
      step.append(minus, input, plus);
      const sw = switchButton(cfg.enabled !== false, t.id);
      sw.classList.add('seg-switch');
      ctl.append(step, sw);
      li.append(text, ctl);
      list.append(li);
    }
    const qh = app.settings.quiet_hours || {};
    $('qh-start').value = qh.start || '22:00';
    $('qh-end').value = qh.end || '07:00';
    $('pi-on').setAttribute('aria-checked', String(app.settings.priority_interrupts !== false));
  }
  ['pi-on'].forEach(id => $(id).addEventListener('click', e => {
    const b = e.currentTarget; b.setAttribute('aria-checked', String(b.getAttribute('aria-checked') !== 'true'));
  }));
  function collectSegments() {
    const segments = {};
    document.querySelectorAll('#seg-list .row').forEach(li => {
      segments[li.dataset.kind] = {
        enabled: li.querySelector('.seg-switch').getAttribute('aria-checked') === 'true',
        per_hour: Math.max(0, Math.min(12, parseInt(li.querySelector('input').value, 10) || 0))
      };
    });
    return {
      segments,
      quiet_hours: { start: $('qh-start').value || '22:00', end: $('qh-end').value || '07:00' },
      priority_interrupts: $('pi-on').getAttribute('aria-checked') === 'true'
    };
  }
  async function saveSettings(patch, statusId, okText, secrets) {
    const status = $(statusId);
    const next = merge(app.settings, patch);
    try {
      if (app.mode === 'host') {
        const body = clone(next);
        delete body.keys;
        const saved = await write('PUT', '/api/settings', body);
        app.settings = scrub(merge(next, saved && typeof saved === 'object' && saved.station ? saved : {}));
        // Secrets travel separately and are never kept or shown here.
        for (const [provider, values] of Object.entries(secrets || {})) {
          await write('POST', '/api/keys', { provider, values });
          app.settings.keys[provider] = { configured: true };
        }
        status.textContent = `${okText} on the station host.`;
      } else {
        app.settings = scrub(next);
        status.textContent = writeDemo({ settings: app.settings }) ? `${okText} in this browser (demo).` : 'This browser would not save the change.';
      }
      renderAll();
      return true;
    } catch (err) {
      status.textContent = err.message || 'The change was not saved.';
      return false;
    }
  }
  $('seg-save').addEventListener('click', () => saveSettings(collectSegments(), 'seg-status', 'Segments saved'));

  /* ---------------- Learn ---------------- */
  function topics() {
    if (app.mode === 'demo') {
      const d = readDemo();
      if (d.learn && Array.isArray(d.learn.topics)) return d.learn.topics;
    }
    const list = clone((app.doc.learn && app.doc.learn.topics) || []);
    for (const t of app.suggested || []) if (!list.some(x => x.title.toLowerCase() === t.title.toLowerCase())) list.push(t);
    return list;
  }
  function saveTopics(list) { writeDemo({ learn: { topics: list } }); }
  function renderLearn() {
    const list = $('learn-list');
    list.replaceChildren();
    const all = topics();
    const counts = { aired: 0, queued: 0, suggested: 0 };
    all.forEach(t => { counts[t.status] = (counts[t.status] || 0) + 1; });
    $('learn-meta').textContent = `${counts.aired} AIRED · ${counts.queued} QUEUED · ${counts.suggested} SUGGESTED`;
    if (!all.length) {
      const li = el('li', 'row'); li.append(el('span', 'row-sub', 'No topics yet. Add one above.')); list.append(li);
    }
    all.forEach(t => {
      const li = el('li', 'row');
      const text = el('div', 'row-text');
      text.append(el('span', 'row-title', t.title));
      if (t.why) text.append(el('span', 'row-sub', t.why));
      if (t.url && /^https?:\/\//i.test(t.url)) {
        const a = el('a', 'row-link', `${hostOf(t.url)} ↗`); a.href = t.url; a.target = '_blank'; a.rel = 'noopener noreferrer';
        text.append(a);
      }
      li.append(text);
      const ctl = el('div', 'row-ctl');
      const chipCls = { aired: 'tag tag-mint', queued: 'tag tag-quiet', suggested: 'tag' }[t.status] || 'tag tag-quiet';
      ctl.append(el('span', chipCls, String(t.status || 'queued').toUpperCase()));
      if (t.status === 'suggested') {
        const b = el('button', 'btn btn-small', 'Queue'); b.type = 'button';
        b.setAttribute('aria-label', `Queue ${t.title}`);
        b.addEventListener('click', () => queueTopic(t.title, t.id));
        ctl.append(b);
      }
      if (app.mode === 'demo' && t.status !== 'aired') {
        const r = el('button', 'btn btn-small', 'Remove'); r.type = 'button';
        r.setAttribute('aria-label', `Remove ${t.title}`);
        r.addEventListener('click', () => {
          saveTopics(topics().filter(x => x.id !== t.id));
          renderLearn();
          $('learn-status').textContent = `Removed “${t.title}”.`;
          $('learn-title').focus();
        });
        ctl.append(r);
      }
      li.append(ctl);
      list.append(li);
    });
  }
  const hostOf = u => { try { return new URL(u).hostname.replace(/^www\./, ''); } catch (_) { return 'source'; } };
  /* Google's grounding terms require showing its Search Suggestions with grounded results.
     The HTML is Google's, so it goes into a sandboxed srcdoc frame, never into this page. */
  function renderGrounding(res) {
    const box = $('learn-grounding');
    box.replaceChildren();
    const sources = Array.isArray(res.sources) ? res.sources.filter(u => typeof u === 'string' && /^https?:\/\//i.test(u)) : [];
    const html = typeof res.search_suggestions_html === 'string' ? res.search_suggestions_html : '';
    if (!html && !sources.length) { box.hidden = true; return; }
    box.hidden = false;
    box.append(el('h3', 'label', 'GROUNDED WITH GOOGLE SEARCH'));
    if (html) {
      const frame = el('iframe', 'grounding-frame');
      frame.setAttribute('sandbox', 'allow-popups allow-popups-to-escape-sandbox');
      frame.setAttribute('referrerpolicy', 'no-referrer');
      frame.title = 'Google Search suggestions';
      frame.srcdoc = `<!doctype html><meta charset="utf-8"><base target="_blank">${html}`;
      box.append(frame);
    }
    if (sources.length) {
      const ul = el('ul', 'grounding-sources');
      sources.slice(0, 8).forEach(u => { const li = el('li'); const a = el('a', null, `${hostOf(u)} ↗`); a.href = u; a.target = '_blank'; a.rel = 'noopener noreferrer'; li.append(a); ul.append(li); });
      box.append(ul);
    }
  }
  const slug = s => s.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '').slice(0, 40) || `topic-${Date.now()}`;
  async function queueTopic(title, existingId) {
    const status = $('learn-status');
    try {
      if (app.mode === 'host') {
        await write('POST', '/api/learn', { title });
        app.doc = await getJSON('/api/station');
      } else {
        const list = topics();
        const hit = list.find(t => t.id === existingId || t.title.toLowerCase() === title.toLowerCase());
        if (hit) hit.status = 'queued';
        else list.push({ id: slug(title), title, status: 'queued' });
        saveTopics(list);
      }
      renderLearn();
      status.textContent = `“${title}” is queued for a Learn segment.`;
      return true;
    } catch (err) {
      status.textContent = err.message || 'The topic was not queued.';
      return false;
    }
  }
  $('learn-form').addEventListener('submit', async e => {
    e.preventDefault();
    const input = $('learn-title');
    const title = input.value.trim().replace(/\s+/g, ' ');
    if (!title) { $('learn-status').textContent = 'Type a topic first.'; input.focus(); return; }
    if (await queueTopic(title)) input.value = '';
    input.focus();
  });
  $('learn-suggest').addEventListener('click', async () => {
    const status = $('learn-status');
    if (app.mode === 'host') {
      try {
        status.textContent = 'Asking the station host for trending topics…';
        const res = await write('POST', '/api/learn/suggest', {});
        const fresh = (Array.isArray(res.topics) ? res.topics : []).filter(t => t && typeof t.title === 'string' && t.title.trim())
          .map(t => ({ id: slug(t.title), title: t.title.trim(), why: typeof t.why === 'string' ? t.why : '', url: typeof t.url === 'string' ? t.url : '', status: 'suggested' }));
        app.suggested = fresh.concat((app.suggested || []).filter(o => !fresh.some(n => n.title.toLowerCase() === o.title.toLowerCase())));
        renderLearn();
        renderGrounding(res);
        status.textContent = fresh.length ? `The station host suggested ${fresh.length} topics. Queue the ones you want.` : 'No new suggestions right now.';
      } catch (err) { status.textContent = err.message || 'Suggestions are unavailable.'; }
      return;
    }
    const list = topics();
    let added = 0;
    for (const title of SUGGESTIONS) {
      if (list.some(t => t.title.toLowerCase() === title.toLowerCase())) continue;
      list.push({ id: slug(title), title, status: 'suggested' });
      added++;
    }
    saveTopics(list);
    renderLearn();
    status.textContent = added ? `Added ${added} suggested topics (demo suggestions).` : 'The demo suggestions are already on the list.';
  });

  /* ---------------- Connections ---------------- */
  const STATUS_CHIP = { connected: ['CONNECTED', 'tag tag-mint'], sample: ['SAMPLE DATA', 'tag'], available: ['AVAILABLE', 'tag tag-quiet'], off: ['OFF', 'tag tag-quiet'] };
  function renderConnections() {
    const grid = $('conn-grid');
    grid.replaceChildren();
    for (const c of CONNECTIONS) {
      const p = app.providers[c.id] || {};
      const card = el('article', 'panel conn');
      card.dataset.id = c.id;
      const head = el('div', 'conn-head');
      const h = el('h3', 'conn-title', p.label || c.title); h.id = `conn-${c.id}-title`;
      const [chipText, chipCls] = STATUS_CHIP[p.status] || ['NOT REPORTED', 'tag tag-quiet'];
      head.append(h, el('span', chipCls, chipText));
      card.setAttribute('aria-labelledby', h.id);
      card.append(head, el('p', 'conn-blurb', p.detail || c.blurb));
      for (const f of c.fields) {
        const fid = `f-${c.id}-${(f.path || f.key).replace(/\./g, '-')}`;
        if (f.type === 'toggle') {
          const row = el('div', 'conn-toggle');
          const lab = el('span', 'row-title', f.label); lab.id = `${fid}-label`;
          const sw = switchButton(!!getPath(app.settings, f.path), lab.id);
          sw.dataset.path = f.path;
          row.append(lab, sw);
          card.append(row);
          continue;
        }
        const wrap = el('label', 'field');
        wrap.htmlFor = fid;
        const lab = el('span', null, f.label);
        let input;
        if (f.type === 'select') {
          input = el('select', 'input');
          f.options.forEach(([v, t]) => input.append(new Option(t, v)));
          input.value = getPath(app.settings, f.path) || f.options[0][0];
        } else {
          input = el('input', 'input');
          input.autocomplete = 'off';
          input.spellcheck = false;
        }
        input.id = fid;
        input.name = fid;
        if (f.secret) {
          input.type = 'password';
          input.autocomplete = 'new-password';
          input.dataset.provider = f.secret;
          input.dataset.key = f.key;
          const configured = !!(app.settings.keys[f.secret] && app.settings.keys[f.secret].configured);
          lab.append(el('em', null, configured ? ' · configured' : ' · not set'));
          if (app.mode === 'demo') { input.disabled = true; input.placeholder = 'Entered on the station host'; }
          else input.placeholder = configured ? 'Saved. Type a new key to replace it.' : 'Paste the key';
        } else if (f.type !== 'select') {
          input.type = f.type || 'text';
          if (f.type === 'number') { input.min = String(f.min); input.max = String(f.max); input.step = String(f.step || 1); input.inputMode = 'numeric'; input.classList.add('mono'); }
          input.placeholder = f.placeholder || '';
          const v = getPath(app.settings, f.path);
          input.value = v == null ? '' : String(v);
        }
        if (f.path) input.dataset.path = f.path;
        wrap.append(lab, input);
        card.append(wrap);
      }
      if (c.note) card.append(el('p', 'conn-note', c.note));
      if (c.hint) {
        const n = el('p', 'conn-note conn-note-quiet', c.hint);
        if (c.code) { n.append(document.createTextNode(' ')); n.append(el('code', null, c.code)); }
        card.append(n);
      }
      grid.append(card);
    }
  }
  $('conn-save').addEventListener('click', async () => {
    const patch = {}, secrets = {};
    let bad = null;
    document.querySelectorAll('#conn-grid [data-path]').forEach(n => {
      if (n.classList.contains('switch')) setPath(patch, n.dataset.path, n.getAttribute('aria-checked') === 'true');
      else if (n.type === 'number') {
        const v = Number(n.value);
        if (!Number.isFinite(v) || v < Number(n.min) || v > Number(n.max)) bad = bad || n;
        else setPath(patch, n.dataset.path, Math.round(v));
      } else setPath(patch, n.dataset.path, n.value.trim());
    });
    if (bad) { $('conn-status').textContent = `Enter a number from ${bad.min} to ${bad.max}.`; bad.focus(); return; }
    if (app.mode === 'host') document.querySelectorAll('#conn-grid input[data-provider]').forEach(i => {
      if (i.value.trim()) (secrets[i.dataset.provider] = secrets[i.dataset.provider] || {})[i.dataset.key] = i.value.trim();
    });
    const ok = await saveSettings(patch, 'conn-status', 'Connections saved', secrets);
    document.querySelectorAll('#conn-grid input[data-provider]').forEach(i => { i.value = ''; });
    if (!ok) return;
  });
  $('conn-form').addEventListener('submit', e => { e.preventDefault(); $('conn-save').click(); });

  /* ---------------- Settings ---------------- */
  function renderSettings() {
    const s = app.settings.station || {};
    $('set-name').value = s.name || '';
    $('set-address').value = s.address || '';
    $('set-edition').textContent = (app.doc.station && app.doc.station.edition) || 'Synthetic sample';
    const box = $('host-list');
    box.replaceChildren();
    (app.settings.hosts || []).forEach((h, i) => {
      const row = el('fieldset', 'host-row');
      row.dataset.id = h.id;
      row.append(el('legend', 'label', `HOST ${i + 1}`));
      for (const [k, label] of [['name', 'Name'], ['role', 'Role'], ['voice', 'Voice']]) {
        const f = el('label', 'field');
        f.append(el('span', null, label));
        const input = el('input', 'input');
        input.type = 'text'; input.maxLength = 60; input.autocomplete = 'off';
        input.value = h[k] || ''; input.dataset.key = k; input.name = `host-${h.id}-${k}`;
        f.append(input);
        row.append(f);
      }
      box.append(row);
    });
  }
  $('set-save').addEventListener('click', () => {
    const name = $('set-name').value.trim();
    if (!name) { $('set-status').textContent = 'The station needs a name.'; $('set-name').focus(); return; }
    const hosts = [...document.querySelectorAll('#host-list .host-row')].map(row => {
      const h = { id: row.dataset.id };
      row.querySelectorAll('input').forEach(i => { h[i.dataset.key] = i.value.trim(); });
      return h;
    });
    saveSettings({ station: { name, address: $('set-address').value.trim() }, hosts }, 'set-status', 'Settings saved');
  });

  /* ---------------- tabs ---------------- */
  const tabs = [...document.querySelectorAll('[role="tab"]')];
  function select(tab, focus) {
    tabs.forEach(t => {
      const on = t === tab;
      t.setAttribute('aria-selected', String(on));
      t.tabIndex = on ? 0 : -1;
      $(t.getAttribute('aria-controls')).hidden = !on;
    });
    if (focus) tab.focus();
    if (location.hash !== `#${tab.dataset.hash}`) history.replaceState(null, '', `#${tab.dataset.hash}`);
  }
  tabs.forEach((t, i) => {
    t.addEventListener('click', () => select(t, false));
    t.addEventListener('keydown', e => {
      const map = { ArrowRight: i + 1, ArrowDown: i + 1, ArrowLeft: i - 1, ArrowUp: i - 1, Home: 0, End: tabs.length - 1 };
      if (!(e.key in map)) return;
      e.preventDefault();
      select(tabs[(map[e.key] + tabs.length) % tabs.length], true);
    });
  });
  const fromHash = () => { const t = tabs.find(x => `#${x.dataset.hash}` === location.hash); if (t) select(t, false); };
  window.addEventListener('hashchange', fromHash);
  fromHash();

  boot();
})();
