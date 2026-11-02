'use strict';
const $ = id => document.getElementById(id);
const el = (tag, text, cls) => { const n = document.createElement(tag); if (text != null) n.textContent = text; if (cls) n.className = cls; return n; };
const audio = $('audio');
audio.addEventListener('canplay', () => { $('audio-status').textContent = 'Audio ready. Use the player controls to listen.'; }, {once:true});
audio.addEventListener('error', () => { $('audio-status').textContent = 'Audio is unavailable. The full transcript is below.'; });
async function init() {
  try {
    const responses = await Promise.all(['episode','card','facts','gate-demo'].map(name => fetch(`data/${name}.json`)));
    if (responses.some(r => !r.ok)) throw new Error('Data unavailable');
    const [episode, card, facts, gate] = await Promise.all(responses.map(r => r.json()));
    $('gate-status').textContent = episode.gate.passed ? 'Passed' : 'Not passed';
    $('push-body').textContent = episode.push?.body || 'No alert for this cycle.';
    const byId = Object.fromEntries(facts.map(f => [f.id, f]));
    const lines = $('lines'); lines.replaceChildren();
    for (const line of episode.lines) {
      const row = el('div', null, 'line'), content = el('div');
      row.append(el('span', line.voice, 'voice')); content.append(el('p', line.text));
      for (const id of line.cites) {
        const f = byId[id], detail = el('details', null, 'citation');
        detail.append(el('summary', `${id} · evidence`));
        detail.append(el('p', f ? `${f.subject} · ${f.predicate}: ${typeof f.value === 'object' ? JSON.stringify(f.value) : f.value}` : 'Evidence unavailable.'));
        if (f?.source) detail.append(el('p', `Source: ${typeof f.source === 'object' ? JSON.stringify(f.source) : f.source}`));
        content.append(detail);
      }
      row.append(content); lines.append(row);
    }
    const item = card.items[0], target = $('card'); target.replaceChildren();
    target.append(el('h3', item.cve), el('p', item.name, 'name'));
    const dl = el('dl');
    for (const [label,value] of [['WHY NOW',item.why_now.join(', ')],['OPEN ASSETS',String(item.open_assets)],['OWNER',(item.owners.length ? item.owners.join(', ') : 'See private action packet')],['INTERNAL DEADLINE',item.internal_deadline]]) { const d = el('div'); d.append(el('dt',label),el('dd',value)); dl.append(d); }
    target.append(dl); const next = el('p',null,'next'); next.append(el('b','NEXT STEP'), document.createTextNode(item.next_steps.join(' '))); target.append(next);
    const ticket = `EXPOSURE RADIO — EXECUTIVE ACTION CARD\nSynthetic sample · As of ${card.as_of}\n\n${item.cve} — ${item.name}\nWhy now: ${item.why_now.join(', ')}\nOpen assets: ${item.open_assets}\nOwner: ${(item.owners.length ? item.owners.join(', ') : 'See private action packet')}\nInternal deadline: ${item.internal_deadline}\nNext step: ${item.next_steps.join(' ')}\nEvidence: ${item.evidence.join(', ')}\n\nSource: CISA KEV catalog https://www.cisa.gov/known-exploited-vulnerabilities-catalog\n`;
    $('copy').disabled = $('download').disabled = false;
    $('copy').addEventListener('click', async () => { try { await navigator.clipboard.writeText(ticket); $('copy-status').textContent = 'Action card copied.'; } catch (_) { $('copy-status').textContent = 'Copy unavailable in this browser. Download the text card instead.'; } });
    $('download').addEventListener('click', () => { const url = URL.createObjectURL(new Blob([ticket], {type:'text/plain;charset=utf-8'})); const a = el('a'); a.href = url; a.download = 'exposure-radio-action-card.txt'; a.click(); setTimeout(() => URL.revokeObjectURL(url),1000); $('copy-status').textContent = 'Action card download started.'; });
    const cases = $('gate-cases'); cases.replaceChildren();
    for (const [index,name] of ['wrong relation: fixed vs open','unsupported all-clear'].entries()) { const c = gate.cases.find(x => x.name === name); if (!c) continue; const box = el('article',null,'case'), top = el('div',null,'case-top'); top.append(el('span',`TEST 0${index+1}`),el('span',c.status.toUpperCase(),'blocked')); box.append(top,el('blockquote',`“${c.text}”`),el('p',c.reason)); cases.append(box); }
    $('gate-summary').textContent = `${gate.summary.false_blocked} of ${gate.summary.false_total} false statements blocked · ${gate.summary.controls_supported} of ${gate.summary.controls_total} supported controls passed · Clean script ${gate.scripts.clean_passed ? 'passed' : 'did not pass'}`;
  } catch (error) { $('lines').textContent = 'Briefing data could not be loaded. Serve this site over HTTP and try again.'; $('gate-status').textContent = 'Unavailable'; $('gate-cases').textContent = 'Gate results are unavailable.'; $('card').textContent = 'Action card is unavailable.'; }
}
init();
