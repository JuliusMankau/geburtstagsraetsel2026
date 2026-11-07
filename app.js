/* Geburtstagsrätsel – öffentliche Engine.
   Die Rätsel selbst stecken verschlüsselt in data.js: Jede Stufe lässt sich nur
   mit der richtigen Lösung der vorherigen entschlüsseln (PBKDF2 + AES-GCM). */
(() => {
  'use strict';

  const D = window.RAETSEL;
  const STORE = 'raetsel-v1';
  const subtle = window.crypto && window.crypto.subtle;
  const enc = new TextEncoder();
  const dec = new TextDecoder();
  const reduced = matchMedia('(prefers-reduced-motion: reduce)').matches;

  const $ = s => document.querySelector(s);
  const wait = ms => new Promise(r => setTimeout(r, ms));
  const b64d = s => Uint8Array.from(atob(s), c => c.charCodeAt(0));
  const b64e = u => btoa(String.fromCharCode(...u));

  // Muss exakt zu norm() in bauen.py passen.
  const norm = s => s.toLowerCase()
    .replace(/ä/g, 'ae').replace(/ö/g, 'oe').replace(/ü/g, 'ue').replace(/ß/g, 'ss')
    .normalize('NFKD').replace(/[̀-ͯ]/g, '')
    .replace(/[^a-z0-9]/g, '');

  // ── Fortschritt (liegt nur im Browser des Spielers) ──
  let S = {};
  try { S = JSON.parse(localStorage.getItem(STORE)) || {}; } catch {}
  S.solved = S.solved || {};
  S.tries = S.tries || {};
  S.extra = S.extra || {};
  const save = () => { try { localStorage.setItem(STORE, JSON.stringify(S)); } catch {} };

  // ── Krypto ──
  async function decrypt(raw, box) {
    const key = await subtle.importKey('raw', raw, 'AES-GCM', false, ['decrypt']);
    return new Uint8Array(await subtle.decrypt({ name: 'AES-GCM', iv: b64d(box.iv) }, key, b64d(box.ct)));
  }

  async function unwrap(lock, token) {
    const base = await subtle.importKey('raw', enc.encode(token), 'PBKDF2', false, ['deriveBits']);
    const k = new Uint8Array(await subtle.deriveBits(
      { name: 'PBKDF2', hash: 'SHA-256', salt: b64d(lock.salt), iterations: D.iter }, base, 256));
    for (const w of lock.w) {
      try { return await decrypt(k, w); } catch {}
    }
    return null;
  }

  const openBox = async (next, key) => JSON.parse(dec.decode(await decrypt(key, next.box)));

  async function sha256(s) {
    const h = new Uint8Array(await subtle.digest('SHA-256', enc.encode(s)));
    return Array.from(h, b => b.toString(16).padStart(2, '0')).join('');
  }

  // ── Ablauf ──
  let cur = null; // { i, p }: aktuelle Stufe und ihr entschlüsselter Inhalt
  let busy = false;

  async function tryUnlock(token) {
    const next = cur.p.next;
    if (!next || !token) return null;
    const key = await unwrap(next.lock, token);
    if (!key) return null;
    const p = await openBox(next, key);
    const i = cur.i + 1;
    S.solved[cur.i] = { t: token, k: b64e(key) };
    S.stage = i;
    save();
    return { i, p, render: () => show(i, p) };
  }

  // Gespeicherten Fortschritt wieder aufschließen: erst mit den gemerkten
  // Schlüsseln, notfalls (nach einem Neubau von data.js) mit den Antworten.
  async function restore() {
    let i = 1;
    let p = D.first;
    while (i < S.stage && p.next) {
      const s = S.solved[i];
      if (!s) break;
      let np = null;
      try { np = await openBox(p.next, b64d(s.k)); } catch {}
      if (!np) {
        const key = await unwrap(p.next.lock, s.t).catch(() => null);
        if (!key) break;
        np = await openBox(p.next, key);
        s.k = b64e(key);
      }
      p = np;
      i++;
    }
    if (i !== S.stage) S.stage = i;
    save();
    return { i, p };
  }

  // ── Darstellung ──
  function marks(m) {
    const nav = $('.marks');
    nav.innerHTML = '';
    for (let j = 1; j <= m.total; j++) {
      const s = document.createElement('span');
      s.className = 'mark' + (j <= m.done ? ' done' : j === m.now ? ' now' : '');
      nav.appendChild(s);
    }
  }

  function frame(p, extra = '', cls = '') {
    return `<section class="stage ${cls}">
      ${p.kicker ? `<p class="kicker">${p.kicker}</p>` : ''}
      <h1>${p.title}</h1>
      <div class="rule"></div>
      <div class="body">${p.html}</div>${extra}
    </section>`;
  }

  function show(i, p) {
    cur = { i, p };
    marks(p.marks);
    if (p.css && !document.querySelector(`style[data-stufe="${i}"]`)) {
      const st = document.createElement('style');
      st.dataset.stufe = i;
      st.textContent = p.css;
      document.head.appendChild(st);
    }
    const wrap = $('.stage-wrap');
    wrap.innerHTML = frame(p);
    const sec = wrap.firstElementChild;
    if (p.input) sec.appendChild(form(p.input));
    if (p.script) {
      new Function('ctx', p.script)({
        el: sec, p, i, marks: $('.marks'),
        store: (S.extra[i] = S.extra[i] || {}),
        save, tryUnlock, norm, reduced, wait,
      });
    }
    window.scrollTo(0, 0);
  }

  async function swap(render) {
    const w = $('.stage-wrap');
    if (!reduced) {
      w.classList.add('out');
      await wait(380);
    }
    render();
    w.classList.add('in');
    w.classList.remove('out');
    void w.offsetWidth;
    w.classList.remove('in');
  }

  function intro() {
    const it = D.intro;
    marks({ total: D.first.marks.total, done: 0 });
    $('.stage-wrap').innerHTML = frame(it, `<div class="start"><button type="button">${it.button}</button></div>`, 'intro');
    $('.start button').addEventListener('click', () => {
      S.stage = 1;
      save();
      swap(() => show(1, D.first));
    });
  }

  // ── Antworten ──
  function form(spec) {
    const f = document.createElement('form');
    f.className = 'answer';
    f.noValidate = true;
    f.setAttribute('autocomplete', 'off');
    if (spec.type === 'choice') {
      f.classList.add('choice');
      f.innerHTML = (spec.label ? `<p class="choice-label">${spec.label}</p>` : '') +
        '<div class="rows">' + spec.names.map(n => `
          <div class="row" role="radiogroup" aria-label="${n}">
            <span class="name">${n}</span>
            <span class="seg">${spec.options.map(o =>
              `<label><input type="radio" name="${n}" value="${o}"><span>${o}</span></label>`).join('')}</span>
          </div>`).join('') + '</div>' +
        '<div class="field end"><button type="submit">Prüfen</button></div>';
    } else {
      f.innerHTML = `<div class="field">
        <input name="a" type="text" placeholder="${spec.placeholder || 'Deine Antwort'}" aria-label="Antwort"
          autocomplete="off" autocapitalize="off" autocorrect="off" spellcheck="false" enterkeyhint="go">
        <button type="submit">Prüfen</button>
      </div>`;
    }
    f.insertAdjacentHTML('beforeend', '<p class="feedback" role="status"></p>');
    f.addEventListener('submit', e => { e.preventDefault(); submit(f, spec); });
    const t = S.tries[cur.i];
    if (t && t.until > Date.now()) setTimeout(() => cooldown(f, 'Kurze Pause.'));
    return f;
  }

  function tokenOf(f, spec) {
    if (spec.type !== 'choice') return norm(f.elements.a.value);
    const parts = [];
    for (const n of spec.names) {
      const c = f.querySelector(`input[name="${n}"]:checked`);
      if (!c) return '';
      parts.push(n + ' ' + c.value);
    }
    return norm(parts.join(' '));
  }

  function say(f, text, kind = '') {
    const fb = f.querySelector('.feedback');
    fb.className = 'feedback' + (kind ? ' ' + kind : '');
    fb.textContent = text;
  }

  // Nach drei Fehlversuchen wird jede weitere Antwort kurz gesperrt –
  // damit Raten mühsamer ist als Nachdenken.
  function cooldown(f, msg) {
    const btn = f.querySelector('button');
    const t = S.tries[cur.i];
    if (msg) say(f, msg, 'no');
    btn.disabled = true;
    (function tick() {
      if (!f.isConnected) return;
      const left = Math.ceil((t.until - Date.now()) / 1000);
      if (left <= 0) {
        btn.disabled = false;
        btn.textContent = 'Prüfen';
        say(f, '');
        return;
      }
      btn.textContent = left + ' s';
      setTimeout(tick, 250);
    })();
  }

  async function submit(f, spec) {
    const btn = f.querySelector('button');
    if (busy || btn.disabled) return;
    const token = tokenOf(f, spec);
    if (!token) {
      say(f, spec.type === 'choice' ? 'Ordne jedem Kind ein Wort zu.' : 'Gib zuerst eine Antwort ein.');
      return;
    }
    busy = true;
    btn.disabled = true;
    btn.classList.add('wait');
    say(f, '');
    const res = await tryUnlock(token).catch(() => null);
    btn.classList.remove('wait');

    if (res) {
      f.classList.add('solved');
      say(f, 'Richtig.', 'ok');
      delete S.tries[cur.i];
      save();
      const m = $('.marks').children[cur.i - 1];
      if (m) m.classList.add('done');
      await wait(reduced ? 300 : 1100);
      await swap(res.render);
      busy = false;
      return;
    }

    busy = false;
    btn.disabled = false;
    if (cur.p.near) {
      const h = await sha256(token);
      const hit = cur.p.near.find(n => n.h === h);
      if (hit) { say(f, hit.msg, 'near'); return; }
    }
    const t = S.tries[cur.i] = S.tries[cur.i] || { n: 0, until: 0 };
    t.n++;
    if (t.n >= 3) t.until = Date.now() + Math.min(10 * 2 ** (t.n - 3), 120) * 1000;
    save();
    f.classList.remove('shake');
    void f.offsetWidth;
    f.classList.add('shake');
    if (t.until > Date.now()) cooldown(f, 'Leider nicht.');
    else say(f, 'Leider nicht.', 'no');
  }

  // ── Start ──
  async function boot() {
    if (new URLSearchParams(location.search).has('reset')) {
      try { localStorage.removeItem(STORE); } catch {}
      S = { solved: {}, tries: {}, extra: {} };
      history.replaceState(null, '', location.pathname);
    }
    document.title = D.title;
    $('.foot').textContent = D.footer;
    if (!subtle) {
      $('.stage-wrap').innerHTML = '<p class="fail">Dieser Browser kann die Rätsel leider nicht öffnen. Bitte einen aktuellen Browser verwenden.</p>';
    } else if (!S.stage) {
      intro();
    } else {
      const { i, p } = await restore();
      show(i, p);
    }
    document.body.classList.add('ready');
  }

  boot();
})();
