// Animasi masuk bila bertukar bahagian (bukan bila data dikemas kini).
(function(){
  const v = document.getElementById('view');
  if(!v || !('MutationObserver' in window)) return;
  if(window.matchMedia && matchMedia('(prefers-reduced-motion: reduce)').matches) return;
  let last = null, timer = 0;
  new MutationObserver(() => {
    const cur = (typeof render === 'function' && render._v) || location.hash;
    if(cur === last) return;
    last = cur;
    const els = [];
    for(const c of v.children){
      if(c.matches('.grid, .notes, .tiles, .stack')) els.push(...c.children); else els.push(c);
      if(els.length > 14) break;
    }
    els.slice(0, 14).forEach((el, i) => { el.classList.add('hy-a'); el.style.setProperty('--hy-i', i); });
    v.classList.remove('hy-vt'); void v.offsetWidth; v.classList.add('hy-vt');
    clearTimeout(timer);
    timer = setTimeout(() => { v.classList.remove('hy-vt'); v.querySelectorAll('.hy-a').forEach(el => el.classList.remove('hy-a')); }, 1300);
  }).observe(v, {childList: true});
})();

// Logo Hey Armay menggantikan teks jenama
(function(){
  const brand = document.querySelector('.side-top .brand');
  if(!brand) return;
  for(const n of [...brand.childNodes]) if(n.nodeType === 3 && n.textContent.trim()) n.remove();
  const lg = document.createElement('span');
  lg.className = 'hy-logo'; lg.setAttribute('role', 'img'); lg.setAttribute('aria-label', 'Hey Armay');
  const i = brand.querySelector('i'); if(i) i.after(lg); else brand.prepend(lg);
})();

// Telefon: laci sisi
(function(){
  const brand = document.querySelector('.side-top .brand');
  const nav = document.getElementById('nav');
  if(!brand || !nav) return;
  const b = document.createElement('button');
  b.type = 'button'; b.className = 'hy-burger'; b.setAttribute('aria-label', 'Buka menu'); b.setAttribute('aria-expanded', 'false'); b.setAttribute('aria-controls', 'nav');
  b.innerHTML = '<span></span>';
  brand.insertBefore(b, brand.firstChild);
  const scrim = document.createElement('div'); scrim.id = 'hy-scrim'; document.body.appendChild(scrim);
  const set = open => {
    document.body.classList.toggle('hy-open', open);
    b.setAttribute('aria-expanded', String(open)); b.setAttribute('aria-label', open ? 'Tutup menu' : 'Buka menu');
    if(open){ const on = nav.querySelector('a.on') || nav.querySelector('a'); if(on) setTimeout(() => on.focus({preventScroll:false}), 60); }
  };
  b.addEventListener('click', () => set(!document.body.classList.contains('hy-open')));
  scrim.addEventListener('click', () => set(false));
  nav.addEventListener('click', e => { if(e.target.closest('a')) set(false); });
  document.addEventListener('keydown', e => { if(e.key === 'Escape' && document.body.classList.contains('hy-open')){ set(false); b.focus(); } });
  // leret ke kiri untuk tutup
  let x0 = null, y0 = null;
  nav.addEventListener('touchstart', e => { x0 = e.touches[0].clientX; y0 = e.touches[0].clientY; }, {passive:true});
  nav.addEventListener('touchend', e => {
    if(x0 === null) return;
    const dx = e.changedTouches[0].clientX - x0, dy = e.changedTouches[0].clientY - y0;
    if(dx < -60 && Math.abs(dy) < 50) set(false);
    x0 = null;
  }, {passive:true});
  matchMedia('(min-width: 821px)').addEventListener('change', ev => { if(ev.matches) set(false); });
  window.hyDrawer = set;
})();

// Tukar tema terang / gelap (disimpan dalam pelayar ini)
document.addEventListener('DOMContentLoaded', () => {
  const brand = document.querySelector('.side-top .brand');
  if(!brand) return;
  const b = document.createElement('button');
  b.type = 'button'; b.className = 'hy-theme';
  b.innerHTML = '<svg class="moon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M21 12.8A9 9 0 1 1 11.2 3a7 7 0 0 0 9.8 9.8z"/></svg>'
    + '<svg class="sun" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" aria-hidden="true"><circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4"/></svg>';
  const root = document.documentElement;
  const label = () => { const d = root.getAttribute('data-hy') === 'dark'; b.setAttribute('aria-label', d ? 'Tukar ke tema terang' : 'Tukar ke tema gelap'); b.title = b.getAttribute('aria-label'); };
  label();
  b.addEventListener('click', () => {
    const next = root.getAttribute('data-hy') === 'dark' ? 'light' : 'dark';
    root.classList.add('hy-swap');
    root.setAttribute('data-hy', next);
    try { localStorage.setItem('hy-theme', next); } catch(e){}
    const m = document.querySelector('meta[name="theme-color"]'); if(m) m.content = next === 'dark' ? '#080B1C' : '#EDF0F8';
    label();
    setTimeout(() => root.classList.remove('hy-swap'), 600);
  });
  brand.appendChild(b);
});

// Telefon: bar bawah (Hari Ini, Kalendar, Cakap, Tulis, Menu) + kotak tulis yang naik dari bawah
(function(){
  const cap = document.getElementById('capture'), input = document.getElementById('cap-in');
  if(!cap) return;
  const ic = {
    home: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M3 10.5L12 3l9 7.5V20a1 1 0 0 1-1 1h-5v-6h-6v6H4a1 1 0 0 1-1-1z"/></svg>',
    cal: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="3" y="4.5" width="18" height="16.5" rx="2.5"/><path d="M3 9.5h18M8 2.5v4M16 2.5v4"/></svg>',
    mic: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="9" y="2.5" width="6" height="12" rx="3"/><path d="M5 11a7 7 0 0 0 14 0M12 18v3.5"/></svg>',
    pen: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M4 20h4L19 9a2.8 2.8 0 0 0-4-4L4 16z"/><path d="M13.5 6.5l4 4"/></svg>',
    menu: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" aria-hidden="true"><path d="M4 7h16M4 12h16M4 17h16"/></svg>'
  };
  const bar = document.createElement('nav');
  bar.className = 'hy-tabbar'; bar.setAttribute('aria-label', 'Akses pantas');
  bar.innerHTML = `<a class="hy-tab" href="#hari-ini" data-view="hari-ini" data-tab="hari-ini">${ic.home}<span>Hari Ini</span></a>
    <a class="hy-tab" href="#kalendar" data-view="kalendar" data-tab="kalendar">${ic.cal}<span>Kalendar</span></a>
    <button type="button" class="hy-fab" data-hy="cakap" aria-label="Cakap dan susun"><i>${ic.mic}</i><span>Cakap</span></button>
    <button type="button" class="hy-tab" data-hy="tulis" aria-label="Tulis cepat">${ic.pen}<span>Tulis</span></button>
    <button type="button" class="hy-tab" data-hy="menu" aria-label="Semua bahagian">${ic.menu}<span>Menu</span></button>`;
  document.body.appendChild(bar);
  const body = document.body;
  const closeCap = () => body.classList.remove('hy-cap');
  bar.addEventListener('click', e => {
    const b = e.target.closest('[data-hy]'); if(!b) return;
    const k = b.dataset.hy;
    if(k === 'tulis'){ body.classList.add('hy-cap'); kbFit(); }
    if(k === 'cakap'){ const v = document.getElementById('cap-voice'); if(v && !v.hidden) v.click(); else { body.classList.add('hy-cap'); if(input) input.focus(); } }
    if(k === 'menu' && window.hyDrawer) window.hyDrawer(true);
  });
  // Papan kekunci: pastikan kotak tulis sentiasa di atas papan kekunci (iPhone & Android)
  const vv = window.visualViewport;
  function kbFit(){
    if(!vv) return;
    const kb = Math.max(0, Math.round(window.innerHeight - vv.height - vv.offsetTop));
    document.documentElement.style.setProperty('--kb', (kb > 60 ? kb : 0) + 'px');
  }
  if(vv){ vv.addEventListener('resize', kbFit); vv.addEventListener('scroll', kbFit); }
  if(input) input.addEventListener('focus', () => setTimeout(kbFit, 250));
  const scrim = document.getElementById('hy-scrim');
  if(scrim) scrim.addEventListener('click', closeCap);
  document.addEventListener('keydown', e => { if(e.key === 'Escape') closeCap(); });
  cap.addEventListener('submit', () => setTimeout(() => { if(!input || !input.value) closeCap(); }, 400));
  const sync = () => {
    const v = (typeof render === 'function' && render._v) || location.hash.slice(1) || 'hari-ini';
    bar.querySelectorAll('[data-tab]').forEach(a => a.classList.toggle('on', a.dataset.tab === v));
  };
  const view = document.getElementById('view');
  if(view && 'MutationObserver' in window) new MutationObserver(sync).observe(view, {childList: true});
  window.addEventListener('hashchange', sync); sync();
})();
