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
