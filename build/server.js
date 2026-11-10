// heyarmay.com — Hey Armay (Cloudflare Worker)
// Bindings: DB (D1), ARMEDIA_DB (D1 armedia-db, baca sahaja, pilihan). Vars: ALLOWED_EMAIL. Secret: ANTHROPIC_API_KEY.
// Log masuk: ID + kata laluan sendiri, sesi dalam kuki HttpOnly. Kata laluan diregangkan
// dua kali (PBKDF2 310k di pelayar, kemudian PBKDF2 dengan garam rawak di pelayan), jadi
// kata laluan sebenar tidak pernah dihantar atau disimpan. Penyediaan akaun pertama kali
// hanya dibenarkan dengan token Cloudflare Access yang sah untuk ALLOWED_EMAIL.
// Laluan /r/<kunci>/<jenis> ialah pengecualian: ia hanya memulangkan teks ringkasan untuk
// notifikasi Claude app.

const MODEL_QUICK = 'claude-haiku-5-5';
const MODEL_COMPLEX = 'claude-sonnet-5-5';
const DAILY_CLAUDE_LIMIT = 300;
const TZ_OFFSET_MIN = 480; // Asia/Kuala_Lumpur, UTC+8

const SCHEMA = [
  `CREATE TABLE IF NOT EXISTS docs (coll TEXT NOT NULL, id TEXT NOT NULL, data TEXT NOT NULL, updated INTEGER NOT NULL, PRIMARY KEY (coll, id))`,
  `CREATE TABLE IF NOT EXISTS files (id TEXT PRIMARY KEY, type TEXT NOT NULL, data BLOB NOT NULL, created INTEGER NOT NULL)`,
  `CREATE TABLE IF NOT EXISTS usage (day TEXT PRIMARY KEY, n INTEGER NOT NULL)`,
  `CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v TEXT NOT NULL)`,
  `CREATE TABLE IF NOT EXISTS sessions (h TEXT PRIMARY KEY, created INTEGER NOT NULL, expires INTEGER NOT NULL)`,
  `CREATE TABLE IF NOT EXISTS fails (ip TEXT PRIMARY KEY, n INTEGER NOT NULL, until INTEGER NOT NULL)`
];
const ACCESS_TEAM = 'raspy-bush-7e42';
const SESSION_DAYS = 90;
const SERVER_ITER = 20000;
const COOKIE = '__Host-hs';

/* ---------------- helpers ---------------- */
const J = (obj, status = 200, extra = {}) => new Response(JSON.stringify(obj), {status, headers: {'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store', ...extra}});
const T = (txt, status = 200, type = 'text/plain; charset=utf-8') => new Response(txt, {status, headers: {'content-type': type, 'cache-control': 'no-store'}});
const pad = n => String(n).padStart(2, '0');
const nowLocal = () => new Date(Date.now() + TZ_OFFSET_MIN * 60000);
const ymdOf = d => `${d.getUTCFullYear()}-${pad(d.getUTCMonth() + 1)}-${pad(d.getUTCDate())}`;
const todayLocal = () => ymdOf(nowLocal());
const addDays = (s, n) => { const [y, m, d] = s.split('-').map(Number); const t = new Date(Date.UTC(y, m - 1, d + n)); return ymdOf(t); };
const daysBetween = (a, b) => { const p = s => { const [y, m, d] = s.split('-').map(Number); return Date.UTC(y, m - 1, d); }; return Math.round((p(b) - p(a)) / 864e5); };
const isYmd = s => /^\d{4}-\d{2}-\d{2}$/.test(s || '');
const money = n => 'RM ' + (Number(n) || 0).toFixed(2);
const SEG = /^[A-Za-z0-9_\-.~:@+]{1,200}$/;
const isObj = v => v && typeof v === 'object' && !Array.isArray(v);
function deepMerge(base, patch){
  const out = isObj(base) ? {...base} : {};
  for(const [k, v] of Object.entries(patch)){
    if(isObj(v) && v.__delete__ === true){ delete out[k]; continue; }
    out[k] = isObj(v) && isObj(out[k]) ? deepMerge(out[k], v) : v;
  }
  return out;
}
let schemaReady = false;
async function ensureSchema(env){
  if(schemaReady) return;
  for(const s of SCHEMA) await env.DB.prepare(s).run();
  schemaReady = true;
}
async function allDocs(env, coll){
  const r = await env.DB.prepare('SELECT id, data FROM docs WHERE coll = ?').bind(coll).all();
  return (r.results || []).map(x => ({id: x.id, data: JSON.parse(x.data)}));
}
async function getMeta(env, k){ const r = await env.DB.prepare('SELECT v FROM meta WHERE k = ?').bind(k).first(); return r ? r.v : null; }
async function setMeta(env, k, v){ await env.DB.prepare('INSERT INTO meta (k, v) VALUES (?, ?) ON CONFLICT(k) DO UPDATE SET v = excluded.v').bind(k, v).run(); }
function randomKey(){ const a = new Uint8Array(18); crypto.getRandomValues(a); return [...a].map(b => b.toString(36).padStart(2, '0')).join('').slice(0, 28); }

/* ---------------- auth ---------------- */
const enc = new TextEncoder();
const b64 = buf => btoa(String.fromCharCode(...new Uint8Array(buf)));
const unb64 = s => Uint8Array.from(atob(s), c => c.charCodeAt(0));
const b64url = buf => b64(buf).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const unb64url = s => unb64(s.replace(/-/g, '+').replace(/_/g, '/') + '==='.slice((s.length + 3) % 4));
const randBytes = n => { const a = new Uint8Array(n); crypto.getRandomValues(a); return a; };
const sha256 = async s => b64(await crypto.subtle.digest('SHA-256', enc.encode(s)));
function sameBytes(a, b){ if(a.length !== b.length) return false; let x = 0; for(let i = 0; i < a.length; i++) x |= a[i] ^ b[i]; return x === 0; }
async function serverHash(clientKeyB64, saltB64, iter){
  const k = await crypto.subtle.importKey('raw', unb64(clientKeyB64), 'PBKDF2', false, ['deriveBits']);
  return new Uint8Array(await crypto.subtle.deriveBits({name: 'PBKDF2', hash: 'SHA-256', salt: unb64(saltB64), iterations: iter}, k, 256));
}
const validKey = k => typeof k === 'string' && /^[A-Za-z0-9+/]{43}=$/.test(k);
const normId = s => String(s || '').trim().toLowerCase();
const validId = s => /^[a-z0-9._@-]{3,40}$/.test(s);
async function getAuth(env){ const v = await getMeta(env, 'auth'); return v ? JSON.parse(v) : null; }
async function setPassword(env, user, clientKey){
  const salt = b64(randBytes(16));
  const hash = b64(await serverHash(clientKey, salt, SERVER_ITER));
  await setMeta(env, 'auth', JSON.stringify({user, salt, iter: SERVER_ITER, hash, changed: Date.now()}));
}
function cookieOf(req, name){
  for(const part of (req.headers.get('cookie') || '').split(';')){
    const i = part.indexOf('='); if(i < 0) continue;
    if(part.slice(0, i).trim() === name) return part.slice(i + 1).trim();
  }
  return '';
}
const setCookie = token => `${COOKIE}=${token}; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=${400 * 86400}`;
const clearCookie = () => `${COOKIE}=; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=0`;
async function newSession(env){
  const token = b64url(randBytes(32));
  await env.DB.prepare('INSERT INTO sessions (h, created, expires) VALUES (?, ?, ?)').bind(await sha256(token), Date.now(), Date.now() + SESSION_DAYS * 864e5).run();
  return token;
}
// Sesi sah? Memanjangkan tempoh (sliding) bila tinggal kurang 80 hari.
async function sessionOk(req, env){
  const token = cookieOf(req, COOKIE);
  if(!/^[A-Za-z0-9_-]{43}$/.test(token)) return false;
  const h = await sha256(token);
  const r = await env.DB.prepare('SELECT expires FROM sessions WHERE h = ?').bind(h).first();
  if(!r) return false;
  if(r.expires < Date.now()){ await env.DB.prepare('DELETE FROM sessions WHERE h = ?').bind(h).run(); return false; }
  if(r.expires - Date.now() < 80 * 864e5) await env.DB.prepare('UPDATE sessions SET expires = ? WHERE h = ?').bind(Date.now() + SESSION_DAYS * 864e5, h).run();
  return true;
}
// Had cubaan: 5 salah setiap IP → kunci 15 minit; 50 salah sejam keseluruhan → kunci semua.
async function lockedOut(env, ip){
  const r = await env.DB.prepare('SELECT n, until FROM fails WHERE ip = ? OR ip = ?').bind(ip, '*').all();
  return (r.results || []).some(x => x.until > Date.now());
}
async function noteFail(env, ip){
  const now = Date.now();
  for(const [key, max, lockMs] of [[ip, 5, 15 * 60000], ['*', 50, 60 * 60000]]){
    const cur = await env.DB.prepare('SELECT n, until FROM fails WHERE ip = ?').bind(key).first();
    let n = cur && cur.until > now - 3600e3 ? cur.n + 1 : 1;
    let until = now;
    if(n >= max){ until = now + lockMs; n = 0; }
    await env.DB.prepare('INSERT INTO fails (ip, n, until) VALUES (?, ?, ?) ON CONFLICT(ip) DO UPDATE SET n = excluded.n, until = excluded.until').bind(key, n, until).run();
  }
}
// Token Cloudflare Access (hanya untuk penyediaan akaun pertama kali)
let certCache = null;
async function accessEmail(req, env){
  const jwt = req.headers.get('cf-access-jwt-assertion') || cookieOf(req, 'CF_Authorization');
  if(!jwt) return null;
  try {
    const [h, p, s] = jwt.split('.');
    const head = JSON.parse(new TextDecoder().decode(unb64url(h)));
    const body = JSON.parse(new TextDecoder().decode(unb64url(p)));
    if(head.alg !== 'RS256') return null;
    if(body.iss !== `https://${ACCESS_TEAM}.cloudflareaccess.com`) return null;
    if(!body.exp || body.exp * 1000 < Date.now()) return null;
    if(!certCache || certCache.at < Date.now() - 3600e3){
      const r = await fetch(`https://${ACCESS_TEAM}.cloudflareaccess.com/cdn-cgi/access/certs`);
      certCache = {at: Date.now(), keys: (await r.json()).keys || []};
    }
    const jwk = certCache.keys.find(k => k.kid === head.kid);
    if(!jwk) return null;
    const key = await crypto.subtle.importKey('jwk', jwk, {name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256'}, false, ['verify']);
    const ok = await crypto.subtle.verify('RSASSA-PKCS1-v1_5', key, unb64url(s), enc.encode(h + '.' + p));
    if(!ok) return null;
    const email = String(body.email || '').toLowerCase();
    const allowed = String(env.ALLOWED_EMAIL || '').split(',').map(x => x.trim().toLowerCase()).filter(Boolean);
    return allowed.includes(email) ? email : null;
  } catch(e){ return null; }
}
const PAGE_HEADERS = {'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store', 'x-frame-options': 'DENY', 'referrer-policy': 'same-origin',
  'content-security-policy': "default-src 'self'; script-src 'unsafe-inline'; style-src 'unsafe-inline' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"};

/* ---------------- Claude ---------------- */
async function countUsage(env){
  const day = todayLocal();
  await env.DB.prepare('INSERT INTO usage (day, n) VALUES (?, 1) ON CONFLICT(day) DO UPDATE SET n = n + 1').bind(day).run();
  const r = await env.DB.prepare('SELECT n FROM usage WHERE day = ?').bind(day).first();
  return r ? r.n : 1;
}
async function askClaude(env, {input, json, tier, images, maxTokens}){
  if(!env.ANTHROPIC_API_KEY) return {error: 'no_key', status: 503};
  const n = await countUsage(env);
  if(n > DAILY_CLAUDE_LIMIT) return {error: 'daily_limit', status: 429};
  const imgBlocks = (images || []).slice(0, 4)
    .filter(im => im && typeof im.data === 'string' && /^image\/(jpeg|png|webp|gif)$/.test(im.media_type))
    .map(im => ({type: 'image', source: {type: 'base64', media_type: im.media_type, data: im.data}}));
  let messages;
  if(typeof input === 'string') messages = [{role: 'user', content: [...imgBlocks, {type: 'text', text: input}]}];
  else if(Array.isArray(input) && input.length){
    messages = [];
    for(const m of input){
      const role = m.role === 'assistant' ? 'assistant' : 'user';
      const last = messages[messages.length - 1];
      if(last && last.role === role) last.content.push({type: 'text', text: String(m.content)});
      else messages.push({role, content: [{type: 'text', text: String(m.content)}]});
    }
    if(imgBlocks.length) messages[messages.length - 1].content.unshift(...imgBlocks);
  } else return {error: 'bad_input', status: 400};
  const body = {
    model: tier === 'complex' ? MODEL_COMPLEX : MODEL_QUICK,
    max_tokens: maxTokens || 2048,
    messages,
    system: 'Anda pembantu peribadi dalam aplikasi Hey Armay (sistem pengurusan diri) milik seorang pemilik perniagaan di Malaysia.' + (json ? ' Balas dengan SATU nilai JSON yang sah sahaja, tanpa teks lain dan tanpa blok kod.' : '')
  };
  const r = await fetch('https://api.anthropic.com/v1/messages', {
    method: 'POST',
    headers: {'x-api-key': env.ANTHROPIC_API_KEY, 'anthropic-version': '2023-06-01', 'content-type': 'application/json'},
    body: JSON.stringify(body)
  });
  if(!r.ok){
    const t = await r.text();
    return {error: 'upstream ' + r.status + ': ' + t.slice(0, 300), status: r.status === 429 ? 429 : 502};
  }
  const j = await r.json();
  const text = (j.content || []).filter(c => c.type === 'text').map(c => c.text).join('');
  return {text, truncated: j.stop_reason === 'max_tokens'};
}

/* ---------------- ringkasan berjadual ---------------- */
const EXP_CAT = {makan:'Makan & minum', transport:'Minyak & pengangkutan', dapur:'Barang dapur & rumah', bil:'Bil & langganan', keluarga:'Keluarga', kesihatan:'Kesihatan', belibelah:'Membeli-belah', hiburan:'Hiburan & riadah', perjalanan:'Pelancongan', sedekah:'Sedekah & zakat', kerja:'Kerja & peralatan', lain:'Lain-lain'};
function nextAnnual(s, t){
  if(!isYmd(s)) return null;
  const [, m, d] = s.split('-'); const y = Number(t.slice(0, 4));
  let n = `${y}-${m}-${d}`; if(n < t) n = `${y + 1}-${m}-${d}`;
  return {date: n, in: daysBetween(t, n)};
}
function morningLines(items, exps, t){
  const L = [], real = items.filter(i => !i.example), by = k => real.filter(i => i.kind === k);
  const ym = t.slice(0, 7), lastDay = new Date(Date.UTC(Number(t.slice(0, 4)), Number(t.slice(5, 7)), 0)).getUTCDate();
  by('event').filter(i => i.date === t).sort((a, b) => (a.start || '').localeCompare(b.start || '')).forEach(i => L.push(`Acara ${i.start || 'sepanjang hari'}: ${i.title}${i.place ? ' @ ' + i.place : ''}`));
  by('event').filter(i => i.date > t && i.date <= addDays(t, 2)).forEach(i => L.push(`Akan datang ${i.date} ${i.start || ''}: ${i.title}`));
  by('reminder').filter(i => !i.done && String(i.at || '').slice(0, 10) <= t).forEach(i => L.push(`Peringatan ${String(i.at).replace('T', ' ')}${String(i.at).slice(0, 10) < t ? ' (terlepas)' : ''}: ${i.title}`));
  by('task').filter(i => !i.done && ((i.due && i.due <= t) || i.priority === 'tinggi')).forEach(i => L.push(`Tugasan${i.priority === 'tinggi' ? ' [penting]' : ''}${i.due ? ' akhir ' + i.due + (i.due < t ? ' (LEWAT)' : '') : ''}: ${i.title}`));
  by('waiting').filter(i => !i.done && (i.expect ? i.expect <= t : (isYmd(i.since) && daysBetween(i.since, t) >= 3))).forEach(i => L.push(`Perlu kejar ${i.who || 'seseorang'}: ${i.title}`));
  by('payment').filter(i => !i.paid && i.due && i.due <= addDays(t, 3)).forEach(i => L.push(`Bayaran klien ${i.client} ${money(i.amount)} ${i.due < t ? 'LEWAT sejak' : 'perlu dibayar'} ${i.due}`));
  by('bill').filter(b => (b.cycle !== 'tahunan' || Number(b.month) === Number(t.slice(5, 7))) && !(b.paid && b.paid[ym])).forEach(b => { const d = `${ym}-${pad(Math.min(Math.max(Number(b.day) || 1, 1), lastDay))}`; if(d <= addDays(t, 3)) L.push(`Bil ${b.title} ${money(b.amount)} hari ke-${b.day}${d < t ? ' (lewat)' : ''}`); });
  by('renewal').filter(i => isYmd(i.date) && daysBetween(t, i.date) <= 14).forEach(i => L.push(`Tamat ${i.title} pada ${i.date}`));
  by('person').forEach(p => { for(const [k, w] of [['birthday', 'Hari lahir'], ['anniv', 'Ulang tahun']]){ const x = nextAnnual(p[k], t); if(x && x.in <= 7) L.push(`${w} ${p.name} dalam ${x.in} hari (${x.date})`); } });
  by('person').filter(p => Number(p.every) > 0 && (!isYmd(p.lastContact) || daysBetween(p.lastContact, t) >= Number(p.every))).slice(0, 2).forEach(p => L.push(`Lama tak hubungi ${p.name}${p.rel ? ' (' + p.rel + ')' : ''}`));
  by('gift').filter(g => !g.done && isYmd(g.date) && g.date <= addDays(t, 7)).forEach(g => L.push(`${g.type || 'Majlis'}: ${g.title} pada ${g.date}`));
  const h = by('habit').map(x => x.title); if(h.length) L.push(`Tabiat harian: ${h.join(', ')}`);
  const sp = exps.filter(e => !e.example && String(e.date || '').slice(0, 7) === ym && e.scope !== 'bisnes').reduce((s, e) => s + (Number(e.amount) || 0), 0);
  const bud = items.find(i => i.id === 'cfg-budget');
  if(bud && Number(bud.total) > 0) L.push(`Belanja peribadi bulan ini ${money(sp)} daripada bajet ${money(bud.total)} (${Math.round(sp / bud.total * 100)}%)`);
  return L;
}
function weeklyLines(items, exps, t){
  const L = [], real = items.filter(i => !i.example), by = k => real.filter(i => i.kind === k);
  const from = addDays(t, -6), to = addDays(t, 7);
  const inLast = ms => { if(!ms) return false; const d = ymdOf(new Date(Number(ms) + TZ_OFFSET_MIN * 60000)); return d >= from && d <= t; };
  by('task').filter(i => i.done && inLast(i.doneAt)).forEach(i => L.push(`SIAP: ${i.title}`));
  by('task').filter(i => !i.done && i.due && i.due < t).forEach(i => L.push(`LEWAT: ${i.title} (akhir ${i.due})`));
  by('waiting').filter(i => i.done && inLast(i.doneAt)).forEach(i => L.push(`DITERIMA: ${i.title}`));
  by('waiting').filter(i => !i.done && (i.expect ? i.expect < t : (isYmd(i.since) && daysBetween(i.since, t) > 3))).forEach(i => L.push(`MENUNGGU ${i.who || ''}: ${i.title}`));
  by('payment').filter(i => i.paid && inLast(i.paidAt)).forEach(i => L.push(`BAYARAN DITERIMA: ${i.client} ${money(i.amount)}`));
  const owed = by('payment').filter(i => !i.paid); if(owed.length) L.push(`TERTUNGGAK: ${owed.length} invois, ${money(owed.reduce((s, i) => s + (Number(i.amount) || 0), 0))}`);
  by('habit').forEach(h => { let n = 0; for(let k = 0; k < 7; k++) if(h.log && h.log[addDays(t, -k)]) n++; L.push(`TABIAT ${h.title}: ${n}/7 hari`); });
  by('goal').forEach(g => L.push(`MATLAMAT ${g.title}: ${Number(g.progress) || 0}%`));
  by('event').filter(i => i.date > t && i.date <= to).forEach(i => L.push(`MINGGU DEPAN ${i.date} ${i.start || ''}: ${i.title}`));
  by('task').filter(i => !i.done && i.due && i.due >= t && i.due <= to).forEach(i => L.push(`AKHIR MINGGU DEPAN ${i.due}: ${i.title}`));
  by('renewal').filter(i => isYmd(i.date) && i.date <= addDays(t, 30)).forEach(i => L.push(`TAMAT ${i.date}: ${i.title}`));
  const sp = exps.filter(e => !e.example && e.date >= from && e.date <= t);
  if(sp.length){
    const bc = {}; sp.forEach(e => { const k = EXP_CAT[e.cat] || 'Lain-lain'; bc[k] = (bc[k] || 0) + (Number(e.amount) || 0); });
    L.push(`BELANJA 7 HARI: ${money(sp.reduce((s, e) => s + (Number(e.amount) || 0), 0))} (peribadi ${money(sp.filter(e => e.scope !== 'bisnes').reduce((s, e) => s + (Number(e.amount) || 0), 0))}, bisnes ${money(sp.filter(e => e.scope === 'bisnes').reduce((s, e) => s + (Number(e.amount) || 0), 0))}); terbanyak: ${Object.entries(bc).sort((a, b) => b[1] - a[1]).slice(0, 3).map(([k, v]) => k + ' ' + money(v)).join(', ')}`);
  }
  return L;
}
const HARI = ['Ahad', 'Isnin', 'Selasa', 'Rabu', 'Khamis', 'Jumaat', 'Sabtu'];
async function makeDigest(env, kind){
  await ensureSchema(env);
  const t = todayLocal(), d = nowLocal();
  const items = await allDocs(env, 'items');
  const exps = (await allDocs(env, 'belanja')).map(x => ({id: x.id, ...x.data}));
  const flat = items.map(x => ({id: x.id, ...x.data}));
  const lines = kind === 'minggu' ? weeklyLines(flat, exps, t) : morningLines(flat, exps, t);
  if(kind !== 'minggu' && env.ARMEDIA_DB){ try { lines.push(...teamLines(await armediaFeed(env, t, t), t)); } catch(e){} }
  const prompt = kind === 'minggu'
    ? `Sekarang ${HARI[d.getUTCDay()]}, ${t}. Tulis semakan mingguan dalam Bahasa Melayu santai dengan empat bahagian bertajuk ringkas: "Minggu ini" (2-3 baris apa yang berjaya), "Belanja" (1-2 baris), "Tersangkut" (poin "• "), dan "3 keutamaan minggu depan" (bernombor). Maksimum 17 baris. Jangan reka maklumat yang tiada dalam data.\n\nData:\n${lines.join('\n') || '(tiada data minggu ini)'}`
    : `Sekarang ${HARI[d.getUTCDay()]}, ${t}, pagi. Tulis ringkasan pagi dalam Bahasa Melayu santai, maksimum 10 baris: satu baris salam pagi dengan tarikh, kemudian poin "• " disusun ikut paling mendesak dahulu (sebut masa jika ada), dan akhiri dengan satu cadangan apa nak buat dulu. Jangan reka maklumat. Jika senarai kosong, kata hari ini lapang dalam 2 baris.\n\nSenarai:\n${lines.join('\n') || '(kosong)'}`;
  let text;
  const r = await askClaude(env, {input: prompt, tier: 'default', maxTokens: 1200});
  if(r.text) text = r.text.trim();
  else text = (kind === 'minggu' ? 'Semakan mingguan' : 'Ringkasan pagi') + ` ${t}\n` + (lines.length ? lines.map(l => '• ' + l).join('\n') : 'Tiada apa-apa dalam senarai.');
  await setMeta(env, 'digest_' + kind, JSON.stringify({date: t, text, created: Date.now()}));
  return text;
}


/* ---------------- ARMEDIA (baca sahaja dari armedia-db melalui binding ARMEDIA_DB) ---------------- */
// Hanya SELECT. Data pengguna ARMEDIA dibaca setakat id + nama sahaja.
async function armediaFeed(env, from, to){
  const db = env.ARMEDIA_DB;
  if(!db) return {connected: false};
  const back = addDays(from, -30);
  const [jr, ur, lr] = await Promise.all([
    db.prepare(`SELECT id, data FROM records WHERE type = 'job' AND (
        json_extract(data, '$.shoot_date') BETWEEN ?1 AND ?2
        OR (substr(IFNULL(json_extract(data, '$.deadline'), ''), 1, 10) BETWEEN ?3 AND ?2 AND IFNULL(json_extract(data, '$.status'), '') <> 'Dipost'))`).bind(from, to, back).all(),
    db.prepare(`SELECT id, json_extract(data, '$.name') AS name FROM records WHERE type = 'user'`).all(),
    db.prepare(`SELECT json_extract(data, '$.staff_id') AS sid, json_extract(data, '$.from') AS f, json_extract(data, '$.to') AS t,
        json_extract(data, '$.type') AS ty, json_extract(data, '$.half_day') AS h FROM records
        WHERE type = 'leave' AND json_extract(data, '$.status') = 'Lulus' AND json_extract(data, '$.from') <= ?2 AND json_extract(data, '$.to') >= ?1`).bind(from, to).all()
  ]);
  const names = new Map((ur.results || []).map(u => [u.id, u.name || '']));
  const nm = id => names.get(id) || '';
  const str = v => (v == null ? '' : String(v)).slice(0, 300);
  const jobs = [];
  for(const r of jr.results || []){
    let j; try { j = JSON.parse(r.data); } catch(e){ continue; }
    if(!j || j.deleted || j.archived) continue;
    const rev = Array.isArray(j.reviewer_ids) && j.reviewer_ids.length ? j.reviewer_ids : j.reviewer_id ? [j.reviewer_id] : [];
    const chs = j.channel ? [{ch: j.channel, editor_id: j.editor_id || ''}] : Array.isArray(j.channels) ? j.channels : [];
    jobs.push({
      id: r.id, shoot: j.shoot_id || r.id, title: str(j.title), date: str(j.shoot_date), time: str(j.shoot_time), location: str(j.location),
      status: str(j.status), urgent: !!j.urgent, deadline: str(j.deadline), kind: str(j.kind),
      reviewers: rev.map(nm).filter(Boolean), editor: nm(j.editor_id),
      channels: chs.map(c => ({ch: str(c.ch), editor: nm(c.editor_id)}))
    });
  }
  const leaves = (lr.results || []).map(l => ({name: nm(l.sid), from: str(l.f), to: str(l.t), type: str(l.ty), half: !!l.h})).filter(l => l.name);
  return {connected: true, from, to, jobs, leaves, at: Date.now()};
}
function teamLines(feed, t){
  if(!feed || !feed.connected) return [];
  const L = [], seen = new Set(), titles = [];
  feed.jobs.filter(j => j.date === t).sort((a, b) => a.time.localeCompare(b.time)).forEach(j => {
    if(seen.has(j.shoot)) return; seen.add(j.shoot); titles.push((j.time ? j.time + ' ' : '') + j.title);
  });
  L.push(titles.length ? `Job team hari ini (${titles.length}): ${titles.join('; ')}` : 'Tiada job team hari ini');
  const CHECK = ['Tunggu approval client', 'Sedia untuk post'];
  const late = feed.jobs.filter(j => j.deadline && j.status !== 'Dipost' && !CHECK.includes(j.status) && j.deadline.slice(0, 10) < t);
  if(late.length) L.push(`Video team lewat deadline: ${late.length} (semak dalam armedia.my)`);
  return L;
}

/* ---------------- halaman log masuk & akaun ---------------- */
const PAGE_CSS = `
@property --ang{syntax:'<angle>';inherits:false;initial-value:0deg}
:root,:root[data-hy="light"]{--bg:#EDF0F8;--card:rgba(255,255,255,.82);--field:rgba(244,246,252,.95);--ink:#11152B;--muted:#5B6385;--line:rgba(36,48,110,.13);--accent:#0C8F80;--on-accent:#FFFFFF;
  --rose:#C53352;--rose-soft:#FBE3E8;--accent-soft:rgba(13,148,136,.10);--glow:13,148,136;--glow2:94,79,230;--lineRGB:36,48,110;
  --aurA:rgba(45,212,191,.26);--aurB:rgba(124,108,247,.22);--aurC:rgba(96,165,250,.20);--gridline:rgba(40,60,150,.055);--cardshadow:0 30px 70px rgba(30,40,100,.16);
  --grad:linear-gradient(120deg,#0D9488 0%,#3E7BEA 55%,#6A54EC 100%);color-scheme:light}
:root[data-hy="dark"]{--bg:#080B1C;--card:rgba(17,21,47,.92);--field:rgba(128,146,255,.07);--ink:#E8ECFF;--muted:#8D95C6;--line:rgba(150,170,255,.16);--accent:#5EEAD4;--on-accent:#04201B;
  --rose:#FF7D96;--rose-soft:rgba(255,125,150,.14);--accent-soft:rgba(94,234,212,.13);--glow:94,234,212;--glow2:156,142,255;--lineRGB:150,170,255;
  --aurA:rgba(94,234,212,.18);--aurB:rgba(156,142,255,.22);--aurC:rgba(121,189,255,.12);--gridline:rgba(150,170,255,.06);--cardshadow:0 30px 80px rgba(0,0,0,.55);
  --grad:linear-gradient(120deg,#5EEAD4 0%,#86B4FF 55%,#9C8EFF 100%);color-scheme:dark}
:root{--ease:cubic-bezier(.2,.8,.2,1)}
*{box-sizing:border-box}
html{background:var(--bg)}
body{margin:0;min-height:100%;color:var(--ink);font:16px/1.5 'Geist',-apple-system,system-ui,"Segoe UI",Roboto,sans-serif;-webkit-font-smoothing:antialiased}
body::before{content:"";position:fixed;inset:-25%;z-index:-2;pointer-events:none;
  background:radial-gradient(38% 32% at 18% 14%,var(--aurA),transparent 70%),radial-gradient(34% 30% at 86% 8%,var(--aurB),transparent 70%),radial-gradient(44% 38% at 62% 96%,var(--aurC),transparent 70%);
  animation:drift 46s ease-in-out infinite alternate}
body::after{content:"";position:fixed;inset:0;z-index:-1;pointer-events:none;opacity:.6;
  background-image:linear-gradient(var(--gridline) 1px,transparent 1px),linear-gradient(90deg,var(--gridline) 1px,transparent 1px);background-size:56px 56px;
  -webkit-mask-image:radial-gradient(60% 55% at 50% 45%,#000 10%,transparent 75%);mask-image:radial-gradient(60% 55% at 50% 45%,#000 10%,transparent 75%)}
main{min-height:100vh;display:grid;place-items:center;padding:24px 16px calc(24px + env(safe-area-inset-bottom))}
.card{position:relative;width:100%;max-width:390px;border-radius:22px;padding:30px 24px;border:1px solid transparent;
  background:linear-gradient(var(--card),var(--card)) padding-box,conic-gradient(from var(--ang),rgb(var(--glow)),#86B4FF,rgb(var(--glow2)),rgba(var(--glow),.12),rgb(var(--glow))) border-box;
  box-shadow:var(--cardshadow);-webkit-backdrop-filter:blur(16px);backdrop-filter:blur(16px);
  animation:spin 9s linear infinite,rise .7s var(--ease) both}
.brand{display:flex;align-items:center;gap:12px;margin-bottom:26px}
.brand .logo{display:block;height:46px;aspect-ratio:2857/1197;background:var(--ink);-webkit-mask:url(/logo.png) left center/contain no-repeat;mask:url(/logo.png) left center/contain no-repeat}
.brand b{font-weight:650;font-size:1.02rem;letter-spacing:-.02em}.brand small{display:block;color:var(--muted);font-size:.8rem;font-weight:400}
h1{font-weight:650;font-size:1.6rem;line-height:1.2;margin:0 0 8px;letter-spacing:-.025em}
p.lead{margin:0 0 20px;color:var(--muted);font-size:.93rem}
label{display:block;font-size:.85rem;font-weight:600;margin:16px 0 6px;color:var(--muted)}
.f{position:relative}
input{width:100%;font:inherit;color:inherit;background:var(--field);border:1px solid var(--line);border-radius:12px;padding:13px 14px;outline:none;transition:border-color .18s,box-shadow .18s}
input::placeholder{color:var(--muted);opacity:.75}
input:focus{border-color:var(--accent);box-shadow:0 0 0 3px rgba(var(--glow),.15)}
.f input{padding-right:70px}
.eye{position:absolute;right:6px;top:50%;transform:translateY(-50%);border:0;background:none;color:var(--muted);font:inherit;font-size:.8rem;font-weight:600;padding:8px;cursor:pointer}
.eye:hover{color:var(--accent)}
button.go{width:100%;margin-top:24px;border:0;border-radius:12px;background:var(--grad);color:var(--on-accent);font:inherit;font-weight:700;padding:14px;cursor:pointer;transition:box-shadow .2s,transform .12s var(--ease)}
button.go:hover{box-shadow:0 0 26px rgba(var(--glow),.35)}
button.go:active{transform:scale(.98)}
button.go:disabled{opacity:.75;cursor:progress;background-size:200% 100%;animation:shimmer 1.2s linear infinite}
button.ghost{width:100%;margin-top:10px;border:1px solid var(--line);border-radius:12px;background:transparent;color:var(--ink);font:inherit;font-weight:600;padding:13px;cursor:pointer}
button.ghost:hover{border-color:var(--rose);color:var(--rose)}
.err{display:none;margin-top:14px;background:var(--rose-soft);color:var(--rose);border:1px solid rgba(197,51,82,.25);border-radius:12px;padding:10px 12px;font-size:.88rem;animation:rise .3s var(--ease) both}
.ok{display:none;margin-top:14px;background:var(--accent-soft);color:var(--accent);border:1px solid rgba(var(--glow),.3);border-radius:12px;padding:10px 12px;font-size:.88rem;animation:rise .3s var(--ease) both}
.hint{color:var(--muted);font-size:.8rem;margin-top:6px}
a{color:var(--accent);font-weight:600;text-decoration:none}
hr{border:0;border-top:1px solid var(--line);margin:26px 0 8px}
:focus-visible{outline:2px solid var(--accent);outline-offset:2px}
@keyframes spin{to{--ang:360deg}}
@keyframes rise{from{opacity:0;transform:translateY(14px)}to{opacity:1;transform:none}}
@keyframes drift{0%{transform:translate3d(0,0,0) scale(1)}50%{transform:translate3d(3%,-2%,0) scale(1.06)}100%{transform:translate3d(-2%,3%,0) scale(1)}}
@keyframes shimmer{to{background-position:-200% 0}}
@media (prefers-reduced-motion:reduce){*,*::before,*::after{animation:none!important;transition:none!important}}`;
const PAGE_JS = `
const $ = s => document.querySelector(s);
async function derive(user, pass){
  const e = new TextEncoder();
  const k = await crypto.subtle.importKey('raw', e.encode(pass), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits({name:'PBKDF2', hash:'SHA-256', salt:e.encode('heyarmay.com|' + user.trim().toLowerCase()), iterations:310000}, k, 256);
  return btoa(String.fromCharCode(...new Uint8Array(bits)));
}
async function post(path, body){
  const r = await fetch(path, {method:'POST', headers:{'content-type':'application/json'}, credentials:'same-origin', body:JSON.stringify(body)});
  let j = {}; try { j = await r.json(); } catch(e){}
  return {status:r.status, ...j};
}
function showErr(msg){ const e = $('.err'); e.textContent = msg; e.style.display = msg ? 'block' : 'none'; }
document.querySelectorAll('.eye').forEach(b => b.addEventListener('click', () => {
  const i = b.previousElementSibling; const show = i.type === 'password';
  i.type = show ? 'text' : 'password'; b.textContent = show ? 'Sorok' : 'Tunjuk';
}));`;
const pageShell = (title, body, script) => `<!doctype html><html lang="ms"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover"><meta name="theme-color" content="#EDF0F8">
<link rel="manifest" href="/manifest.webmanifest"><link rel="icon" href="/favicon.png?v=3" type="image/png"><link rel="apple-touch-icon" href="/apple-touch-icon.png?v=3">
<meta name="apple-mobile-web-app-capable" content="yes"><meta name="apple-mobile-web-app-title" content="Hey Armay">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin><link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Geist:wght@400;500;600;700&family=Geist+Mono:wght@500&display=swap">
<title>${title}</title><script>(function(){var t;try{t=localStorage.getItem("hy-theme")}catch(e){}document.documentElement.setAttribute("data-hy",t==="dark"?"dark":"light");})();</script><style>${PAGE_CSS}</style></head><body><main><div class="card">
<div class="brand"><span class="logo" role="img" aria-label="Hey Armay"></span></div>
${body}</div></main><script>${PAGE_JS}${script}</script></body></html>`;
const pwField = (id, ac, label) => `<label for="${id}">${label}</label><div class="f"><input id="${id}" type="password" autocomplete="${ac}" required><button type="button" class="eye">Tunjuk</button></div>`;
function authPage(mode){
  if(mode === 'closed') return pageShell('Log masuk', `<h1>Akaun belum disediakan</h1>
<p class="lead">ID dan kata laluan belum dicipta lagi. Penyediaan pertama hanya boleh dibuat oleh pemilik melalui log masuk Cloudflare Access.</p>`, '');
  const setup = mode === 'setup';
  return pageShell(setup ? 'Cipta log masuk' : 'Log masuk', `<h1>${setup ? 'Cipta log masuk' : 'Log masuk'}</h1>
<p class="lead">${setup ? 'Pilih ID dan kata laluan. Lepas ini, anda akan log masuk dengan ID dan kata laluan ini sahaja.' : 'Masukkan ID dan kata laluan anda.'}</p>
<form id="f" novalidate>
<label for="u">ID</label><input id="u" name="username" autocomplete="username" autocapitalize="none" spellcheck="false" required ${setup ? 'placeholder="contoh: armay"' : ''}>
${setup ? '<div class="hint">3–40 aksara: huruf, nombor, titik, sengkang atau @.</div>' : ''}
${pwField('p', setup ? 'new-password' : 'current-password', 'Kata laluan')}
${setup ? '<div class="hint">Sekurang-kurangnya 8 aksara.</div>' + pwField('p2', 'new-password', 'Ulang kata laluan') : ''}
<button class="go" type="submit">${setup ? 'Cipta & masuk' : 'Log masuk'}</button>
<div class="err" role="alert"></div></form>`, `
const SETUP = ${setup};
$('#f').addEventListener('submit', async ev => {
  ev.preventDefault(); showErr('');
  const u = $('#u').value.trim().toLowerCase(), p = $('#p').value;
  if(!u || !p) return showErr('Isi ID dan kata laluan.');
  if(SETUP){
    if(!/^[a-z0-9._@-]{3,40}$/.test(u)) return showErr('ID mesti 3–40 aksara: huruf, nombor, titik, sengkang atau @.');
    if(p.length < 8) return showErr('Kata laluan mesti sekurang-kurangnya 8 aksara.');
    if(p !== $('#p2').value) return showErr('Kata laluan tak sama. Taip semula.');
  }
  const btn = $('.go'); btn.disabled = true; btn.textContent = 'Sebentar…';
  try {
    const r = await post(SETUP ? '/api/auth/setup' : '/api/auth/login', {user:u, key:await derive(u, p)});
    if(r.ok){ location.reload(); return; }
    showErr(r.error === 'locked' ? 'Terlalu banyak cubaan salah. Cuba lagi selepas 15 minit.'
      : r.error === 'wrong' ? 'ID atau kata laluan salah.'
      : r.error === 'access' ? 'Penyediaan perlu log masuk Cloudflare Access. Muat semula halaman.'
      : r.error === 'exists' ? 'Akaun sudah wujud. Muat semula untuk log masuk.'
      : 'Tak berjaya. Cuba lagi.');
  } catch(e){ showErr('Tiada sambungan. Cuba lagi.'); }
  btn.disabled = false; btn.textContent = SETUP ? 'Cipta & masuk' : 'Log masuk';
});
$('#u').focus();`);
}
function accountPage(user){
  const safe = String(user).replace(/[^a-z0-9._@-]/g, '');
  return pageShell('Akaun', `<a href="/">← Kembali</a>
<h1 style="margin-top:14px">Akaun</h1><p class="lead">Log masuk sebagai <b>${safe}</b></p>
<form id="f" novalidate>
<input type="text" name="username" autocomplete="username" value="${safe}" hidden>
${pwField('o', 'current-password', 'Kata laluan semasa')}
${pwField('n', 'new-password', 'Kata laluan baru')}
${pwField('n2', 'new-password', 'Ulang kata laluan baru')}
<button class="go" type="submit">Tukar kata laluan</button>
<div class="err" role="alert"></div><div class="ok" role="status"></div></form>
<hr><button class="ghost" id="out" type="button">Log keluar</button>`, `
const USER = ${JSON.stringify(safe)};
$('#f').addEventListener('submit', async ev => {
  ev.preventDefault(); showErr(''); $('.ok').style.display = 'none';
  const o = $('#o').value, n = $('#n').value;
  if(n.length < 8) return showErr('Kata laluan baru mesti sekurang-kurangnya 8 aksara.');
  if(n !== $('#n2').value) return showErr('Kata laluan baru tak sama. Taip semula.');
  const btn = $('.go'); btn.disabled = true; btn.textContent = 'Sebentar…';
  try {
    const r = await post('/api/auth/password', {old:await derive(USER, o), key:await derive(USER, n)});
    if(r.ok){ ev.target.reset(); const k = $('.ok'); k.textContent = 'Kata laluan ditukar. Peranti lain telah dilog keluar.'; k.style.display = 'block'; }
    else showErr(r.error === 'wrong' ? 'Kata laluan semasa salah.' : r.error === 'locked' ? 'Terlalu banyak cubaan salah. Cuba lagi selepas 15 minit.' : 'Tak berjaya. Cuba lagi.');
  } catch(e){ showErr('Tiada sambungan. Cuba lagi.'); }
  btn.disabled = false; btn.textContent = 'Tukar kata laluan';
});
$('#out').addEventListener('click', async () => { await post('/api/auth/logout', {}); location.href = '/'; });`);
}

/* ---------------- router ---------------- */
async function handle(req, env, ctx){
  const url = new URL(req.url), p = url.pathname, m = req.method;

  // Pautan ringkasan untuk notifikasi Claude app (tanpa log masuk, hanya teks ringkasan)
  const dg = p.match(/^\/r\/([a-z0-9]{20,64})\/(pagi|minggu)$/);
  if(dg){
    await ensureSchema(env);
    const key = await getMeta(env, 'digest_key');
    if(!key || key !== dg[1]) return T('Tidak dijumpai', 404);
    const kind = dg[2];
    let row = await getMeta(env, 'digest_' + kind);
    let d = row ? JSON.parse(row) : null;
    if(!d || d.date !== todayLocal()) d = {date: todayLocal(), text: await makeDigest(env, kind)};
    return T(d.text + '\n\nBuka: https://heyarmay.com' + (kind === 'minggu' ? '/#semakan' : '/'));
  }

  const PNGS = {'/icon-mask-192.png': ICON_MASK_192, '/icon-mask-512.png': ICON_MASK_512, '/favicon.png': ICON_64, '/favicon.svg': ICON_64, '/icon.svg': ICON_64, '/apple-touch-icon.png': ICON_180, '/logo.png': LOGO_PNG};
  if(PNGS[p]){
    const bin = Uint8Array.from(atob(PNGS[p]), c => c.charCodeAt(0));
    return new Response(bin, {headers: {'content-type': 'image/png', 'cache-control': 'public, max-age=3600'}});
  }
  if(p === '/manifest.webmanifest') return new Response(MANIFEST, {headers: {'content-type': 'application/manifest+json'}});
  if(p === '/icon-192.png' || p === '/icon-512.png') {
    const b64 = p === '/icon-512.png' ? ICON_512 : ICON_192;
    const bin = Uint8Array.from(atob(b64), c => c.charCodeAt(0));
    return new Response(bin, {headers: {'content-type': 'image/png', 'cache-control': 'public, max-age=86400'}});
  }

  await ensureSchema(env);
  if(!['GET', 'HEAD'].includes(m)){
    const o = req.headers.get('origin');
    if(o && o !== url.origin) return J({error: 'origin'}, 403);
  }
  const ip = req.headers.get('cf-connecting-ip') || 'tiada';

  // Log masuk / penyediaan akaun
  if(p === '/api/auth/login' && m === 'POST'){
    const auth = await getAuth(env);
    if(!auth) return J({error: 'no_account'}, 409);
    if(await lockedOut(env, ip)) return J({error: 'locked'}, 429);
    const b = await req.json().catch(() => null) || {};
    let ok = false;
    if(validKey(b.key)) ok = sameBytes(await serverHash(b.key, auth.salt, auth.iter), unb64(auth.hash)) && normId(b.user) === auth.user;
    if(!ok){ await noteFail(env, ip); return J({error: 'wrong'}, 401); }
    return J({ok: true}, 200, {'set-cookie': setCookie(await newSession(env))});
  }
  if(p === '/api/auth/setup' && m === 'POST'){
    if(await getAuth(env)) return J({error: 'exists'}, 409);
    if(!await accessEmail(req, env)) return J({error: 'access'}, 403);
    const b = await req.json().catch(() => null) || {};
    const user = normId(b.user);
    if(!validId(user)) return J({error: 'id'}, 400);
    if(!validKey(b.key)) return J({error: 'key'}, 400);
    await setPassword(env, user, b.key);
    return J({ok: true}, 200, {'set-cookie': setCookie(await newSession(env))});
  }
  if(!await sessionOk(req, env)){
    if(p.startsWith('/api/') || p.startsWith('/_blob/')) return J({error: 'login'}, 401);
    if(m !== 'GET' && m !== 'HEAD') return T('Log masuk dahulu', 401);
    const auth = await getAuth(env);
    const mode = auth ? 'login' : (await accessEmail(req, env)) ? 'setup' : 'closed';
    return new Response(authPage(mode), {headers: PAGE_HEADERS});
  }
  if(p === '/api/auth/logout' && m === 'POST'){
    const token = cookieOf(req, COOKIE);
    await env.DB.prepare('DELETE FROM sessions WHERE h = ?').bind(await sha256(token)).run();
    return J({ok: true}, 200, {'set-cookie': clearCookie()});
  }
  if(p === '/api/auth/password' && m === 'POST'){
    const auth = await getAuth(env);
    if(await lockedOut(env, ip)) return J({error: 'locked'}, 429);
    const b = await req.json().catch(() => null) || {};
    if(!validKey(b.old) || !validKey(b.key)) return J({error: 'key'}, 400);
    if(!sameBytes(await serverHash(b.old, auth.salt, auth.iter), unb64(auth.hash))){ await noteFail(env, ip); return J({error: 'wrong'}, 400); }
    await setPassword(env, auth.user, b.key);
    await env.DB.prepare('DELETE FROM sessions').run();
    return J({ok: true}, 200, {'set-cookie': setCookie(await newSession(env))});
  }
  if(p === '/akaun' && m === 'GET') return new Response(accountPage((await getAuth(env)).user), {headers: PAGE_HEADERS});

  // Kemas kini paparan aplikasi tanpa tampal semula kod Worker (log masuk diperlukan)
  if(p === '/api/admin/app' && m === 'PUT'){
    const html = await req.text();
    if(html.length < 1000 || html.length > 1500 * 1024 || !/^<!doctype html>/i.test(html)) return J({error: 'html'}, 400);
    await setMeta(env, 'app_html', html); await setMeta(env, 'app_html_at', String(Date.now()));
    return J({ok: true, bytes: html.length});
  }
  if(p === '/api/admin/app' && m === 'DELETE'){ await env.DB.prepare("DELETE FROM meta WHERE k IN ('app_html','app_html_at')").run(); return J({ok: true}); }
  if(p === '/' || p === '/index.html'){
    const custom = url.searchParams.has('asal') ? null : await getMeta(env, 'app_html');
    return new Response(custom || APP_HTML, {headers: {'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store', 'x-frame-options': 'DENY', 'referrer-policy': 'same-origin'}});
  }

  // Data
  if(p === '/api/docs' && m === 'GET'){
    const coll = url.searchParams.get('coll') || '';
    if(!SEG.test(coll)) return J({error: 'coll'}, 400);
    let rows = await allDocs(env, coll);
    for(const [k, v] of url.searchParams){
      if(k.startsWith('gte_')){ const f = k.slice(4); rows = rows.filter(r => String(r.data[f] ?? '') >= v); }
      if(k.startsWith('eq_')){ const f = k.slice(3); rows = rows.filter(r => String(r.data[f] ?? '') === v); }
    }
    return J(rows);
  }
  const dm = p.match(/^\/api\/docs\/([^/]+)\/([^/]+)$/);
  if(dm){
    const coll = decodeURIComponent(dm[1]), id = decodeURIComponent(dm[2]);
    if(!SEG.test(coll) || !SEG.test(id)) return J({error: 'path'}, 400);
    if(m === 'PUT' || m === 'PATCH'){
      const raw = await req.text();
      if(raw.length > 256 * 1024) return J({error: 'too_large'}, 413);
      let body; try { body = JSON.parse(raw); } catch(e){ return J({error: 'json'}, 400); }
      if(!isObj(body)) return J({error: 'object'}, 400);
      let data = body;
      if(m === 'PATCH'){
        const cur = await env.DB.prepare('SELECT data FROM docs WHERE coll = ? AND id = ?').bind(coll, id).first();
        if(!cur) return J({error: 'missing'}, 404);
        data = deepMerge(JSON.parse(cur.data), body);
      }
      await env.DB.prepare('INSERT INTO docs (coll, id, data, updated) VALUES (?, ?, ?, ?) ON CONFLICT(coll, id) DO UPDATE SET data = excluded.data, updated = excluded.updated')
        .bind(coll, id, JSON.stringify(data), Date.now()).run();
      return J({ok: true});
    }
    if(m === 'DELETE'){ await env.DB.prepare('DELETE FROM docs WHERE coll = ? AND id = ?').bind(coll, id).run(); return new Response(null, {status: 204}); }
  }
  if(p === '/api/import' && m === 'POST'){
    const body = await req.json().catch(() => null);
    if(!body || !Array.isArray(body.docs)) return J({error: 'docs'}, 400);
    let n = 0;
    for(const d of body.docs){
      if(!d || !SEG.test(d.coll || '') || !SEG.test(d.id || '') || !isObj(d.data)) continue;
      await env.DB.prepare('INSERT INTO docs (coll, id, data, updated) VALUES (?, ?, ?, ?) ON CONFLICT(coll, id) DO UPDATE SET data = excluded.data, updated = excluded.updated')
        .bind(d.coll, d.id, JSON.stringify(d.data), Date.now()).run();
      n++;
    }
    return J({imported: n});
  }
  if(p === '/api/export' && m === 'GET'){
    const r = await env.DB.prepare('SELECT coll, id, data FROM docs').all();
    return J({exported: new Date().toISOString(), docs: (r.results || []).map(x => ({coll: x.coll, id: x.id, data: JSON.parse(x.data)}))}, 200, {'content-disposition': `attachment; filename="heyarmay-sandaran-${todayLocal()}.json"`});
  }

  // Jadual team ARMEDIA (baca sahaja)
  if(p === '/api/armedia' && m === 'GET'){
    const from = url.searchParams.get('from') || todayLocal(), to = url.searchParams.get('to') || addDays(from, 30);
    if(!isYmd(from) || !isYmd(to) || to < from || daysBetween(from, to) > 120) return J({error: 'range'}, 400);
    try { return J(await armediaFeed(env, from, to)); }
    catch(e){ return J({connected: false, error: 'db', message: String(e && e.message || e).slice(0, 200)}, 200); }
  }

  // Gambar resit
  if(p === '/api/files' && m === 'POST'){
    const type = (req.headers.get('content-type') || '').split(';')[0].trim();
    if(!/^image\/(jpeg|png|webp|gif)$/.test(type)) return J({error: 'type'}, 415);
    const buf = await req.arrayBuffer();
    if(!buf.byteLength) return J({error: 'empty'}, 400);
    if(buf.byteLength > 1800 * 1024) return J({error: 'too_large'}, 413);
    const id = randomKey();
    await env.DB.prepare('INSERT INTO files (id, type, data, created) VALUES (?, ?, ?, ?)').bind(id, type, buf, Date.now()).run();
    return J({id, size: buf.byteLength});
  }
  const fm = p.match(/^\/(?:_blob|api\/files)\/([a-z0-9]{10,64})$/);
  if(fm){
    if(m === 'GET'){
      const r = await env.DB.prepare('SELECT type, data FROM files WHERE id = ?').bind(fm[1]).first();
      if(!r) return T('Tidak dijumpai', 404);
      return new Response(r.data, {headers: {'content-type': r.type, 'cache-control': 'private, max-age=86400'}});
    }
    if(m === 'DELETE'){ await env.DB.prepare('DELETE FROM files WHERE id = ?').bind(fm[1]).run(); return new Response(null, {status: 204}); }
  }

  // Claude
  if(p === '/api/claude' && m === 'POST'){
    const raw = await req.text();
    if(raw.length > 12 * 1024 * 1024) return J({error: 'too_large'}, 413);
    let body; try { body = JSON.parse(raw); } catch(e){ return J({error: 'json'}, 400); }
    const r = await askClaude(env, {input: body.input, json: !!body.json, tier: body.tier, images: body.images});
    if(r.error) return J({error: r.error}, r.status || 502);
    return J(r);
  }

  // Tetapan: pautan ringkasan & penggunaan
  if(p === '/api/settings' && m === 'GET'){
    let key = await getMeta(env, 'digest_key');
    if(!key){ key = randomKey(); await setMeta(env, 'digest_key', key); }
    const u = await env.DB.prepare('SELECT n FROM usage WHERE day = ?').bind(todayLocal()).first();
    return J({digestPagi: `${url.origin}/r/${key}/pagi`, digestMinggu: `${url.origin}/r/${key}/minggu`, claudeToday: u ? u.n : 0, claudeLimit: DAILY_CLAUDE_LIMIT, hasKey: !!env.ANTHROPIC_API_KEY});
  }
  if(p === '/api/settings/rotate' && m === 'POST'){ const key = randomKey(); await setMeta(env, 'digest_key', key); return J({ok: true}); }

  return T('Tidak dijumpai', 404);
}

export default {
  async fetch(req, env, ctx){
    try { return await handle(req, env, ctx); }
    catch(e){ return J({error: 'server', message: String(e && e.message || e)}, 500); }
  },
  async scheduled(event, env, ctx){
    const kind = event.cron && event.cron.trim().endsWith('SUN') ? 'minggu' : 'pagi';
    ctx.waitUntil(makeDigest(env, kind));
  }
};
