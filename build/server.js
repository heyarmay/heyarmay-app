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
  `CREATE TABLE IF NOT EXISTS fails (ip TEXT PRIMARY KEY, n INTEGER NOT NULL, until INTEGER NOT NULL)`,
  `CREATE TABLE IF NOT EXISTS ai_usage (day TEXT NOT NULL, model TEXT NOT NULL, calls INTEGER NOT NULL, inp INTEGER NOT NULL, outp INTEGER NOT NULL, usd REAL NOT NULL, PRIMARY KEY (day, model))`,
  `CREATE TABLE IF NOT EXISTS push_subs (endpoint TEXT PRIMARY KEY, data TEXT NOT NULL, created INTEGER NOT NULL)`
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
  'content-security-policy': "default-src 'self'; script-src 'unsafe-inline'; worker-src 'self'; style-src 'unsafe-inline' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"};

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
  const imgBlocks = (images || []).slice(0, 6)
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
    system: 'You are the personal assistant inside Hey Armay, a personal management app owned by a business owner in Malaysia. Write in English unless asked otherwise.' + (json ? ' Reply with ONE valid JSON value only, no other text and no code block.' : '')
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
  try { await recordUsage(env, body.model, j.usage || {}); } catch(e){}
  const text = (j.content || []).filter(c => c.type === 'text').map(c => c.text).join('');
  return {text, truncated: j.stop_reason === 'max_tokens'};
}

/* ---------------- kos Claude (anggaran daripada token sebenar setiap panggilan) ---------------- */
// Harga asas USD per juta token (platform.claude.com/docs/en/about-claude/pricing, Nov 2026)
function priceUsd(model, inp, outp){
  if(/haiku-5-5/.test(model)){ const big = inp > 100000; return (inp * (big ? 0.5 : 0.1) + outp * (big ? 2.5 : 0.5)) / 1e6; }
  if(/sonnet/.test(model)) return (inp * 2 + outp * 10) / 1e6;
  if(/opus-5-5/.test(model)) return (inp * 4 + outp * 20) / 1e6;
  return (inp * 2 + outp * 10) / 1e6;
}
async function recordUsage(env, model, u){
  const inp = (Number(u.input_tokens) || 0) + (Number(u.cache_creation_input_tokens) || 0) + (Number(u.cache_read_input_tokens) || 0);
  const outp = Number(u.output_tokens) || 0;
  const usd = priceUsd(model, inp, outp);
  await env.DB.prepare(`INSERT INTO ai_usage (day, model, calls, inp, outp, usd) VALUES (?, ?, 1, ?, ?, ?)
    ON CONFLICT(day, model) DO UPDATE SET calls = calls + 1, inp = inp + excluded.inp, outp = outp + excluded.outp, usd = usd + excluded.usd`).bind(todayLocal(), model, inp, outp, usd).run();
}
async function usdToMyr(env){
  const t = todayLocal(), hit = await getMeta(env, 'fx_usdmyr');
  const c = hit ? JSON.parse(hit) : null;
  if(c && c.date === t) return c;
  for(const [u, pick] of [['https://api.frankfurter.app/latest?from=USD&to=MYR', d => d.rates && d.rates.MYR], ['https://open.er-api.com/v6/latest/USD', d => d.rates && d.rates.MYR]]){
    try { const r = await fetch(u); const d = await r.json(); const rate = Number(pick(d)); if(rate > 1 && rate < 10){ const out = {rate, date: t, live: true}; await setMeta(env, 'fx_usdmyr', JSON.stringify(out)); return out; } } catch(e){}
  }
  return c || {rate: 4.4, date: t, live: false};
}

/* ---------------- ringkasan berjadual ---------------- */
const EXP_CAT = {makan:'Food & drinks', transport:'Fuel & transport', dapur:'Groceries & home', bil:'Bills & subscriptions', keluarga:'Family', kesihatan:'Health', belibelah:'Shopping', hiburan:'Entertainment & leisure', perjalanan:'Travel', sedekah:'Charity & zakat', kerja:'Work & equipment', lain:'Other'};
function nextAnnual(s, t){
  if(!isYmd(s)) return null;
  const [, m, d] = s.split('-'); const y = Number(t.slice(0, 4));
  let n = `${y}-${m}-${d}`; if(n < t) n = `${y + 1}-${m}-${d}`;
  return {date: n, in: daysBetween(t, n)};
}
function morningLines(items, exps, t){
  const L = [], real = items.filter(i => !i.example), by = k => real.filter(i => i.kind === k);
  const ym = t.slice(0, 7), lastDay = new Date(Date.UTC(Number(t.slice(0, 4)), Number(t.slice(5, 7)), 0)).getUTCDate();
  by('event').filter(i => i.date === t).sort((a, b) => (a.start || '').localeCompare(b.start || '')).forEach(i => L.push(`Event ${i.start || 'all day'}: ${i.title}${i.place ? ' @ ' + i.place : ''}`));
  by('event').filter(i => i.date > t && i.date <= addDays(t, 2)).forEach(i => L.push(`Upcoming ${i.date} ${i.start || ''}: ${i.title}`));
  by('reminder').filter(i => !i.done && String(i.at || '').slice(0, 10) <= t).forEach(i => L.push(`Reminder ${String(i.at).replace('T', ' ')}${String(i.at).slice(0, 10) < t ? ' (missed)' : ''}: ${i.title}`));
  by('task').filter(i => !i.done && ((i.due && i.due <= t) || i.priority === 'tinggi')).forEach(i => L.push(`Task${i.priority === 'tinggi' ? ' [important]' : ''}${i.due ? ' due ' + i.due + (i.due < t ? ' (OVERDUE)' : '') : ''}: ${i.title}`));
  by('waiting').filter(i => !i.done && (i.expect ? i.expect <= t : (isYmd(i.since) && daysBetween(i.since, t) >= 3))).forEach(i => L.push(`Chase ${i.who || 'someone'}: ${i.title}`));
  by('payment').filter(i => !i.paid && i.due && i.due <= addDays(t, 3)).forEach(i => L.push(`Client payment ${i.client} ${money(i.amount)} ${i.due < t ? 'OVERDUE since' : 'due'} ${i.due}`));
  by('bill').filter(b => (b.cycle !== 'tahunan' || Number(b.month) === Number(t.slice(5, 7))) && !(b.paid && b.paid[ym])).forEach(b => { const d = `${ym}-${pad(Math.min(Math.max(Number(b.day) || 1, 1), lastDay))}`; if(d <= addDays(t, 3)) L.push(`Bill ${b.title} ${money(b.amount)} on day ${b.day}${d < t ? ' (overdue)' : ''}`); });
  by('renewal').filter(i => isYmd(i.date) && daysBetween(t, i.date) <= 14).forEach(i => L.push(`${i.title} expires on ${i.date}`));
  by('person').forEach(p => { for(const [k, w] of [['birthday', 'Birthday'], ['anniv', 'Anniversary']]){ const x = nextAnnual(p[k], t); if(x && x.in <= 7) L.push(`${w} of ${p.name} in ${x.in} days (${x.date})`); } });
  by('person').filter(p => Number(p.every) > 0 && (!isYmd(p.lastContact) || daysBetween(p.lastContact, t) >= Number(p.every))).slice(0, 2).forEach(p => L.push(`Haven't contacted ${p.name} in a while${p.rel ? ' (' + p.rel + ')' : ''}`));
  by('gift').filter(g => !g.done && isYmd(g.date) && g.date <= addDays(t, 7)).forEach(g => L.push(`${g.type || 'Function'}: ${g.title} on ${g.date}`));
  const h = by('habit').map(x => x.title); if(h.length) L.push(`Daily habits: ${h.join(', ')}`);
  const sp = exps.filter(e => !e.example && String(e.date || '').slice(0, 7) === ym && e.scope !== 'bisnes').reduce((s, e) => s + (Number(e.amount) || 0), 0);
  const bud = items.find(i => i.id === 'cfg-budget');
  if(bud && Number(bud.total) > 0) L.push(`Personal spending this month ${money(sp)} of ${money(bud.total)} budget (${Math.round(sp / bud.total * 100)}%)`);
  return L;
}
function weeklyLines(items, exps, t){
  const L = [], real = items.filter(i => !i.example), by = k => real.filter(i => i.kind === k);
  const from = addDays(t, -6), to = addDays(t, 7);
  const inLast = ms => { if(!ms) return false; const d = ymdOf(new Date(Number(ms) + TZ_OFFSET_MIN * 60000)); return d >= from && d <= t; };
  by('task').filter(i => i.done && inLast(i.doneAt)).forEach(i => L.push(`DONE: ${i.title}`));
  by('task').filter(i => !i.done && i.due && i.due < t).forEach(i => L.push(`OVERDUE: ${i.title} (due ${i.due})`));
  by('waiting').filter(i => i.done && inLast(i.doneAt)).forEach(i => L.push(`RECEIVED: ${i.title}`));
  by('waiting').filter(i => !i.done && (i.expect ? i.expect < t : (isYmd(i.since) && daysBetween(i.since, t) > 3))).forEach(i => L.push(`WAITING ON ${i.who || ''}: ${i.title}`));
  by('payment').filter(i => i.paid && inLast(i.paidAt)).forEach(i => L.push(`PAYMENT RECEIVED: ${i.client} ${money(i.amount)}`));
  const owed = by('payment').filter(i => !i.paid); if(owed.length) L.push(`OUTSTANDING: ${owed.length} invoices, ${money(owed.reduce((s, i) => s + (Number(i.amount) || 0), 0))}`);
  by('habit').forEach(h => { let n = 0; for(let k = 0; k < 7; k++) if(h.log && h.log[addDays(t, -k)]) n++; L.push(`HABIT ${h.title}: ${n}/7 days`); });
  by('goal').forEach(g => L.push(`GOAL ${g.title}: ${Number(g.progress) || 0}%`));
  by('event').filter(i => i.date > t && i.date <= to).forEach(i => L.push(`NEXT WEEK ${i.date} ${i.start || ''}: ${i.title}`));
  by('task').filter(i => !i.done && i.due && i.due >= t && i.due <= to).forEach(i => L.push(`DUE NEXT WEEK ${i.due}: ${i.title}`));
  by('renewal').filter(i => isYmd(i.date) && i.date <= addDays(t, 30)).forEach(i => L.push(`EXPIRES ${i.date}: ${i.title}`));
  const sp = exps.filter(e => !e.example && e.date >= from && e.date <= t);
  if(sp.length){
    const bc = {}; sp.forEach(e => { const k = EXP_CAT[e.cat] || 'Other'; bc[k] = (bc[k] || 0) + (Number(e.amount) || 0); });
    L.push(`SPENDING 7 DAYS: ${money(sp.reduce((s, e) => s + (Number(e.amount) || 0), 0))} (personal ${money(sp.filter(e => e.scope !== 'bisnes').reduce((s, e) => s + (Number(e.amount) || 0), 0))}, business ${money(sp.filter(e => e.scope === 'bisnes').reduce((s, e) => s + (Number(e.amount) || 0), 0))}); top: ${Object.entries(bc).sort((a, b) => b[1] - a[1]).slice(0, 3).map(([k, v]) => k + ' ' + money(v)).join(', ')}`);
  }
  return L;
}
const HARI = ['Sunday', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday'];
async function makeDigest(env, kind){
  await ensureSchema(env);
  const t = todayLocal(), d = nowLocal();
  const items = await allDocs(env, 'items');
  const exps = (await allDocs(env, 'belanja')).map(x => ({id: x.id, ...x.data}));
  const flat = items.map(x => ({id: x.id, ...x.data}));
  const lines = kind === 'minggu' ? weeklyLines(flat, exps, t) : morningLines(flat, exps, t);
  if(kind !== 'minggu' && env.ARMEDIA_DB){ try { lines.push(...teamLines(await armediaFeed(env, t, t), t)); } catch(e){} }
  const prompt = kind === 'minggu'
    ? `It is now ${HARI[d.getUTCDay()]}, ${t}. Write a weekly review in friendly English with four sections with short headings: "This week" (2-3 lines on what went well), "Spending" (1-2 lines), "Stuck" ("• " points), and "3 priorities for next week" (numbered). At most 17 lines. Do not invent anything that is not in the data.\n\nData:\n${lines.join('\n') || '(no data this week)'}`
    : `It is now ${HARI[d.getUTCDay()]}, ${t}, morning. Write a morning summary in friendly English, at most 10 lines: one good-morning line with the date, then "• " points ordered most urgent first (mention times where there are any), and end with one suggestion of what to do first. Do not invent anything. If the list is empty, say the day is free in 2 lines.\n\nList:\n${lines.join('\n') || '(empty)'}`;
  let text;
  const r = await askClaude(env, {input: prompt, tier: 'default', maxTokens: 1200});
  if(r.text) text = r.text.trim();
  else text = (kind === 'minggu' ? 'Weekly review' : 'Morning summary') + ` ${t}\n` + (lines.length ? lines.map(l => '• ' + l).join('\n') : 'Nothing on the list.');
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
  L.push(titles.length ? `Team jobs today (${titles.length}): ${titles.join('; ')}` : 'No team jobs today');
  const CHECK = ['Tunggu approval client', 'Sedia untuk post'];
  const late = feed.jobs.filter(j => j.deadline && j.status !== 'Dipost' && !CHECK.includes(j.status) && j.deadline.slice(0, 10) < t);
  if(late.length) L.push(`Team videos past deadline: ${late.length} (check in armedia.my)`);
  return L;
}

/* ---------------- Web Push: notifikasi pagi 8:00 ---------------- */
const te = new TextEncoder();
const b64u = buf => { const a = new Uint8Array(buf); let s = ''; for(let i = 0; i < a.length; i++) s += String.fromCharCode(a[i]); return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''); };
const unb64u = s => { s = String(s || '').replace(/-/g, '+').replace(/_/g, '/'); while(s.length % 4) s += '='; return Uint8Array.from(atob(s), c => c.charCodeAt(0)); };
const catBytes = (...a) => { const o = new Uint8Array(a.reduce((n, x) => n + x.length, 0)); let i = 0; for(const x of a){ o.set(x, i); i += x.length; } return o; };
const PUSH_HOSTS = /^(fcm\.googleapis\.com|updates\.push\.services\.mozilla\.com|[a-z0-9.-]+\.push\.apple\.com|[a-z0-9.-]+\.notify\.windows\.com|push\.services\.mozilla\.com)$/;
function validSub(s){
  try { const u = new URL(s.endpoint); return u.protocol === 'https:' && PUSH_HOSTS.test(u.hostname) && unb64u(s.keys.p256dh).length === 65 && unb64u(s.keys.auth).length === 16; } catch(e){ return false; }
}
async function vapidKeys(env){
  const hit = await getMeta(env, 'vapid');
  if(hit) return JSON.parse(hit);
  const kp = await crypto.subtle.generateKey({name: 'ECDSA', namedCurve: 'P-256'}, true, ['sign', 'verify']);
  const v = {priv: await crypto.subtle.exportKey('jwk', kp.privateKey), pub: b64u(await crypto.subtle.exportKey('raw', kp.publicKey))};
  await setMeta(env, 'vapid', JSON.stringify(v));
  return v;
}
async function hkdf(salt, ikm, info, len){
  const k = await crypto.subtle.importKey('raw', ikm, 'HKDF', false, ['deriveBits']);
  return new Uint8Array(await crypto.subtle.deriveBits({name: 'HKDF', hash: 'SHA-256', salt, info}, k, len * 8));
}
// RFC 8291 (aes128gcm)
async function encryptPush(sub, payload){
  const ua = unb64u(sub.keys.p256dh), auth = unb64u(sub.keys.auth);
  const eph = await crypto.subtle.generateKey({name: 'ECDH', namedCurve: 'P-256'}, true, ['deriveBits']);
  const asPub = new Uint8Array(await crypto.subtle.exportKey('raw', eph.publicKey));
  const uaKey = await crypto.subtle.importKey('raw', ua, {name: 'ECDH', namedCurve: 'P-256'}, false, []);
  const shared = new Uint8Array(await crypto.subtle.deriveBits({name: 'ECDH', public: uaKey}, eph.privateKey, 256));
  const ikm = await hkdf(auth, shared, catBytes(te.encode('WebPush: info'), new Uint8Array([0]), ua, asPub), 32);
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const cek = await hkdf(salt, ikm, catBytes(te.encode('Content-Encoding: aes128gcm'), new Uint8Array([0])), 16);
  const nonce = await hkdf(salt, ikm, catBytes(te.encode('Content-Encoding: nonce'), new Uint8Array([0])), 12);
  const key = await crypto.subtle.importKey('raw', cek, 'AES-GCM', false, ['encrypt']);
  const ct = new Uint8Array(await crypto.subtle.encrypt({name: 'AES-GCM', iv: nonce}, key, catBytes(te.encode(payload), new Uint8Array([2]))));
  const head = new Uint8Array(21); head.set(salt, 0); new DataView(head.buffer).setUint32(16, 4096); head[20] = 65;
  return catBytes(head, asPub, ct);
}
async function vapidAuth(env, endpoint){
  const v = await vapidKeys(env);
  const h = b64u(te.encode(JSON.stringify({typ: 'JWT', alg: 'ES256'})));
  const c = b64u(te.encode(JSON.stringify({aud: new URL(endpoint).origin, exp: Math.floor(Date.now() / 1000) + 12 * 3600, sub: 'https://heyarmay.com'})));
  const k = await crypto.subtle.importKey('jwk', v.priv, {name: 'ECDSA', namedCurve: 'P-256'}, false, ['sign']);
  const sig = await crypto.subtle.sign({name: 'ECDSA', hash: 'SHA-256'}, k, te.encode(h + '.' + c));
  return `vapid t=${h}.${c}.${b64u(sig)}, k=${v.pub}`;
}
async function sendPush(env, sub, msg){
  const body = await encryptPush(sub, JSON.stringify(msg));
  const r = await fetch(sub.endpoint, {method: 'POST', body, headers: {'content-encoding': 'aes128gcm', 'content-type': 'application/octet-stream', ttl: '43200', urgency: 'high', authorization: await vapidAuth(env, sub.endpoint)}});
  return r.status;
}
async function pushAll(env, msg, only){
  const rows = ((await env.DB.prepare('SELECT endpoint, data FROM push_subs').all()).results || []).filter(r => !only || r.endpoint === only);
  let sent = 0; const codes = [];
  for(const r of rows){
    try {
      const s = await sendPush(env, JSON.parse(r.data), msg); codes.push(s);
      if(s === 404 || s === 410) await env.DB.prepare('DELETE FROM push_subs WHERE endpoint = ?').bind(r.endpoint).run();
      else if(s >= 200 && s < 300) sent++;
    } catch(e){ codes.push(0); }
  }
  return {sent, total: rows.length, codes};
}
const MON3 = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
const hm12 = s => { const [h, m] = String(s).split(':').map(Number); if(!isFinite(h)) return ''; return `${h % 12 === 0 ? 12 : h % 12}:${pad(m || 0)}${h < 12 ? 'am' : 'pm'}`; };
const WXT = c => c === 0 ? 'Clear' : c <= 2 ? 'Partly cloudy' : c === 3 ? 'Cloudy' : c === 45 || c === 48 ? 'Foggy' : c <= 57 ? 'Drizzle' : c <= 63 ? 'Rain' : c <= 67 ? 'Heavy rain' : c <= 82 ? 'Showers' : c >= 95 ? 'Thunderstorms' : '';
async function morningMessage(env){
  await ensureSchema(env);
  const t = todayLocal(), d = nowLocal(), ym = t.slice(0, 7);
  const items = (await allDocs(env, 'items')).map(x => ({id: x.id, ...x.data})).filter(i => !i.example);
  const by = k => items.filter(i => i.kind === k);
  const agenda = [];
  by('event').filter(i => i.date === t).forEach(i => agenda.push([i.start || '', i.title + (i.place ? ' @ ' + i.place : '')]));
  by('reminder').filter(i => !i.done && String(i.at || '').slice(0, 10) === t).forEach(i => agenda.push([String(i.at).slice(11, 16), '⏰ ' + i.title]));
  if(env.ARMEDIA_DB){
    try { const f = await armediaFeed(env, t, t), seen = new Set();
      f.jobs.filter(j => j.date === t).forEach(j => { if(seen.has(j.shoot)) return; seen.add(j.shoot); agenda.push([j.time || '', '🎬 ' + (j.title || 'Team job')]); });
    } catch(e){}
  }
  agenda.sort((a, b) => (a[0] || '99').localeCompare(b[0] || '99'));
  const lines = agenda.slice(0, 4).map(([s, x]) => (s ? hm12(s) + ' ' : 'All day · ') + x);
  if(agenda.length > 4) lines.push(`+${agenda.length - 4} more on the schedule`);
  const extra = [];
  const tasks = by('task').filter(i => !i.done && ((i.due && i.due <= t) || i.priority === 'tinggi'));
  const lateT = tasks.filter(i => i.due && i.due < t).length;
  if(tasks.length) extra.push(`✅ ${tasks.length} task${tasks.length > 1 ? 's' : ''} need${tasks.length > 1 ? '' : 's'} attention${lateT ? ` (${lateT} overdue)` : ''}`);
  const lastDay = new Date(Date.UTC(Number(t.slice(0, 4)), Number(t.slice(5, 7)), 0)).getUTCDate();
  const bills = by('bill').filter(b => (b.cycle !== 'tahunan' || Number(b.month) === Number(t.slice(5, 7))) && !(b.paid && b.paid[ym]) && `${ym}-${pad(Math.min(Math.max(Number(b.day) || 1, 1), lastDay))}` <= t);
  if(bills.length) extra.push(`💳 Bill${bills.length > 1 ? 's' : ''} due: ${bills.map(b => b.title).slice(0, 3).join(', ')}`);
  const ren = by('renewal').filter(i => isYmd(i.date) && daysBetween(t, i.date) <= 7);
  if(ren.length) extra.push(`⚠️ ${ren.map(i => i.title + (i.date < t ? ' (expired)' : i.date === t ? ' (today)' : ` (${daysBetween(t, i.date)}d)`)).slice(0, 2).join(', ')}`);
  by('person').forEach(p => { for(const [k, w] of [['birthday', 'birthday'], ['anniv', 'anniversary']]){ const x = nextAnnual(p[k], t); if(x && x.in === 0) extra.push(`🎂 ${p.name}'s ${w} today`); } });
  try {
    const q = new URLSearchParams({latitude: '3.04', longitude: '101.45', timezone: 'Asia/Kuala_Lumpur', forecast_days: '1', daily: 'temperature_2m_max,temperature_2m_min,precipitation_probability_max,weather_code'});
    const w = await (await fetch('https://api.open-meteo.com/v1/forecast?' + q)).json();
    const dy = w.daily || {};
    if(dy.temperature_2m_max) extra.push(`🌦 ${WXT(dy.weather_code[0]) || 'Weather'}, ${Math.round(dy.temperature_2m_max[0])}°/${Math.round(dy.temperature_2m_min[0])}°, ${dy.precipitation_probability_max[0]}% chance of rain`);
  } catch(e){}
  const body = [...lines, ...extra].join('\n') || 'Nothing on the schedule today. Enjoy the free day.';
  const HARI3 = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'];
  return {title: `Good morning, Amir · ${HARI3[d.getUTCDay()]} ${d.getUTCDate()} ${MON3[d.getUTCMonth()]}`, body, url: '/#hari-ini', tag: 'hy-morning'};
}
async function morningPushOnce(env){
  await ensureSchema(env);
  const t = todayLocal();
  if(await getMeta(env, 'push_last') === t) return {skipped: true};
  const n = (await env.DB.prepare('SELECT COUNT(*) AS n FROM push_subs').first()).n;
  if(!n) return {sent: 0, total: 0};
  await setMeta(env, 'push_last', t);
  return pushAll(env, await morningMessage(env));
}
const SW_JS = `self.addEventListener('install', () => self.skipWaiting());
self.addEventListener('activate', e => e.waitUntil(self.clients.claim()));
self.addEventListener('push', e => {
  let d = {};
  try { d = e.data ? e.data.json() : {}; } catch(_){ d = {body: e.data ? e.data.text() : ''}; }
  e.waitUntil(self.registration.showNotification(d.title || 'Hey Armay', {body: d.body || '', icon: '/icon-192.png', tag: d.tag || 'hy', renotify: true, data: {url: d.url || '/'}}));
});
self.addEventListener('notificationclick', e => {
  e.notification.close();
  const url = new URL((e.notification.data && e.notification.data.url) || '/', self.location.origin).href;
  e.waitUntil(self.clients.matchAll({type: 'window', includeUncontrolled: true}).then(ws => {
    for(const w of ws){ if(w.url.indexOf(self.location.origin) === 0){ if('navigate' in w) w.navigate(url).catch(() => {}); return w.focus(); } }
    return self.clients.openWindow(url);
  }));
});`;

/* ---------------- Widget telefon (app Android) ---------------- */
async function sha256hex(s){ return [...new Uint8Array(await crypto.subtle.digest('SHA-256', te.encode(s)))].map(b => b.toString(16).padStart(2, '0')).join(''); }
async function widgetTokens(env){ try { return JSON.parse(await getMeta(env, 'widget_tokens') || '[]'); } catch(e){ return []; } }
async function widgetAuth(req, env){
  const m = /^Bearer\s+([A-Za-z0-9_-]{40,})$/.exec(req.headers.get('authorization') || '');
  if(!m) return false;
  const h = await sha256hex(m[1]), list = await widgetTokens(env);
  const hit = list.find(x => x.h === h);
  if(!hit) return false;
  if(!hit.last || Date.now() - hit.last > 6 * 3600e3){ hit.last = Date.now(); await setMeta(env, 'widget_tokens', JSON.stringify(list)); }
  return true;
}
async function widgetData(env){
  const t = todayLocal(), d = nowLocal(), nowHM = pad(d.getUTCHours()) + ':' + pad(d.getUTCMinutes());
  const tm = addDaysYmd(t, 1);
  const items = (await allDocs(env, 'items')).map(x => ({id: x.id, ...x.data})).filter(i => !i.example);
  const by = k => items.filter(i => i.kind === k);
  const agendaFor = async day => {
    const a = [];
    by('event').filter(i => i.date === day).forEach(i => a.push({time: i.start || '', title: i.title || 'Event', sub: i.place || 'Event'}));
    by('reminder').filter(i => !i.done && String(i.at || '').slice(0, 10) === day).forEach(i => a.push({time: String(i.at).slice(11, 16), title: i.title || 'Reminder', sub: 'Reminder'}));
    let team = 0;
    if(env.ARMEDIA_DB){
      try { const f = await armediaFeed(env, day, day), seen = new Set();
        f.jobs.filter(j => j.date === day).forEach(j => { if(seen.has(j.shoot)) return; seen.add(j.shoot); team++; a.push({time: j.time || '', title: j.title || 'Team job', sub: 'ARMEDIA team' + (j.location ? ' · ' + j.location : '')}); });
      } catch(e){}
    }
    a.sort((x, y) => (x.time || '99').localeCompare(y.time || '99'));
    return {a, team};
  };
  const today = await agendaFor(t);
  const left = today.a.filter(x => !x.time || x.time >= nowHM);
  let next = left[0] ? {...left[0], day: 'Today'} : null, more = Math.max(0, left.length - 1);
  if(!next){ const tom = await agendaFor(tm); if(tom.a[0]){ next = {...tom.a[0], day: 'Tomorrow'}; more = tom.a.length - 1; } }
  if(next) next.time = next.time ? hm12(next.time) : 'All day';
  const tasks = by('task').filter(i => !i.done && ((i.due && i.due <= t) || i.priority === 'tinggi')).length;
  const invoices = by('payment').filter(i => !i.paid).length;
  let weather = null;
  try {
    let w = await getMeta(env, 'wx_widget'); w = w ? JSON.parse(w) : null;
    if(!w || Date.now() - w.at > 20 * 60e3){
      const q = new URLSearchParams({latitude: '3.04', longitude: '101.45', timezone: 'Asia/Kuala_Lumpur', forecast_days: '1', current: 'temperature_2m,weather_code,is_day', daily: 'temperature_2m_max,temperature_2m_min,precipitation_probability_max'});
      const r = await (await fetch('https://api.open-meteo.com/v1/forecast?' + q)).json();
      w = {at: Date.now(), r}; await setMeta(env, 'wx_widget', JSON.stringify(w));
    }
    const c = w.r.current || {}, dy = w.r.daily || {};
    weather = {temp: Math.round(c.temperature_2m), desc: WXT(c.weather_code) || '', code: c.weather_code, day: !!c.is_day, hi: dy.temperature_2m_max ? Math.round(dy.temperature_2m_max[0]) : null, lo: dy.temperature_2m_min ? Math.round(dy.temperature_2m_min[0]) : null, rain: dy.precipitation_probability_max ? dy.precipitation_probability_max[0] : null};
  } catch(e){}
  const h = d.getUTCHours(), HARI3 = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'];
  return {greet: (h < 12 ? 'Good morning' : h < 18 ? 'Good afternoon' : 'Good evening') + ', Amir', date: `${HARI3[d.getUTCDay()]}, ${d.getUTCDate()} ${MON3[d.getUTCMonth()]}`,
    next, more, tasks, invoices, team: today.team, weather, updated: pad(d.getUTCHours()) + ':' + pad(d.getUTCMinutes())};
}
function addDaysYmd(s, n){ const x = new Date(s + 'T00:00:00Z'); x.setUTCDate(x.getUTCDate() + n); return x.toISOString().slice(0, 10); }

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
button.go,a.go{width:100%;margin-top:24px;border:0;border-radius:12px;background:var(--grad);color:var(--on-accent);font:inherit;font-weight:700;padding:14px;cursor:pointer;transition:box-shadow .2s,transform .12s var(--ease)}
button.go:hover,a.go:hover{box-shadow:0 0 26px rgba(var(--glow),.35)}
button.go:active{transform:scale(.98)}
button.go:disabled{opacity:.75;cursor:progress;background-size:200% 100%;animation:shimmer 1.2s linear infinite}
.nt-b{display:flex;flex-direction:column;gap:0}.nt-b [hidden]{display:none}
button.ghost{width:100%;margin-top:10px;border:1px solid var(--line);border-radius:12px;background:transparent;color:var(--ink);font:inherit;font-weight:600;padding:13px;cursor:pointer}
button.ghost:hover{border-color:var(--rose);color:var(--rose)}
.err{display:none;margin-top:14px;background:var(--rose-soft);color:var(--rose);border:1px solid rgba(197,51,82,.25);border-radius:12px;padding:10px 12px;font-size:.88rem;animation:rise .3s var(--ease) both}
.ok{display:none;margin-top:14px;background:var(--accent-soft);color:var(--accent);border:1px solid rgba(var(--glow),.3);border-radius:12px;padding:10px 12px;font-size:.88rem;animation:rise .3s var(--ease) both}
.hint{color:var(--muted);font-size:.8rem;margin-top:6px}
.use h2,.pw-h{font-size:1rem;font-weight:650;margin:22px 0 10px;letter-spacing:-.01em}
.use-grid{display:grid;grid-template-columns:repeat(3,1fr);gap:8px}
.use-grid div{display:flex;flex-direction:column;gap:2px;padding:10px;border-radius:12px;border:1px solid var(--line);background:var(--field)}
.use-grid span{font-size:.72rem;color:var(--muted);font-weight:600}
.use-grid b{font-size:1.05rem;font-weight:650;font-variant-numeric:tabular-nums;letter-spacing:-.01em}
.use-grid small{font-size:.7rem;color:var(--muted)}
.use-bars{display:flex;align-items:flex-end;gap:2px;height:64px;margin-top:12px;padding:0 2px;border-bottom:1px solid var(--line)}
.use-bars i{flex:1;min-width:0;border-radius:3px 3px 0 0;background:var(--grad);opacity:.85}
.use-axis{display:flex;justify-content:space-between;font-size:.68rem;color:var(--muted);margin-top:4px}
.use-models{display:flex;flex-direction:column;margin-top:10px}
.use-models div{display:flex;justify-content:space-between;gap:10px;font-size:.82rem;padding:6px 0;border-bottom:1px solid var(--line)}
.use-models span{color:var(--muted)}
.use-models b{white-space:nowrap;font-variant-numeric:tabular-nums}
.use-link{display:inline-block;margin-top:6px;font-size:.85rem}
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
  i.type = show ? 'text' : 'password'; b.textContent = show ? 'Hide' : 'Show';
}));`;
const pageShell = (title, body, script) => `<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover"><meta name="theme-color" content="#EDF0F8">
<link rel="manifest" href="/manifest.webmanifest"><link rel="icon" href="/favicon.png?v=3" type="image/png"><link rel="apple-touch-icon" href="/apple-touch-icon.png?v=3">
<meta name="apple-mobile-web-app-capable" content="yes"><meta name="apple-mobile-web-app-title" content="Hey Armay">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin><link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Geist:wght@400;500;600;700&family=Geist+Mono:wght@500&display=swap">
<title>${title}</title><script>(function(){var t;try{t=localStorage.getItem("hy-theme")}catch(e){}document.documentElement.setAttribute("data-hy",t==="dark"?"dark":"light");})();</script><style>${PAGE_CSS}</style></head><body><main><div class="card">
<div class="brand"><span class="logo" role="img" aria-label="Hey Armay"></span></div>
${body}</div></main><script>${PAGE_JS}${script}</script></body></html>`;
const pwField = (id, ac, label) => `<label for="${id}">${label}</label><div class="f"><input id="${id}" type="password" autocomplete="${ac}" required><button type="button" class="eye">Show</button></div>`;
function authPage(mode){
  if(mode === 'closed') return pageShell('Sign in', `<h1>Account not set up</h1>
<p class="lead">The ID and password haven't been created yet. The first setup can only be done by the owner through a Cloudflare Access sign-in.</p>`, '');
  const setup = mode === 'setup';
  return pageShell(setup ? 'Create sign-in' : 'Sign in', `<h1>${setup ? 'Create sign-in' : 'Sign in'}</h1>
<p class="lead">${setup ? 'Choose an ID and password. From now on you will sign in with this ID and password only.' : 'Enter your ID and password.'}</p>
<form id="f" novalidate>
<label for="u">ID</label><input id="u" name="username" autocomplete="username" autocapitalize="none" spellcheck="false" required ${setup ? 'placeholder="e.g. armay"' : ''}>
${setup ? '<div class="hint">3–40 characters: letters, numbers, dot, dash or @.</div>' : ''}
${pwField('p', setup ? 'new-password' : 'current-password', 'Password')}
${setup ? '<div class="hint">At least 8 characters.</div>' + pwField('p2', 'new-password', 'Repeat password') : ''}
<button class="go" type="submit">${setup ? 'Create & sign in' : 'Sign in'}</button>
<div class="err" role="alert"></div></form>`, `
const SETUP = ${setup};
$('#f').addEventListener('submit', async ev => {
  ev.preventDefault(); showErr('');
  const u = $('#u').value.trim().toLowerCase(), p = $('#p').value;
  if(!u || !p) return showErr('Enter your ID and password.');
  if(SETUP){
    if(!/^[a-z0-9._@-]{3,40}$/.test(u)) return showErr('ID must be 3–40 characters: letters, numbers, dot, dash or @.');
    if(p.length < 8) return showErr('Password must be at least 8 characters.');
    if(p !== $('#p2').value) return showErr("Passwords don't match. Type them again.");
  }
  const btn = $('.go'); btn.disabled = true; btn.textContent = 'One moment…';
  try {
    const r = await post(SETUP ? '/api/auth/setup' : '/api/auth/login', {user:u, key:await derive(u, p)});
    if(r.ok){ location.reload(); return; }
    showErr(r.error === 'locked' ? 'Too many wrong attempts. Try again in 15 minutes.'
      : r.error === 'wrong' ? 'Wrong ID or password.'
      : r.error === 'access' ? 'Setup needs a Cloudflare Access sign-in. Reload the page.'
      : r.error === 'exists' ? 'The account already exists. Reload to sign in.'
      : "That didn't work. Try again.");
  } catch(e){ showErr('No connection. Try again.'); }
  btn.disabled = false; btn.textContent = SETUP ? 'Create & sign in' : 'Sign in';
});
$('#u').focus();`);
}
function accountPage(user){
  const safe = String(user).replace(/[^a-z0-9._@-]/g, '');
  return pageShell('Account', `<a href="/">← Back</a>
<h1 style="margin-top:14px">Account</h1><p class="lead">Signed in as <b>${safe}</b></p>
<section class="use" aria-labelledby="wd-h"><h2 id="wd-h">Phone widget</h2>
<p class="hint" id="wd-s" style="margin:4px 0 12px">Shows today's next event, tasks, invoices, team jobs and weather on your Android home screen. On your Android phone: download and install the app (step 1), then tap Connect (step 2).</p>
<div class="nt-b"><a class="go" id="wd-dl" href="/HeyArmayWidget.apk" download style="display:block;text-align:center;text-decoration:none;box-sizing:border-box">1. Download the widget app</a><button class="go" id="wd-on" type="button">2. Connect widget on this phone</button><button class="ghost" id="wd-off" type="button">Disconnect all widgets</button></div></section>
<hr><section class="use" aria-labelledby="use-h"><h2 id="use-h">Claude AI cost</h2>
<div class="use-grid"><div><span>Today</span><b id="u-today">…</b><small id="u-today-n"></small></div><div><span>This month</span><b id="u-month">…</b><small id="u-month-n"></small></div><div><span>Since start</span><b id="u-all">…</b><small id="u-all-n"></small></div></div>
<div class="use-bars" id="u-bars" aria-label="Cost over 30 days"></div><div class="use-axis"><span>30 days ago</span><span>Today</span></div>
<div class="use-models" id="u-models"></div>
<p class="hint" id="u-note"></p>
<a class="use-link" href="https://platform.claude.com/dashboard" target="_blank" rel="noopener">Credit balance & actual billing in Claude Console ↗</a></section>
<hr><section class="use" aria-labelledby="nt-h"><h2 id="nt-h">Morning notification</h2>
<p class="hint" id="nt-s" style="margin:4px 0 12px">Every day at 8:00 am, a notification on this device with today's schedule, team jobs, tasks and weather.</p>
<div class="nt-b"><button class="go" id="nt-on" type="button" hidden>Turn on for this device</button><button class="ghost" id="nt-test" type="button" hidden>Send a preview now</button><button class="ghost" id="nt-off" type="button" hidden>Turn off on this device</button></div></section>
<hr><h2 class="pw-h">Change password</h2>
<form id="f" novalidate>
<input type="text" name="username" autocomplete="username" value="${safe}" hidden>
${pwField('o', 'current-password', 'Current password')}
${pwField('n', 'new-password', 'New password')}
${pwField('n2', 'new-password', 'Repeat new password')}
<button class="go" type="submit">Change password</button>
<div class="err" role="alert"></div><div class="ok" role="status"></div></form>
<hr><button class="ghost" id="out" type="button">Sign out</button>`, `
const USER = ${JSON.stringify(safe)};
$('#f').addEventListener('submit', async ev => {
  ev.preventDefault(); showErr(''); $('.ok').style.display = 'none';
  const o = $('#o').value, n = $('#n').value;
  if(n.length < 8) return showErr('The new password must be at least 8 characters.');
  if(n !== $('#n2').value) return showErr("The new passwords don't match. Type them again.");
  const btn = $('.go'); btn.disabled = true; btn.textContent = 'One moment…';
  try {
    const r = await post('/api/auth/password', {old:await derive(USER, o), key:await derive(USER, n)});
    if(r.ok){ ev.target.reset(); const k = $('.ok'); k.textContent = 'Password changed. Other devices have been signed out.'; k.style.display = 'block'; }
    else showErr(r.error === 'wrong' ? 'The current password is wrong.' : r.error === 'locked' ? 'Too many wrong attempts. Try again in 15 minutes.' : "That didn't work. Try again.");
  } catch(e){ showErr('No connection. Try again.'); }
  btn.disabled = false; btn.textContent = 'Change password';
});
$('#out').addEventListener('click', async () => { await post('/api/auth/logout', {}); location.href = '/'; });
(function(){
  const s = $('#wd-s');
  fetch('/api/widget/status', {credentials:'same-origin', cache:'no-store'}).then(r => r.json()).then(j => { if(j.devices) s.textContent = 'Connected on ' + j.devices + ' device' + (j.devices > 1 ? 's' : '') + (j.last ? ' · last update ' + new Date(j.last).toLocaleString('en-GB', {day:'numeric', month:'short', hour:'numeric', minute:'2-digit'}) : '') + '. Tap Connect again on a new phone.'; }).catch(() => {});
  $('#wd-on').addEventListener('click', async () => {
    try { const r = await post('/api/widget/connect', {}); if(!r.link) throw 0; s.textContent = 'Opening the Hey Armay Widget app… If nothing happens, install the app first and try again.'; location.href = /Android/i.test(navigator.userAgent) ? 'intent://connect?' + r.link.split('?')[1] + '#Intent;scheme=heyarmay;package=com.heyarmay.app;end' : r.link; }
    catch(e){ s.textContent = "Couldn't connect. Try again."; }
  });
  $('#wd-off').addEventListener('click', async () => { await post('/api/widget/revoke', {}); s.textContent = 'All widgets disconnected.'; });
})();
(function(){
  const s = $('#nt-s'), on = $('#nt-on'), off = $('#nt-off'), tst = $('#nt-test');
  const ok = 'serviceWorker' in navigator && 'PushManager' in window && 'Notification' in window;
  const u8 = x => { x = String(x).replace(/-/g, '+').replace(/_/g, '/'); while(x.length % 4) x += '='; return Uint8Array.from(atob(x), c => c.charCodeAt(0)); };
  let reg = null, sub = null;
  const show = (state, msg) => { on.hidden = state !== 'off'; off.hidden = tst.hidden = state !== 'on'; if(msg) s.textContent = msg; };
  if(!ok){ show('none', "This browser can't receive notifications. On Android, use Chrome; on iPhone, add Hey Armay to the Home Screen first."); return; }
  (async () => {
    try {
      reg = await navigator.serviceWorker.register('/sw.js'); sub = await reg.pushManager.getSubscription();
      if(Notification.permission === 'denied') show('none', 'Notifications are blocked for heyarmay.com. Allow them in your browser or phone settings, then reload this page.');
      else if(sub) show('on', "On for this device. You'll get today's plan at 8:00 am every morning.");
      else show('off');
    } catch(e){ show('none', "Notifications aren't available here."); }
  })();
  on.addEventListener('click', async () => {
    on.disabled = true;
    try {
      const perm = await Notification.requestPermission();
      if(perm !== 'granted'){ show(perm === 'denied' ? 'none' : 'off', 'Notifications were not allowed.'); on.disabled = false; return; }
      await navigator.serviceWorker.ready;
      const k = (await (await fetch('/api/push/key', {credentials:'same-origin', cache:'no-store'})).json()).key;
      sub = await reg.pushManager.getSubscription() || await reg.pushManager.subscribe({userVisibleOnly: true, applicationServerKey: u8(k)});
      const r = await post('/api/push/sub', JSON.parse(JSON.stringify(sub)));
      if(!r.ok) throw new Error('sub');
      show('on', "On for this device. You'll get today's plan at 8:00 am every morning. A preview is on its way.");
      post('/api/push/test', {endpoint: sub.endpoint});
    } catch(e){ s.textContent = "Couldn't turn on notifications. Try again."; }
    on.disabled = false;
  });
  tst.addEventListener('click', async () => {
    tst.disabled = true;
    try { const r = await post('/api/push/test', {endpoint: sub && sub.endpoint}); s.textContent = r.sent ? 'Preview sent. It should appear in a few seconds.' : "The preview couldn't be delivered. Turn it off and on again."; } catch(e){ s.textContent = 'No connection. Try again.'; }
    tst.disabled = false;
  });
  off.addEventListener('click', async () => {
    try { if(sub){ await post('/api/push/unsub', {endpoint: sub.endpoint}); await sub.unsubscribe(); sub = null; } show('off', 'Off for this device.'); } catch(e){ s.textContent = "Couldn't turn it off. Try again."; }
  });
})();
(async () => {
  try {
    const u = await (await fetch('/api/usage', {credentials:'same-origin', cache:'no-store'})).json();
    const rm = v => 'RM ' + (v < 0.01 && v > 0 ? v.toFixed(4) : v.toFixed(2));
    const set = (k, o) => { $('#u-' + k).textContent = rm(o.rm); $('#u-' + k + '-n').textContent = o.calls + ' uses'; };
    set('today', u.today); set('month', u.month); set('all', u.all);
    const mx = Math.max.apply(null, u.days.map(d => d.rm).concat([0.0001]));
    $('#u-bars').innerHTML = u.days.map(d => '<i title="' + d.day + ': RM ' + d.rm.toFixed(4) + ' · ' + d.calls + ' uses" style="height:' + Math.max(2, Math.round(d.rm / mx * 100)) + '%"></i>').join('');
    const nm = m => /haiku/.test(m) ? 'Haiku (fast: categories, quick capture, receipts)' : /sonnet/.test(m) ? 'Sonnet (voice & photo sorting, summaries)' : m;
    $('#u-models').innerHTML = u.models.map(x => '<div><span>' + nm(x.model) + '</span><b>' + rm(x.rm) + '</b></div>').join('');
    $('#u-note').textContent = 'Estimated from the actual tokens of each call and official Claude pricing. Exchange rate: 1 USD = RM ' + u.rate.toFixed(3) + (u.rateLive ? '' : ' (estimate)') + '. Counted since ' + u.since + '.';
  } catch(e){ $('#u-note').textContent = "Couldn't load usage data."; }
})();`);
}

/* ---------------- router ---------------- */
async function handle(req, env, ctx){
  const url = new URL(req.url), p = url.pathname, m = req.method;

  // Pautan ringkasan untuk notifikasi Claude app (tanpa log masuk, hanya teks ringkasan)
  const dg = p.match(/^\/r\/([a-z0-9]{20,64})\/(pagi|minggu)$/);
  if(dg){
    await ensureSchema(env);
    const key = await getMeta(env, 'digest_key');
    if(!key || key !== dg[1]) return T('Not found', 404);
    const kind = dg[2];
    let row = await getMeta(env, 'digest_' + kind);
    let d = row ? JSON.parse(row) : null;
    if(!d || d.date !== todayLocal()) d = {date: todayLocal(), text: await makeDigest(env, kind)};
    return T(d.text + '\n\nOpen: https://heyarmay.com' + (kind === 'minggu' ? '/#semakan' : '/'));
  }

  const PNGS = {'/icon-mask-192.png': ICON_MASK_192, '/icon-mask-512.png': ICON_MASK_512, '/favicon.png': ICON_64, '/favicon.svg': ICON_64, '/icon.svg': ICON_64, '/apple-touch-icon.png': ICON_180, '/logo.png': LOGO_PNG, ...SC_PNGS};
  if(PNGS[p]){
    const bin = Uint8Array.from(atob(PNGS[p]), c => c.charCodeAt(0));
    return new Response(bin, {headers: {'content-type': 'image/png', 'cache-control': 'public, max-age=3600'}});
  }
  if(p === '/api/widget' && m === 'GET'){
    await ensureSchema(env);
    if(!await widgetAuth(req, env)) return J({error: 'token'}, 401);
    return J(await widgetData(env));
  }
  if(p === '/sw.js') return new Response(SW_JS, {headers: {'content-type': 'text/javascript; charset=utf-8', 'cache-control': 'no-cache'}});
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
    if(m !== 'GET' && m !== 'HEAD') return T('Sign in first', 401);
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
  if(p === '/HeyArmayWidget.apk' && m === 'GET'){
    const bin = Uint8Array.from(atob(WIDGET_APK), c => c.charCodeAt(0));
    return new Response(bin, {headers: {'content-type': 'application/vnd.android.package-archive', 'content-disposition': 'attachment; filename="HeyArmayWidget.apk"', 'cache-control': 'no-store'}});
  }
  // SEMENTARA: tinjau struktur armedia (baca sahaja)
  if(p === '/api/armedia/inspect' && m === 'GET' && env.ARMEDIA_DB){
    const db = env.ARMEDIA_DB;
    const types = (await db.prepare('SELECT type, COUNT(*) AS n, MAX(updated_at) AS u FROM records GROUP BY type ORDER BY n DESC').all()).results || [];
    const want = (url.searchParams.get('types') || '').split(',').filter(Boolean).slice(0, 8);
    const samples = {};
    for(const ty of want){
      const rows = (await db.prepare('SELECT id, data, created_at, updated_at FROM records WHERE type = ? ORDER BY updated_at DESC LIMIT 3').bind(ty).all()).results || [];
      samples[ty] = rows.map(r => { let d = {}; try { d = JSON.parse(r.data); } catch(e){} const o = {}; for(const [k, v] of Object.entries(d)) o[k] = typeof v === 'string' ? v.slice(0, 80) : Array.isArray(v) ? '[' + v.length + ']' + JSON.stringify(v).slice(0, 120) : v && typeof v === 'object' ? JSON.stringify(v).slice(0, 120) : v; return {id: r.id, ...o}; });
    }
    return J({types, samples});
  }
  // Widget telefon: sambung / putus
  if(p === '/api/widget/connect' && m === 'POST'){
    const raw = crypto.getRandomValues(new Uint8Array(32)), tok = b64u(raw);
    const list = (await widgetTokens(env)).slice(-4);
    list.push({h: await sha256hex(tok), created: Date.now(), last: 0});
    await setMeta(env, 'widget_tokens', JSON.stringify(list));
    return J({link: 'heyarmay://connect?t=' + tok});
  }
  if(p === '/api/widget/revoke' && m === 'POST'){ await setMeta(env, 'widget_tokens', '[]'); return J({ok: true}); }
  if(p === '/api/widget/status' && m === 'GET'){ const l = await widgetTokens(env); return J({devices: l.length, last: Math.max(0, ...l.map(x => x.last || 0))}); }
  // Notifikasi pagi (Web Push)
  if(p === '/api/push/key' && m === 'GET') return J({key: (await vapidKeys(env)).pub});
  if(p === '/api/push/sub' && m === 'POST'){
    const s = await req.json().catch(() => null);
    if(!s || !s.keys || !validSub(s)) return J({error: 'sub'}, 400);
    const n = (await env.DB.prepare('SELECT COUNT(*) AS n FROM push_subs').first()).n;
    if(n >= 10) await env.DB.prepare('DELETE FROM push_subs WHERE endpoint IN (SELECT endpoint FROM push_subs ORDER BY created LIMIT 1)').run();
    await env.DB.prepare('INSERT INTO push_subs (endpoint, data, created) VALUES (?, ?, ?) ON CONFLICT(endpoint) DO UPDATE SET data = excluded.data').bind(s.endpoint, JSON.stringify({endpoint: s.endpoint, keys: {p256dh: s.keys.p256dh, auth: s.keys.auth}}), Date.now()).run();
    return J({ok: true});
  }
  if(p === '/api/push/unsub' && m === 'POST'){
    const s = await req.json().catch(() => null) || {};
    await env.DB.prepare('DELETE FROM push_subs WHERE endpoint = ?').bind(String(s.endpoint || '')).run();
    return J({ok: true});
  }
  if(p === '/api/push/test' && m === 'POST'){
    const s = await req.json().catch(() => null) || {};
    const msg = await morningMessage(env);
    return J(await pushAll(env, {...msg, title: msg.title.replace('Good morning', 'Preview'), tag: 'hy-test'}, s.endpoint ? String(s.endpoint) : null));
  }
  if(p === '/api/push/status' && m === 'GET'){
    const ep = url.searchParams.get('endpoint') || '';
    const r = ep ? await env.DB.prepare('SELECT 1 AS x FROM push_subs WHERE endpoint = ?').bind(ep).first() : null;
    const n = (await env.DB.prepare('SELECT COUNT(*) AS n FROM push_subs').first()).n;
    return J({on: !!r, devices: n});
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

  // Cuaca (Open-Meteo, tanpa kunci) — cache 15 minit
  if(p === '/api/cuaca' && m === 'GET'){
    const lat = Math.round(Number(url.searchParams.get('lat') || 3.0449) * 100) / 100, lon = Math.round(Number(url.searchParams.get('lon') || 101.4456) * 100) / 100;
    if(!isFinite(lat) || !isFinite(lon) || Math.abs(lat) > 90 || Math.abs(lon) > 180) return J({error: 'coords'}, 400);
    const key = `wx:${lat},${lon}`, hit = await getMeta(env, key);
    if(hit){ const c = JSON.parse(hit); if(Date.now() - c.at < 15 * 60000) return J(c); }
    const q = new URLSearchParams({latitude: lat, longitude: lon, timezone: 'Asia/Kuala_Lumpur', forecast_days: '2',
      current: 'temperature_2m,apparent_temperature,relative_humidity_2m,weather_code,wind_speed_10m,is_day,precipitation',
      hourly: 'temperature_2m,precipitation_probability,weather_code',
      daily: 'temperature_2m_max,temperature_2m_min,precipitation_probability_max,sunrise,sunset,uv_index_max,weather_code'});
    try {
      const r = await fetch('https://api.open-meteo.com/v1/forecast?' + q);
      if(!r.ok) throw new Error('upstream ' + r.status);
      const d = await r.json();
      const out = {at: Date.now(), lat, lon, current: d.current || {}, hourly: d.hourly || {}, daily: d.daily || {}};
      await setMeta(env, key, JSON.stringify(out));
      return J(out);
    } catch(e){ return hit ? J(JSON.parse(hit)) : J({error: 'cuaca'}, 502); }
  }
  // Waktu solat JAKIM (e-Solat), cache sehari; sandaran Aladhan (kaedah JAKIM)
  if(p === '/api/solat' && m === 'GET'){
    const zone = /^[A-Z]{3}\d{2}$/.test(url.searchParams.get('zone') || '') ? url.searchParams.get('zone') : 'SGR03';
    const t = todayLocal(), key = `solat:${zone}:${t}`, hit = await getMeta(env, key);
    if(hit) return J(JSON.parse(hit));
    const hm = v => String(v || '').slice(0, 5);
    let out = null;
    try {
      const r = await fetch(`https://www.e-solat.gov.my/index.php?r=esolatApi/TakwimSolat&period=today&zone=${zone}`, {headers: {'user-agent': 'heyarmay.com'}});
      const d = await r.json(); const x = d && d.prayerTime && d.prayerTime[0];
      if(x && x.fajr) out = {date: t, zone, src: 'JAKIM', hijri: x.hijri || '', times: {imsak: hm(x.imsak), subuh: hm(x.fajr), syuruk: hm(x.syuruk), zohor: hm(x.dhuhr), asar: hm(x.asr), maghrib: hm(x.maghrib), isyak: hm(x.isha)}};
    } catch(e){}
    if(!out){
      try {
        const [y, mo, da] = t.split('-');
        const r = await fetch(`https://api.aladhan.com/v1/timings/${da}-${mo}-${y}?latitude=3.0449&longitude=101.4456&method=17`);
        const d = await r.json(); const x = d && d.data && d.data.timings;
        if(x) out = {date: t, zone, src: 'Aladhan (JAKIM)', times: {imsak: hm(x.Imsak), subuh: hm(x.Fajr), syuruk: hm(x.Sunrise), zohor: hm(x.Dhuhr), asar: hm(x.Asr), maghrib: hm(x.Maghrib), isyak: hm(x.Isha)}};
      } catch(e){}
    }
    if(!out) return J({error: 'solat'}, 502);
    await setMeta(env, key, JSON.stringify(out));
    return J(out);
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
      if(!r) return T('Not found', 404);
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
  if(p === '/api/usage' && m === 'GET'){
    const fx = await usdToMyr(env), t = todayLocal(), ym = t.slice(0, 7), from = addDays(t, -29);
    const rows = (await env.DB.prepare('SELECT day, model, calls, inp, outp, usd FROM ai_usage ORDER BY day').all()).results || [];
    const sum = arr => arr.reduce((a, r) => ({calls: a.calls + r.calls, inp: a.inp + r.inp, outp: a.outp + r.outp, usd: a.usd + r.usd}), {calls: 0, inp: 0, outp: 0, usd: 0});
    const withRm = o => ({...o, rm: Math.round(o.usd * fx.rate * 10000) / 10000});
    const days = [];
    for(let d = from; d <= t; d = addDays(d, 1)) days.push(withRm({day: d, ...sum(rows.filter(r => r.day === d))}));
    const models = {};
    rows.filter(r => r.day.startsWith(ym)).forEach(r => { models[r.model] = sum([models[r.model] || {calls: 0, inp: 0, outp: 0, usd: 0}, r]); });
    const since = rows.length ? rows[0].day : t;
    return J({rate: fx.rate, rateLive: fx.live, rateDate: fx.date, since,
      today: withRm(sum(rows.filter(r => r.day === t))), month: withRm(sum(rows.filter(r => r.day.startsWith(ym)))), all: withRm(sum(rows)),
      days, models: Object.entries(models).map(([model, v]) => withRm({model, ...v}))});
  }
  if(p === '/api/settings' && m === 'GET'){
    let key = await getMeta(env, 'digest_key');
    if(!key){ key = randomKey(); await setMeta(env, 'digest_key', key); }
    const u = await env.DB.prepare('SELECT n FROM usage WHERE day = ?').bind(todayLocal()).first();
    return J({digestPagi: `${url.origin}/r/${key}/pagi`, digestMinggu: `${url.origin}/r/${key}/minggu`, claudeToday: u ? u.n : 0, claudeLimit: DAILY_CLAUDE_LIMIT, hasKey: !!env.ANTHROPIC_API_KEY});
  }
  if(p === '/api/settings/rotate' && m === 'POST'){ const key = randomKey(); await setMeta(env, 'digest_key', key); return J({ok: true}); }

  return T('Not found', 404);
}

export default {
  async fetch(req, env, ctx){
    try { return await handle(req, env, ctx); }
    catch(e){ return J({error: 'server', message: String(e && e.message || e)}, 500); }
  },
  async scheduled(event, env, ctx){
    // 00:00 UTC = 8:00 pagi waktu Malaysia: hantar notifikasi pagi ke semua peranti yang dihidupkan
    ctx.waitUntil(morningPushOnce(env).catch(() => {}));
  }
};
