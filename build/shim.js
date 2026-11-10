// Penyambung untuk heyarmay.com: menyediakan window.claude.use(...) yang sama bentuknya
// dengan versi dalam Claude, tetapi disokong oleh API Worker sendiri (/api/*).
(function(){
  window.__standalone = true;

  async function api(path, opts){
    const r = await fetch(path, Object.assign({credentials:'same-origin'}, opts || {}));
    if(r.status === 401 || r.status === 403){ location.reload(); throw {code:'revoked', message:'Session expired'}; }
    if(!r.ok){
      let msg = ''; try { msg = await r.text(); } catch(e){}
      throw {code: r.status === 413 ? 'quota_exceeded' : r.status === 404 ? 'invalid_argument' : r.status === 429 ? 'resource_exhausted' : 'unavailable', message: msg};
    }
    return r.status === 204 ? null : r.json();
  }
  const json = (method, body) => ({method, headers:{'content-type':'application/json'}, body:JSON.stringify(body)});

  /* ---------- db ---------- */
  function makeDB(){
    const subs = new Set();
    const snap = rows => {
      const docs = rows.map(r => ({id:r.id, exists:true, data:() => r.data, metadata:{fromCache:false, hasPendingWrites:false}}));
      return {docs, size:docs.length, empty:!docs.length, docChanges:() => [], metadata:{fromCache:false, hasPendingWrites:false}};
    };
    const fetchColl = (coll, filters) => {
      const q = new URLSearchParams({coll});
      for(const [f, op, v] of filters){ if(op === '>=') q.set('gte_' + f, v); else if(op === '==') q.set('eq_' + f, v); }
      return api('/api/docs?' + q.toString());
    };
    async function refresh(s){ try { s.next(snap(await fetchColl(s.coll, s.filters))); } catch(e){ if(e && e.code === 'revoked' && s.err) s.err(e); } }
    const refreshAll = () => subs.forEach(refresh);
    setInterval(() => { if(document.visibilityState === 'visible') refreshAll(); }, 30000);
    document.addEventListener('visibilitychange', () => { if(document.visibilityState === 'visible') refreshAll(); });
    function query(coll, filters){
      return {
        where(f, op, v){ return query(coll, filters.concat([[f, op, v]])); },
        orderBy(){ return query(coll, filters); },
        limit(){ return query(coll, filters); },
        onSnapshot(next, err){ const s = {coll, filters, next, err}; subs.add(s); refresh(s); return () => subs.delete(s); },
        async get(){ return snap(await fetchColl(coll, filters)); }
      };
    }
    const newId = () => (crypto.randomUUID ? crypto.randomUUID() : String(Math.random()).slice(2) + Date.now()).replace(/-/g, '').slice(0, 20);
    function docRef(coll, id){
      id = id || newId();
      const url = `/api/docs/${encodeURIComponent(coll)}/${encodeURIComponent(id)}`;
      return {
        id, path: coll + '/' + id,
        async set(data){ await api(url, json('PUT', data)); refreshAll(); },
        async update(data){ await api(url, json('PATCH', data)); refreshAll(); },
        async delete(){ await api(url, {method:'DELETE'}); refreshAll(); },
        async get(){ const rows = await fetchColl(coll, []); const r = rows.find(x => x.id === id); return {id, exists:!!r, data:() => r && r.data}; }
      };
    }
    return {
      collection(coll){ return Object.assign(query(coll, []), {path:coll, doc:id => docRef(coll, id), async add(d){ const r = docRef(coll); await r.set(d); return r; }}); },
      doc(p){ const i = p.lastIndexOf('/'); return docRef(p.slice(0, i), p.slice(i + 1)); }
    };
  }

  /* ---------- sample (Claude) ---------- */
  const toB64 = blob => new Promise((res, rej) => { const fr = new FileReader(); fr.onload = () => { const s = String(fr.result); res({media_type: blob.type || 'image/jpeg', data: s.slice(s.indexOf(',') + 1)}); }; fr.onerror = rej; fr.readAsDataURL(blob); });
  function parseLoose(t){
    t = String(t || '').trim();
    try { return JSON.parse(t); } catch(e){}
    const fence = t.match(/```(?:json)?\s*([\s\S]*?)```/); if(fence){ try { return JSON.parse(fence[1]); } catch(e){} }
    const a = t.search(/[\[{]/), b = Math.max(t.lastIndexOf('}'), t.lastIndexOf(']'));
    if(a >= 0 && b > a){ try { return JSON.parse(t.slice(a, b + 1)); } catch(e){} }
    return undefined;
  }
  async function callClaude(input, opts, asJson){
    opts = opts || {};
    const body = {input, json:!!asJson, tier: opts.modelTier || 'default'};
    if(opts.images){
      const list = opts.images instanceof Blob ? [opts.images] : Array.from(opts.images);
      body.images = await Promise.all(list.slice(0, 6).map(toB64));
    }
    let r;
    try { r = await fetch('/api/claude', Object.assign(json('POST', body), {signal: opts.signal, credentials:'same-origin'})); }
    catch(e){ throw (e && e.name === 'AbortError') ? {code:'cancelled', message:'cancelled'} : {code:'upstream_error', message:String(e)}; }
    if(r.status === 401 || r.status === 403){ location.reload(); throw {code:'not_granted', message:'Session expired'}; }
    if(!r.ok){
      let m = ''; try { m = await r.text(); } catch(e){}
      throw {code: r.status === 429 ? 'rate_limited' : r.status === 503 ? 'sampling_disabled' : r.status === 400 ? 'invalid_request' : 'upstream_error', message:m};
    }
    const out = await r.json();
    if(opts.onText && out.text) try { opts.onText({text:out.text, delta:out.text}); } catch(e){}
    return {text: out.text, truncated: !!out.truncated, modelTierApplied: body.tier};
  }
  const sample = (input, opts) => callClaude(input, opts, false);
  sample.json = async (input, opts) => {
    const r = await callClaude(input, opts, true);
    const v = parseLoose(r.text);
    if(v === undefined) throw {code:'invalid_json', message:'Response was not JSON', text:r.text};
    return v;
  };
  sample.limits = async () => ({maxPromptBytes:262144, images:{maxCount:6, maxInputBytes:20e6, mediaTypes:['image/jpeg','image/png','image/webp','image/gif']}, tools:null});

  /* ---------- assets (gambar resit) ---------- */
  const assets = {
    async upload(blob, o){
      const type = (o && o.type) || blob.type || 'image/jpeg';
      const r = await api('/api/files', {method:'POST', headers:{'content-type':type}, body:blob});
      return {id:r.id, url:'/_blob/' + r.id, sizeBytes:r.size, contentType:type};
    },
    async delete(id){ await api('/api/files/' + encodeURIComponent(id), {method:'DELETE'}); return {deleted:true}; },
    async list(){ return {assets:[], usage:{}}; }
  };

  /* ---------- downloads ---------- */
  const downloads = {
    async save({filename, data}){
      const blob = data instanceof Blob ? data : new Blob([data]);
      const a = document.createElement('a');
      a.href = URL.createObjectURL(blob); a.download = filename;
      document.body.appendChild(a); a.click();
      setTimeout(() => { URL.revokeObjectURL(a.href); a.remove(); }, 4000);
      return {status:'saved'};
    }
  };

  const caps = {db:makeDB(), sample, assets, downloads};
  window.claude = {use: async name => caps[name] || null};

  /* ---------- pautan Akaun (tukar kata laluan / log keluar) ---------- */
  document.addEventListener('DOMContentLoaded', () => {
    const brand = document.querySelector('.side-top .brand');
    if(!brand) return;
    const st = document.createElement('style');
    st.textContent = '.side-top .brand{display:flex;align-items:center}.side-top .brand .acct{margin-left:auto;font:600 .75rem/1 var(--f-body,system-ui);color:var(--muted);text-decoration:none;border:1px solid var(--line);border-radius:999px;padding:5px 10px;letter-spacing:0;text-transform:none}.side-top .brand .acct:hover{color:var(--accent);border-color:var(--accent)}';
    document.head.appendChild(st);
    const a = document.createElement('a');
    a.className = 'acct'; a.href = '/akaun'; a.textContent = 'Account';
    brand.appendChild(a);
  });
})();
