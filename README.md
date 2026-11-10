# Hey Armay (heyarmay.com)

Sistem pengurusan diri peribadi. Cloudflare Worker + D1.

- `src/worker.js` — kod yang dijalankan (dijana).
- `build/` — sumber: pelayan (`server.js`), halaman aplikasi, lapisan reka bentuk, logo.
- `wrangler.jsonc` — tetapan Worker (D1 `DB`, `ARMEDIA_DB` baca sahaja, laluan heyarmay.com).

Rahsia `ANTHROPIC_API_KEY` disimpan di Cloudflare, bukan di sini.
