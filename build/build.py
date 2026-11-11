import base64, io, json, pathlib
from PIL import Image, ImageDraw, ImageFont

HERE = pathlib.Path(__file__).parent
PAGE = (HERE.parent / 'pengurusan-diri.html').read_text()
SHIM = (HERE / 'shim.js').read_text()
SERVER = (HERE / 'server.js').read_text()
FUTUR_CSS = (HERE / 'futur.css').read_text()
FUTUR_JS = (HERE / 'futur.js').read_text()

ACCENT, PAPER = (17, 21, 47), (94, 234, 212)

def f64(name):
    return base64.b64encode((HERE.parent / 'logo' / name).read_bytes()).decode()

def icon(size):
    im = Image.new('RGBA', (size, size), ACCENT + (255,))
    d = ImageDraw.Draw(im)
    s = size / 512
    # tick inside a rounded "card", matching the app's checkbox mark
    d.rounded_rectangle([118*s, 118*s, 394*s, 394*s], radius=56*s, outline=PAPER + (255,), width=int(22*s))
    d.line([(180*s, 262*s), (238*s, 320*s), (338*s, 198*s)], fill=(156, 142, 255, 255), width=int(40*s), joint='curve')
    buf = io.BytesIO(); im.save(buf, 'PNG', optimize=True)
    return base64.b64encode(buf.getvalue()).decode()

ICON_SVG = ('<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 512 512"><defs><linearGradient id="g" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="#5EEAD4"/><stop offset=".55" stop-color="#86B4FF"/><stop offset="1" stop-color="#9C8EFF"/></linearGradient></defs>'
            '<rect width="512" height="512" rx="112" fill="#11152F"/>'
            '<rect x="129" y="129" width="254" height="254" rx="50" fill="none" stroke="url(#g)" stroke-width="22"/>'
            '<path d="M180 262l58 58 100-122" fill="none" stroke="url(#g)" stroke-width="40" stroke-linecap="round" stroke-linejoin="round"/></svg>')
MANIFEST = json.dumps({
    'name': 'Hey Armay', 'short_name': 'Hey Armay', 'start_url': '/', 'display': 'standalone',
    'background_color': '#11152F', 'theme_color': '#EDF0F8', 'lang': 'en',
    'id': '/',
    'icons': [{'src': '/icon-192.png?v=3', 'sizes': '192x192', 'type': 'image/png', 'purpose': 'any'},
              {'src': '/icon-512.png?v=3', 'sizes': '512x512', 'type': 'image/png', 'purpose': 'any'},
              {'src': '/icon-mask-192.png?v=3', 'sizes': '192x192', 'type': 'image/png', 'purpose': 'maskable'},
              {'src': '/icon-mask-512.png?v=3', 'sizes': '512x512', 'type': 'image/png', 'purpose': 'maskable'}],
    'shortcuts': [
      {'name': 'Speak', 'short_name': 'Speak', 'description': 'Speak and let Claude sort it', 'url': '/?go=speak', 'icons': [{'src': '/sc-speak.png?v=1', 'sizes': '192x192', 'type': 'image/png'}]},
      {'name': 'Write', 'short_name': 'Write', 'description': 'Quick note or task', 'url': '/?go=write', 'icons': [{'src': '/sc-write.png?v=1', 'sizes': '192x192', 'type': 'image/png'}]},
      {'name': 'Today', 'short_name': 'Today', 'description': "Today's plan", 'url': '/#hari-ini', 'icons': [{'src': '/sc-today.png?v=1', 'sizes': '192x192', 'type': 'image/png'}]},
      {'name': 'Log expense', 'short_name': 'Expense', 'description': 'Record spending', 'url': '/?go=expense', 'icons': [{'src': '/sc-expense.png?v=1', 'sizes': '192x192', 'type': 'image/png'}]}]})

HEAD = ('<!doctype html><html lang="en"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover,interactive-widget=resizes-content">'
        '<meta name="theme-color" content="#EDF0F8">'
        '<link rel="manifest" href="/manifest.webmanifest"><link rel="icon" href="/favicon.png?v=3" type="image/png">'
        '<link rel="apple-touch-icon" href="/apple-touch-icon.png?v=3"><meta name="apple-mobile-web-app-capable" content="yes">'
        '<meta name="apple-mobile-web-app-title" content="Hey Armay">'
        '<style>:root{color-scheme:light;padding-top:env(safe-area-inset-top,0px);padding-bottom:env(safe-area-inset-bottom,0px)}'
        'body{margin:0;font:14px/1.4 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}img{max-width:100%}[hidden]{display:none!important}</style>'
        '<script>(function(){var t;try{t=localStorage.getItem("hy-theme")}catch(e){}if(t!=="dark"&&t!=="light")t="light";document.documentElement.setAttribute("data-hy",t);var m=document.querySelector("meta[name=theme-color]");if(m)m.content=t==="dark"?"#080B1C":"#EDF0F8";})();</script>'
        '<script>' + SHIM + '</script></head><body>')
PAGE = PAGE.replace('<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Familjen+Grotesk:wght@500;600;700&family=Figtree:wght@400;500;600;700&family=JetBrains+Mono:wght@500&display=swap">', '<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Geist:wght@400;500;600;700&family=Geist+Mono:wght@500&display=swap">')
PAGE2 = PAGE.replace('</style>', '</style>\n<style id="futur">' + FUTUR_CSS + '</style>', 1)
APP_HTML = HEAD + PAGE2 + '<script>' + FUTUR_JS + '</script></body></html>'
(HERE / 'dist').mkdir(exist_ok=True)
(HERE / 'dist' / 'app.html').write_text(APP_HTML)

out = (SERVER
       + '\nconst APP_HTML = ' + json.dumps(APP_HTML) + ';'
       + '\nconst ICON_SVG = ' + json.dumps(ICON_SVG) + ';'
       + '\nconst MANIFEST = ' + json.dumps(MANIFEST) + ';'
       + '\nconst ICON_192 = ' + json.dumps(f64('icon-192.png')) + ';'
       + '\nconst ICON_512 = ' + json.dumps(f64('icon-512.png')) + ';'
       + '\nconst ICON_180 = ' + json.dumps(f64('icon-180.png')) + ';'
       + '\nconst ICON_64 = ' + json.dumps(f64('icon-64.png')) + ';'
       + '\nconst ICON_MASK_192 = ' + json.dumps(f64('icon-mask-192.png')) + ';'
       + '\nconst ICON_MASK_512 = ' + json.dumps(f64('icon-mask-512.png')) + ';'
       + '\nconst SC_PNGS = ' + json.dumps({'/sc-' + n + '.png': f64('sc-' + n + '.png') for n in ['speak', 'write', 'today', 'expense']}) + ';'
       + '\nconst WIDGET_APK = ' + json.dumps(f64('HeyArmayWidget.apk')) + ';'
       + '\nconst LOGO_PNG = ' + json.dumps(f64('logo-640.png')) + ';\n')
(HERE / 'dist').mkdir(exist_ok=True)
(HERE / 'dist' / 'worker.js').write_text(out)
print('worker.js', len(out.encode()) // 1024, 'KB')
