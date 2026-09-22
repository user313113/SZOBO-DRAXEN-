"""Create an offline browser preview from actual CLI renderer output.

Run from the repository root: python tools/preview_terminal.py
The generated HTML is intentionally kept under ignored reports/, not in Git.
"""

import html
import io
import os
import re
import sys
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from draxen.terminal_ui import TerminalUI, Span


SGR = re.compile(r"\x1b\[([0-9;]*)m")


def ansi_html(text):
    """The preview forces 24-bit ANSI, so only RGB and bold are needed."""
    parts, offset, opened = [], 0, False
    for match in SGR.finditer(text):
        parts.append(html.escape(text[offset:match.start()]))
        if opened:
            parts.append("</span>")
            opened = False
        codes = [int(n) for n in match.group(1).split(";") if n]
        if codes and codes != [0]:
            styles = []
            if codes[0] == 1:
                styles.append("font-weight:600")
                codes = codes[1:]
            if len(codes) == 5 and codes[:2] == [38, 2]:
                styles.append(f"color:rgb({codes[2]},{codes[3]},{codes[4]})")
            parts.append('<span style="' + ";".join(styles) + '">')
            opened = True
        offset = match.end()
    parts.append(html.escape(text[offset:]))
    if opened:
        parts.append("</span>")
    return "".join(parts)


def build_preview(destination):
    templates = []
    for width in (108, 80, 38):
        for mode in ("color", "ascii", "plain"):
            stream = io.StringIO()
            with patch.dict(os.environ, {"TERM": "xterm-256color", "COLORTERM": "truecolor", "LINES": "40" if width > 38 else "28"}, clear=True):
                console = TerminalUI(stream, width=width, color="always", ascii_only=mode == "ascii", plain=mode == "plain")
                console.home(interactive=mode != "plain")
                if mode != "plain":
                    stream.write(console.line([Span("› ", "green"), Span("Seçim > ", "cyan")]))
            templates.append(f'<template id="view-{width}-{mode}">{ansi_html(stream.getvalue().strip(chr(10)))}</template>')
    page = '''<!doctype html>
<html lang="tr"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>DRAXEN / Terminal önizlemesi</title>
<style>
:root{color-scheme:dark;--bg:#090d14;--line:#222e40;--text:#dde6f2;--muted:#90a1b8;--cyan:#5ee4ef}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font-family:system-ui,-apple-system,sans-serif}
main{max-width:1140px;margin:auto;padding:40px 28px 24px}header{display:flex;justify-content:space-between;align-items:center;gap:20px;padding-bottom:28px;border-bottom:1px solid var(--line)}
.brand{font:700 19px monospace;letter-spacing:2px}.brand i{font-style:normal;color:var(--cyan)}.version{color:var(--muted);font:11px monospace;letter-spacing:1px}
.intro{margin:32px 0 24px}.eyebrow{font:11px monospace;color:var(--cyan);letter-spacing:2px}h1{font-size:30px;font-weight:550;letter-spacing:-1px;margin:10px 0}p{color:var(--muted);font-size:14px;line-height:1.7;margin:8px 0}
.controls{display:flex;align-items:center;justify-content:space-between;gap:16px;flex-wrap:wrap;margin:24px 0 16px}.sizes{display:flex;gap:5px;background:#101722;border:1px solid var(--line);padding:4px;border-radius:9px}
button,select{font:12px ui-monospace,monospace;color:var(--muted);background:transparent;border:1px solid transparent;border-radius:5px;padding:9px 14px;cursor:pointer}
button[aria-pressed=true]{background:#193039;color:var(--cyan);border-color:#2d535d}button:hover{color:white}button:focus-visible,select:focus-visible{outline:2px solid var(--cyan);outline-offset:3px}select{border-color:var(--line);background:#101722}
.terminal{border:1px solid #2c3b50;border-radius:12px;overflow:hidden;background:#101415;box-shadow:0 20px 60px #0005}.bar{display:flex;gap:10px;align-items:center;background:#111925;border-bottom:1px solid var(--line);padding:14px 20px;font:11px ui-monospace,monospace;color:var(--muted)}.dot{width:6px;height:6px;border-radius:50%;background:var(--cyan);box-shadow:0 0 8px #5ee4ef55}.bar strong{font-weight:400;color:var(--text)}.bar .label{margin-left:auto;font-size:10px;color:#c1a1ff}
.viewport{overflow:auto;padding:24px 22px}pre{display:block;width:max-content;margin:0 auto;font:14px/1.15 "DejaVu Sans Mono","Liberation Mono",Consolas,monospace;letter-spacing:0;font-variant-ligatures:none;font-feature-settings:"liga" 0;tab-size:4;white-space:pre}pre span{font-family:inherit}
.command{display:flex;gap:18px;align-items:center;justify-content:space-between;padding:18px 0;margin-top:6px;border-bottom:1px solid var(--line)}code{color:var(--cyan);font:12px monospace}.command button{border-color:var(--line)}footer{display:flex;justify-content:space-between;gap:20px;padding-top:20px;color:var(--muted);font:11px monospace}
@media(max-width:600px){main{padding:24px 12px}header{padding:0 4px 20px}.version{font-size:9px}h1{font-size:24px}.intro{margin:26px 4px 18px}.controls{gap:10px}.sizes button{padding:8px 10px;font-size:11px}select{font-size:11px;max-width:140px;padding:8px}.viewport{padding:18px 10px}pre{font-size:clamp(11px,calc((100vw - 60px)/23),14px);line-height:1.15}.bar{padding:12px;font-size:10px;gap:6px}.bar .label{font-size:9px}.command{padding:14px 4px;gap:8px}code{font-size:11px}footer{font-size:9px;line-height:1.6}}
</style></head><body><main>
<header><div class="brand"><i>▰</i> SZOBO / DRAXEN</div><div class="version">TERMINAL UI / 1.6.0</div></header>
<div class="intro"><div class="eyebrow">KAYNAKLARDAN KANITA.</div><h1>Tarayıcıda değil. Terminalin içinde.</h1><p>Katmanlı SZOBO / DRAXEN başlığı ve doğrudan Termux/iSH içinde çalışan yerel menü.<br>Bu sayfa yalnızca açılış ekranının statik önizlemesidir. Uygulamayı terminalde başlatın.</p></div>
<div class="controls"><div class="sizes" aria-label="Terminal genişliği"><button type="button" data-width="108" aria-pressed="true">108 kolon</button><button type="button" data-width="80" aria-pressed="false">80 kolon</button><button type="button" data-width="38" aria-pressed="false">38 kolon</button></div><label><select id="mode" aria-label="Görünüm"><option value="color">ANSI / Piksel</option><option value="ascii">ASCII uyumlu</option><option value="plain">Sade çıktı</option></select></label></div>
<div class="terminal"><div class="bar"><span class="dot"></span><strong>python -m draxen</strong><span class="label" id="dimensions">108 KOLON / TRUECOLOR</span></div><div class="viewport"><pre id="screen" aria-label="DRAXEN terminal çıktısı"></pre></div></div>
<div class="command"><code id="command">python -m draxen</code><button type="button" id="copy">Komutu kopyala</button></div>
<footer><span>STANDART KÜTÜPHANE / SIFIR EK PAKET</span><span>TERMUX · iSH · MASAÜSTÜ</span></footer>
''' + "\n".join(templates) + '''
<script>
const fittedWidth = () => window.innerWidth < 800 ? 38 : window.innerWidth < 1020 ? 80 : 108;
let width = fittedWidth(), manualWidth = false;
const mode = document.getElementById('mode');
function render(){
  document.getElementById('screen').replaceChildren(document.getElementById(`view-${width}-${mode.value}`).content.cloneNode(true));
  document.querySelectorAll('[data-width]').forEach(button=>button.setAttribute('aria-pressed',String(Number(button.dataset.width)===width)));
  document.getElementById('dimensions').textContent=`${width} KOLON / ${mode.value==='plain'?'SADE':mode.value==='ascii'?'ASCII':'TRUECOLOR'}`;
  document.getElementById('command').textContent='python -m draxen'+(mode.value==='ascii'?' --ascii':mode.value==='plain'?' --plain':'');
}
document.querySelectorAll('[data-width]').forEach(button=>button.onclick=()=>{manualWidth=true;width=Number(button.dataset.width);render()});
mode.onchange=render;
window.addEventListener('resize',()=>{if(!manualWidth){width=fittedWidth();render()}});
document.getElementById('copy').onclick=async function(){try{await navigator.clipboard.writeText(document.getElementById('command').textContent);this.textContent='Kopyalandı';setTimeout(()=>this.textContent='Komutu kopyala',1400)}catch{this.textContent='Komutu seçip kopyala'}};
render();
</script></main></body></html>'''
    destination = Path(destination)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(page, encoding="utf-8")
    return destination


if __name__ == "__main__":
    print(build_preview(Path("reports/terminal-preview/index.html")))
