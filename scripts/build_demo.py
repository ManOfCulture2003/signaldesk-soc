"""Build a public demo using only the bundled synthetic fixture."""
import json
from pathlib import Path
import tempfile

from signaldesk.demo import demo_payload
from signaldesk.store import Store
from signaldesk.detections import RULES

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "demo"
OUT.mkdir(exist_ok=True)
with tempfile.TemporaryDirectory() as folder:
    store = Store(Path(folder) / "demo.sqlite")
    store.ingest(demo_payload())
    store.run_detection()
    seed = {"events": store.events(limit=500)["items"], "rules": RULES,
            "cases": {a["id"]: store.case(a["id"]) for a in store.alerts()}}
(OUT / "seed.js").write_text("window.DEMO_SEED = " + json.dumps(seed, ensure_ascii=True) + ";\n", encoding="utf-8")
static = ROOT / "signaldesk/static"
html = (static / "index.html").read_text(encoding="utf-8")
html = html.replace('/static/style.css', './style.css').replace('/static/app.js', './app.js')
html = html.replace('<script src="./app.js"', '<script src="./seed.js" defer></script><script src="./demo.js" defer></script><script src="./app.js"')
html = html.replace('● LOCAL INVESTIGATION WORKBENCH', 'INTERACTIVE DEMO · SYNTHETIC DATA')
html = html.replace('id="detect">Run detections', 'id="detect">Replay sample results')
html = html.replace('<main>', '<main><section class="demo-notice"><strong>Try SignalDesk — no account needed.</strong><p>This is a working investigation demo with 16 synthetic events. It does not read your device. Decisions stay in this browser tab. Nothing is sent to the project owner.</p><a href="https://github.com/ManOfCulture2003/signaldesk-soc/tree/secure-local-and-demo-nov08#quick-start" target="_blank" rel="noopener">Run the real local app →</a></section>')
html = html.replace('id="lock" type="button">Lock workspace', 'id="lock" type="button">Reset demo')
html = html.replace('<button id="collect-windows" type="button">Read this PC’s Security log</button>', '')
html = html.replace('<section class="import">', '<section class="import" hidden>')
html = html.replace('Single-user local lab · No automatic containment · UTC event timestamps · Synthetic records are labeled throughout', 'Browser demo · Synthetic evidence · No device access · No accounts or tracking · Reset clears this tab’s decisions')
(OUT / "index.html").write_text(html, encoding="utf-8")
css = (static / "style.css").read_text(encoding="utf-8")
css += '\n[hidden]{display:none!important}.demo-notice{padding:20px;border:1px solid #6cddc2;border-radius:10px;margin-bottom:24px;background:#142631}.intro{flex-wrap:wrap}.intro>div{flex:1 1 300px}button:focus-visible,a:focus-visible{outline:3px solid #6cddc2;outline-offset:3px}\n'
(OUT / "style.css").write_text(css, encoding="utf-8")
js = (static / "app.js").read_text(encoding="utf-8")
start, end = js.index('async function api('), js.index('function action(')
js = js[:start] + 'async function api(path, options={}) { return window.demoApi(path, options); }\n' + js[end:]
js = js[:js.index("$('lock').addEventListener")]
js = js.replace('Detections complete:', 'Bundled Python detection results replayed:')
js += "$('lock').addEventListener('click',()=>{window.resetDemo();location.reload();});\n"
js = js.replace("link.href='/api/alerts/'+id+'/export';", "link.href='#';link.addEventListener('click',event=>{event.preventDefault();window.downloadDemoCase(id);});")
(OUT / "app.js").write_text(js, encoding="utf-8")
(OUT / ".nojekyll").touch()
