# SPDX-License-Identifier: EUPL-1.2
"""Record the office's story mode frame by frame and write an animated GIF.

    .venv/bin/python scripts/make_gif.py [--chrome PATH] [--fps 12]

Opens docs/office.html#story&capture in headless Chrome, drives the page's virtual clock through
the DevTools protocol, and collects one canvas frame per tick. Needs `websocket-client` and
Pillow, neither of which the proof of concept itself needs.
"""
from __future__ import annotations

import argparse
import base64
import functools
import http.server
import io
import json
import shutil
import subprocess
import tempfile
import threading
import time
import urllib.request
from pathlib import Path

import websocket
from PIL import Image

DOCS = Path(__file__).resolve().parents[1] / "docs"


class Page:
    def __init__(self, ws_url: str):
        self.ws, self.n = websocket.create_connection(ws_url, timeout=60, max_size=None), 0

    def eval(self, expr: str):
        self.n += 1
        self.ws.send(json.dumps({"id": self.n, "method": "Runtime.evaluate",
                                 "params": {"expression": expr, "returnByValue": True, "awaitPromise": True}}))
        while True:
            m = json.loads(self.ws.recv())
            if m.get("id") == self.n:
                if "exceptionDetails" in m.get("result", {}):
                    raise RuntimeError(m["result"]["exceptionDetails"])
                return m["result"]["result"].get("value")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--chrome", default=shutil.which("chromium") or shutil.which("google-chrome") or
                    str(Path.home() / ".cache/ms-playwright/chromium_headless_shell-1248/"
                        "chrome-headless-shell-linux64/chrome-headless-shell"))
    ap.add_argument("--fps", type=int, default=12)
    ap.add_argument("--out", default=str(DOCS / "media" / "office"))
    a = ap.parse_args()

    handler = functools.partial(http.server.SimpleHTTPRequestHandler, directory=str(DOCS))
    httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    handler.log_message = lambda *x: None
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    port = httpd.server_address[1]

    prof = tempfile.mkdtemp()
    chrome = subprocess.Popen([a.chrome, "--headless", "--no-sandbox", "--remote-debugging-port=9339",
                               f"--user-data-dir={prof}", "--window-size=1100,800", "about:blank"],
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        for _ in range(100):
            try:
                tabs = json.load(urllib.request.urlopen("http://127.0.0.1:9339/json"))
                break
            except OSError:
                time.sleep(.1)
        page = Page(next(t for t in tabs if t["type"] == "page")["webSocketDebuggerUrl"])
        page.eval(f"location.href = 'http://127.0.0.1:{port}/office.html#story&capture'")
        time.sleep(1)
        for _ in range(200):
            try:
                if page.eval("window.__ready && window.__ready()") and page.eval("document.fonts.ready.then(() => true)"):
                    break
            except RuntimeError:
                pass
            time.sleep(.1)
        frames, t, dt, tail = [], 0.0, 1000 / a.fps, None
        while True:
            url = page.eval(f"__frame({t})")
            frames.append(Image.open(io.BytesIO(base64.b64decode(url.split(",", 1)[1]))).convert("RGB"))
            t += dt
            if tail is None and page.eval("__done()"):
                tail = len(frames) + 2 * a.fps            # hold the last frame for 2 s
            if tail is not None and len(frames) >= tail or len(frames) > 5000:
                break
    finally:
        chrome.terminate()
        httpd.shutdown()
    out = Path(a.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    # one palette for all frames, no dithering: pixel art stays crisp and the GIF stays small
    pal = frames[len(frames) // 3].quantize(colors=128, method=Image.Quantize.MEDIANCUT, dither=Image.Dither.NONE)
    q = [f.quantize(palette=pal, dither=Image.Dither.NONE) for f in frames]
    q[0].save(out.with_suffix(".gif"), save_all=True, append_images=q[1:], duration=int(dt), loop=0, optimize=True,
              disposal=1)
    print(f"{len(frames)} frames, {len(frames) / a.fps:.0f} s -> {out.with_suffix('.gif')} "
          f"({out.with_suffix('.gif').stat().st_size / 1e6:.1f} MB)")


if __name__ == "__main__":
    main()
