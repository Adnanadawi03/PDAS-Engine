# agent.py
import time, os, threading, re
import httpx
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

API_BASE = "http://127.0.0.1:8000"
WATCH_DIRS = [
    os.path.join(os.path.expanduser("~"), "Downloads"),
    # أضف مسارات أخرى لو حاب
]

processed = set()
url_regex = re.compile(r"^https?://", re.I)

def scan_url(url: str):
    try:
        r = httpx.post(f"{API_BASE}/scan/url", json={"url": url}, timeout=10)
        r.raise_for_status()
        data = r.json()
        print(f"[URL] {url} -> score={data['score']} verdict={data['verdict']}")
    except Exception as e:
        print(f"[URL][ERR] {url}: {e}")

def scan_file(path: str):
    try:
        with open(path, "rb") as f:
            files = {"file": (os.path.basename(path), f, "application/octet-stream")}
            r = httpx.post(f"{API_BASE}/scan/file", files=files, timeout=30)
        r.raise_for_status()
        data = r.json()
        print(f"[FILE] {path} -> score={data['score']} verdict={data['verdict']}")
        # مثال: حجر تلقائي إذا عالي الخطورة
        if data["score"] >= 80:
            try:
                qdir = os.path.join(os.path.dirname(path), "_quarantine")
                os.makedirs(qdir, exist_ok=True)
                os.replace(path, os.path.join(qdir, os.path.basename(path)))
                print(f"[FILE] moved to quarantine: {qdir}")
            except Exception as qe:
                print(f"[FILE][QUARANTINE][ERR] {qe}")
    except Exception as e:
        print(f"[FILE][ERR] {path}: {e}")

class Handler(FileSystemEventHandler):
    def on_created(self, event):
        if event.is_directory:
            return
        path = event.src_path
        if path in processed:
            return
        processed.add(path)
        # انتظر لحظة حتى يكتمل تنزيل الملف
        time.sleep(0.5)
        scan_file(path)

def watch_dirs():
    obs = Observer()
    handler = Handler()
    for d in WATCH_DIRS:
        if os.path.isdir(d):
            obs.schedule(handler, d, recursive=False)
            print(f"[WATCH] {d}")
    obs.start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        obs.stop()
    obs.join()

def poll_clipboard():
    try:
        import pyperclip
    except Exception:
        print("[CLIPBOARD] pyperclip not available")
        return
    last = None
    while True:
        try:
            txt = pyperclip.paste()
            if txt and txt != last and url_regex.match(txt.strip()):
                last = txt
                scan_url(txt.strip())
        except Exception as e:
            print(f"[CLIPBOARD][ERR] {e}")
        time.sleep(2)

if __name__ == "__main__":
    # خيّر: شغّل مراقبة المجلد ومراقبة الحافظة بالتوازي
    threading.Thread(target=poll_clipboard, daemon=True).start()
    watch_dirs()
