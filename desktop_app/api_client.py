import httpx

API_BASE = "http://127.0.0.1:8000"  # استبدل برابط ngrok في حالة المؤسسات

def scan_url(url: str):
    r = httpx.post(f"{API_BASE}/scan/url", json={"url": url}, timeout=10)
    r.raise_for_status()
    return r.json()

def scan_file(path: str):
    with open(path, "rb") as f:
        files = {"file": (path, f, "application/octet-stream")}
        r = httpx.post(f"{API_BASE}/scan/file", files=files, timeout=30)
    r.raise_for_status()
    return r.json()

def get_events(limit=20):
    r = httpx.get(f"{API_BASE}/events?limit={limit}", timeout=10)
    r.raise_for_status()
    return r.json()
