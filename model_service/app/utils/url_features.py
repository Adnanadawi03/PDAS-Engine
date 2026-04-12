import re
from urllib.parse import urlparse

SUSPICIOUS_WORDS = ("login","verify","secure","account","update","bank","otp")

def extract_url_features(url: str) -> dict:
    u = urlparse(url)
    host = u.netloc or ""
    return {
        "len": len(url),
        "num_dots": url.count("."),
        "has_ip": bool(re.match(r"^(?:\d{1,3}\.){3}\d{1,3}$", (host.split(":")[0]))),
        "tld_len": len(host.split(".")[-1]) if "." in host else 0,
        "path_len": len(u.path or ""),
        "query_len": len(u.query or ""),
        "susp_words": sum(w in url.lower() for w in SUSPICIOUS_WORDS),
        "num_hyphen": url.count("-"),
        "num_digits": sum(c.isdigit() for c in url),
        "subdomain_depth": max(0, len(host.split(".")) - 2),
        "starts_https": url.lower().startswith("https"),
        "has_at": "@" in url,
    }
