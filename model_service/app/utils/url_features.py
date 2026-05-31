import re
from urllib.parse import urlparse

from .url_ml_features import extract_ml_url_features
from .url_utils import build_host_context

SUSPICIOUS_WORDS = ("login","verify","secure","account","update","bank","otp")
SUSPICIOUS_EXTENSIONS = (".exe", ".scr", ".js", ".vbs", ".bat", ".cmd", ".ps1", ".zip", ".iso")

def extract_url_features(url: str) -> dict:
    u = urlparse(url)
    ctx = build_host_context(url)
    host = ctx["host"]
    path = u.path or ""
    lower_url = url.lower()
    features = {
        "len": len(url),
        "num_dots": url.count("."),
        "has_ip": bool(re.match(r"^(?:\d{1,3}\.){3}\d{1,3}$", host)),
        "tld_len": len(host.split(".")[-1]) if "." in host else 0,
        "path_len": len(path),
        "query_len": len(u.query or ""),
        "susp_words": sum(w in lower_url for w in SUSPICIOUS_WORDS),
        "num_hyphen": url.count("-"),
        "num_digits": sum(c.isdigit() for c in url),
        "subdomain_depth": max(0, len(host.split(".")) - 2),
        "starts_https": lower_url.startswith("https"),
        "has_at": "@" in url,
        "host_len": len(host),
        "registered_domain_len": len(ctx["registered_domain"]),
        "path_segments": ctx["path_segments"],
        "query_param_count": ctx["query_param_count"],
        "percent_encoded_count": lower_url.count("%"),
        "has_suspicious_extension": any(path.lower().endswith(ext) for ext in SUSPICIOUS_EXTENSIONS),
    }
    features.update(extract_ml_url_features(url))
    return features
