import re
from urllib.parse import urlparse

from ..app.config import get_settings
from ..app.utils.url_utils import build_host_context, host_matches_domain

RISKY_TLDS = (
    ".tk", ".top", ".gq", ".ml", ".cf", ".zip", ".mov",
    ".xyz", ".info", ".pw", ".cc", ".biz", ".click",
    ".online", ".icu", ".buzz", ".cyou", ".cfd", ".sbs",
)
URL_SUSPICIOUS_WORDS = ("login", "verify", "secure", "account", "update", "reset", "signin", "password")
URL_SHORTENER_DOMAINS = {
    "bit.ly", "cutt.ly", "goo.gl", "is.gd", "lnkd.in",
    "ow.ly", "rb.gy", "rebrand.ly", "shorturl.at", "t.co",
    "tiny.cc", "tinyurl.com",
}
PROTECTED_BRANDS = {
    "microsoft": ("microsoft.com", "microsoftonline.com", "office.com", "live.com"),
    "office": ("microsoft.com", "microsoftonline.com", "office.com", "live.com"),
    "office365": ("microsoft.com", "microsoftonline.com", "office.com", "live.com"),
    "outlook": ("outlook.com", "office.com", "live.com"),
    "live": ("live.com",),
    "onedrive": ("live.com", "microsoft.com", "microsoftonline.com"),
    "google": ("google.com", "googleblog.com", "gmail.com", "youtube.com"),
    "github": ("github.com",),
    "dropbox": ("dropbox.com",),
    "openai": ("openai.com",),
    "paypal": ("paypal.com",),
    "apple": ("apple.com",),
    "adobe": ("adobe.com",),
    "amazon": ("amazon.com", "amazonaws.com"),
    "visa": ("visa.com", "visa.co"),
    "mastercard": ("mastercard.com",),
}


def _find_brand_impersonation(host: str) -> str | None:
    if not host:
        return None

    parts = host.split(".")
    # Exclude TLD (last label) from brand matching — "live", "online", etc. are valid TLDs
    non_tld_parts = parts[:-1] if len(parts) > 1 else parts
    non_tld_host = ".".join(non_tld_parts)
    labels = [p for p in non_tld_parts if p]

    for brand, official_domains in PROTECTED_BRANDS.items():
        if any(host_matches_domain(host, domain) for domain in official_domains):
            continue
        if brand in labels or brand in non_tld_host:
            return brand
    return None


def is_trusted_host(host: str) -> bool:
    trusted_domains = get_settings().trusted_domains
    return any(host_matches_domain(host, domain) for domain in trusted_domains)


def rule_score_url(url: str) -> tuple[float, dict]:
    lower_url = url.lower()
    ctx = build_host_context(url)
    host = ctx["host"]
    path = urlparse(url).path.lower()
    signals, score = {}, 0.0

    if lower_url.startswith("http://"):
        score += 8
        signals["no_https"] = True

    if any(host.endswith(tld) for tld in RISKY_TLDS):
        score += 18
        signals["risky_tld"] = host.rsplit(".", 1)[-1]

    if "@" in url:
        score += 20
        signals["has_at"] = True

    if re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", host):
        score += 25
        signals["ip_host"] = True

    if host in URL_SHORTENER_DOMAINS:
        score += 12
        signals["url_shortener"] = host

    if "xn--" in host:
        score += 20
        signals["punycode"] = True

    if re.search(r"[A-Za-z]\d{6,}", lower_url):
        score += 5
        signals["long_digits"] = True

    susp_word_count = sum(word in lower_url for word in URL_SUSPICIOUS_WORDS)
    if susp_word_count >= 2:
        score += 10
        signals["suspicious_words"] = susp_word_count

    if ctx["label_count"] >= 4 and not re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", host):
        score += 8
        signals["deep_subdomain"] = ctx["label_count"]

    if any(path.endswith(ext) for ext in (".exe", ".scr", ".js", ".vbs", ".zip", ".iso")):
        score += 12
        signals["suspicious_download_extension"] = True

    brand = _find_brand_impersonation(host)
    if brand:
        score += 25
        signals["brand_impersonation"] = brand
        if susp_word_count >= 1:
            score += 12
            signals["brand_plus_lure_words"] = susp_word_count

    if is_trusted_host(host):
        signals["trusted_host"] = ctx["registered_domain"] or host

    return min(score, 100.0), signals


def rule_score_file(features: dict) -> tuple[float, dict]:
    signals, score = {}, 0.0
    ext = ("." + features.get("ext","")).lower()
    if ext in (".exe",".scr",".js",".vbs",".bat",".cmd",".ps1"):
        score += 30; signals["bad_ext"] = True

    if features.get("size", 0) < 1024:
        score += 10; signals["tiny_file"] = True

    if features.get("url_count", 0) >= 3:
        score += 10; signals["many_urls"] = True

    if features.get("entropy", 0) > 7.5:
        score += 10; signals["high_entropy"] = True

    t = features.get("type")
    if t == "pdf":
        if features.get("pdf_has_js"):        score += 20; signals["pdf_js"] = True
        if features.get("pdf_has_openaction"):score += 15; signals["pdf_openaction"] = True
    if t in ("ooxml","ole"):
        if features.get("has_macros"):        score += 25; signals["macros"] = True
    if t == "pe":
        for k, v in features.items():
            if k.startswith("pe_str_") and v:
                score += 10; signals[k] = True

    return min(score, 60.0), signals
