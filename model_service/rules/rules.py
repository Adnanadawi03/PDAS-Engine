import re
BAD_TLDS = (".ru",".cn",".tk",".top",".xyz")
BRAND_IMPERSONATION = ("microsoft","office","outlook","paypal","apple","amazon","bank","visa","mastercard")

def rule_score_url(url: str) -> tuple[float, dict]:
    signals, score = {}, 0.0
    if url.lower().startswith("http://"):
        score += 10; signals["no_https"] = True
    if any(url.lower().endswith(t) or f"{t}/" in url.lower() for t in BAD_TLDS):
        score += 20; signals["bad_tld"] = True
    if "@" in url:
        score += 15; signals["has_at"] = True
    if re.search(r"[A-Za-z]\d{6,}", url):
        score += 5; signals["long_digits"] = True
    if any(b in url.lower() for b in BRAND_IMPERSONATION) and not re.search(r"(microsoft|office|apple|amazon)\.com", url.lower()):
        score += 15; signals["brand_impersonation"] = True
    return min(score, 40.0), signals


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

