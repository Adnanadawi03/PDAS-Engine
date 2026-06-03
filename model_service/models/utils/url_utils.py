import re
from functools import lru_cache
from urllib.parse import urlparse
import tldextract

_tld_extractor = tldextract.TLDExtract(include_psl_private_domains=True)


MULTIPART_PUBLIC_SUFFIXES = {
    "ac.uk",
    "co.il",
    "co.jp",
    "co.kr",
    "co.nz",
    "co.uk",
    "com.au",
    "com.br",
    "com.cn",
    "com.mx",
    "com.tr",
    "com.tw",
    "gov.uk",
    "net.au",
    "org.au",
    "org.uk",
    # Jordanian public suffixes
    "com.jo",
    "edu.jo",
    "gov.jo",
    "mil.jo",
    "net.jo",
    "org.jo",
}


def normalize_host(host: str) -> str:
    host = (host or "").strip().lower().rstrip(".")
    if not host:
        return ""
    try:
        return host.encode("idna").decode("ascii")
    except UnicodeError:
        return host


def extract_host(url: str) -> str:
    return normalize_host(urlparse(url).hostname or "")


def host_matches_domain(host: str, domain: str) -> bool:
    host = normalize_host(host)
    domain = normalize_host(domain)
    return bool(host and domain) and (host == domain or host.endswith("." + domain))


def get_registered_domain(host: str) -> str:
    host = normalize_host(host)
    if not host:
        return ""
    if re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", host):
        return host

    try:
        ext = _tld_extractor(host)
        reg_dom = ext.top_domain_under_public_suffix
        if reg_dom:
            return reg_dom
    except Exception:
        pass

    parts = host.split(".")
    if len(parts) <= 2:
        return host

    suffix_candidate = ".".join(parts[-2:])
    if suffix_candidate in MULTIPART_PUBLIC_SUFFIXES and len(parts) >= 3:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


@lru_cache(maxsize=512)
def build_host_context(url: str) -> dict:
    parsed = urlparse(url)
    host = extract_host(url)
    registered_domain = get_registered_domain(host)
    labels = [label for label in host.split(".") if label]
    return {
        "scheme": (parsed.scheme or "").lower(),
        "host": host,
        "registered_domain": registered_domain,
        "label_count": len(labels),
        "path_segments": len([part for part in (parsed.path or "").split("/") if part]),
        "query_param_count": len([part for part in (parsed.query or "").split("&") if part]),
    }


REDIRECT_DOMAINS = {"google.com", "facebook.com", "t.co", "linkedin.com", "twitter.com", "youtube.com"}
REDIRECT_PARAMS = {"q", "url", "redirect", "u", "target", "link", "dest", "destination", "next"}

UGC_HOSTS = {
    "wixsite.com", "github.io", "pages.dev", "firebaseapp.com",
    "weebly.com", "blogspot.com", "wordpress.com", "webflow.io"
}

def resolve_open_redirect(url: str) -> str:
    try:
        parsed = urlparse(url)
        host = normalize_host(parsed.hostname or "")
        is_redirector = any(host_matches_domain(host, d) for d in REDIRECT_DOMAINS)
        if is_redirector:
            from urllib.parse import parse_qs
            qs = parse_qs(parsed.query)
            for param in REDIRECT_PARAMS:
                if param in qs:
                    val = qs[param][0]
                    if val.startswith("http://") or val.startswith("https://"):
                        return val
    except Exception:
        pass
    return url


def is_ugc_url(url: str) -> bool:
    try:
        ctx = build_host_context(url)
        host = ctx["host"]
        reg_domain = ctx["registered_domain"]

        # Check subdomains of blogging/hosting providers
        if reg_domain in UGC_HOSTS and host != reg_domain:
            return True

        # Check specific paths on major trusted domains
        parsed = urlparse(url)
        path = parsed.path.lower()
        if host_matches_domain(host, "google.com"):
            if "/forms/" in path or "/viewform" in path or "/presentation/" in path:
                return True
        if host_matches_domain(host, "office.com") or host_matches_domain(host, "microsoft.com"):
            if "/forms/" in path or "/viewform" in path:
                return True
        if host_matches_domain(host, "sharepoint.com"):
            return True
    except Exception:
        pass
    return False

