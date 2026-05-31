import re
from functools import lru_cache
from urllib.parse import urlparse


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
