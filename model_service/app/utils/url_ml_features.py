import math
import re
from collections import Counter
from urllib.parse import urlparse

from .url_utils import build_host_context


ML_FEATURE_NAMES = [
    # --- URL-level char counts ---
    "qty_dot_url",
    "qty_hyphen_url",
    "qty_underline_url",
    "qty_slash_url",
    "qty_questionmark_url",
    "qty_equal_url",
    "qty_at_url",
    "qty_and_url",
    "qty_exclamation_url",
    "qty_space_url",
    "qty_tilde_url",
    "qty_comma_url",
    "qty_plus_url",
    "qty_asterisk_url",
    "qty_hashtag_url",
    "qty_dollar_url",
    "qty_percent_url",
    "length_url",
    # --- Domain-level features ---
    "qty_dot_domain",
    "qty_hyphen_domain",
    "qty_underline_domain",
    "qty_vowels_domain",
    "domain_length",
    "domain_in_ip",
    "server_client_domain",
    # --- Directory-level char counts ---
    "qty_dot_directory",
    "qty_hyphen_directory",
    "qty_underline_directory",
    "qty_slash_directory",
    "qty_questionmark_directory",
    "qty_equal_directory",
    "qty_at_directory",
    "qty_and_directory",
    "qty_exclamation_directory",
    "qty_space_directory",
    "qty_tilde_directory",
    "qty_comma_directory",
    "qty_plus_directory",
    "qty_asterisk_directory",
    "qty_hashtag_directory",
    "qty_dollar_directory",
    "qty_percent_directory",
    "directory_length",
    # --- File-level char counts ---
    "qty_dot_file",
    "qty_hyphen_file",
    "qty_underline_file",
    "qty_slash_file",
    "qty_questionmark_file",
    "qty_equal_file",
    "qty_at_file",
    "qty_and_file",
    "qty_exclamation_file",
    "qty_space_file",
    "qty_tilde_file",
    "qty_comma_file",
    "qty_plus_file",
    "qty_asterisk_file",
    "qty_hashtag_file",
    "qty_dollar_file",
    "qty_percent_file",
    "file_length",
    # --- Query params char counts ---
    "qty_dot_params",
    "qty_hyphen_params",
    "qty_underline_params",
    "qty_slash_params",
    "qty_questionmark_params",
    "qty_equal_params",
    "qty_at_params",
    "qty_and_params",
    "qty_exclamation_params",
    "qty_space_params",
    "qty_tilde_params",
    "qty_comma_params",
    "qty_plus_params",
    "qty_asterisk_params",
    "qty_hashtag_params",
    "qty_dollar_params",
    "qty_percent_params",
    "params_length",
    "tld_present_params",
    "qty_params",
    "email_in_url",
    "url_shortened",
    # --- New high-signal features ---
    "letter_ratio",
    "digit_ratio",
    "special_char_ratio",
    "char_continuation_rate",
    "has_obfuscation",
    "obfuscation_ratio",
    "tld_legit_prob",
    "has_port",
    "has_fragment",
    "url_entropy",
    "url_similarity_idx",
]

SHORTENER_DOMAINS = {
    "bit.ly", "cutt.ly", "goo.gl", "is.gd", "lnkd.in",
    "ow.ly", "rb.gy", "rebrand.ly", "shorturl.at", "t.co",
    "tiny.cc", "tinyurl.com",
}

# P(legitimate | TLD) computed from PhiUSIIL dataset (235K URLs)
TLD_LEGIT_PROB = {
    "gov": 1.000, "mil": 1.000, "int": 1.000, "edu": 0.997,
    "ie": 0.981, "no": 0.968, "hr": 0.954, "bg": 0.956,
    "uk": 0.950, "fi": 0.941, "jp": 0.938, "ca": 0.931,
    "cz": 0.903, "nz": 0.901, "dk": 0.901, "nl": 0.889,
    "sk": 0.899, "si": 0.895, "be": 0.894, "ch": 0.888,
    "it": 0.885, "lk": 0.897, "org": 0.879, "au": 0.875,
    "gr": 0.874, "rs": 0.877, "ee": 0.871, "ph": 0.834,
    "hk": 0.839, "se": 0.825, "de": 0.828, "tw": 0.822,
    "es": 0.818, "at": 0.799, "hu": 0.803, "my": 0.788,
    "pt": 0.776, "lu": 0.784, "lv": 0.763, "tz": 0.740,
    "tr": 0.741, "fr": 0.735, "za": 0.742, "eu": 0.709,
    "ro": 0.710, "kr": 0.719, "il": 0.905, "am": 0.740,
    "ge": 0.720, "ec": 0.792, "tv": 0.838, "sg": 0.858,
    "ba": 0.782, "fm": 0.908, "cat": 0.913, "travel": 0.957,
    "ai": 0.813, "az": 0.771, "bd": 0.714, "uy": 0.764,
    "np": 0.689, "ma": 0.673, "ug": 0.661, "by": 0.629,
    "br": 0.646, "com": 0.611, "us": 0.612, "in": 0.611,
    "ar": 0.653, "mx": 0.564, "net": 0.563, "cl": 0.513,
    "ng": 0.500, "asia": 0.500, "mobi": 0.594, "pk": 0.588,
    "ke": 0.605, "cr": 0.563, "pl": 0.402, "mt": 0.429,
    "info": 0.430, "ua": 0.441, "nu": 0.449, "kz": 0.439,
    "do": 0.362, "vn": 0.434, "pe": 0.402, "tn": 0.243,
    "id": 0.302, "cn": 0.305, "ir": 0.273, "ru": 0.230,
    "bz": 0.244, "tech": 0.294, "me": 0.152, "la": 0.220,
    "name": 0.238, "world": 0.368, "art": 0.245, "li": 0.250,
    "to": 0.186, "store": 0.175, "life": 0.182, "pro": 0.188,
    "space": 0.127, "one": 0.112, "sh": 0.117, "io": 0.520,
    "network": 0.102, "online": 0.200, "co": 0.420,
    "live": 0.420, "club": 0.050, "vip": 0.040, "shop": 0.200,
    "ws": 0.091, "cc": 0.159, "biz": 0.226, "su": 0.154,
    "email": 0.100, "re": 0.177, "gg": 0.442, "zw": 0.539,
    "website": 0.070, "digital": 0.073, "ht": 0.077,
    "gy": 0.072, "gp": 0.013, "ink": 0.061, "bio": 0.057,
    "click": 0.029, "pw": 0.031, "work": 0.024, "cloud": 0.350,
    "app": 0.550, "ly": 0.020, "tk": 0.019, "xyz": 0.017,
    "dev": 0.500, "win": 0.012, "gd": 0.009, "fun": 0.011,
    "ga": 0.004, "link": 0.006, "site": 0.003, "ml": 0.001,
    "top": 0.001, "cf": 0.000, "gq": 0.000, "page": 0.550,
    "icu": 0.000, "cfd": 0.000, "cyou": 0.000, "host": 0.000,
    "goog": 0.950, "gle": 0.000,
}

TLD_PATTERN = re.compile(r"\.(?:com|net|org|edu|gov|co|io|ai|app|dev|biz|info|xyz|top|ru|cn|tk|zip)\b", re.I)
EMAIL_PATTERN = re.compile(r"[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}", re.I)
IP_PATTERN = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")
OBFUSCATION_PATTERN = re.compile(r"%[0-9A-Fa-f]{2}")

CHAR_NAMES = {
    ".": "dot", "-": "hyphen", "_": "underline", "/": "slash",
    "?": "questionmark", "=": "equal", "@": "at", "&": "and",
    "!": "exclamation", " ": "space", "~": "tilde", ",": "comma",
    "+": "plus", "*": "asterisk", "#": "hashtag", "$": "dollar",
    "%": "percent",
}

_SPECIAL_CHARS = frozenset('!@#$%^&*()_+-=[]{}|\\;\':",./<>?~`')

# Known legitimate registered domains — used to compute url_similarity_idx at
# inference time (training uses the pre-computed CSV value).
_TRUSTED_REGISTERED_DOMAINS = frozenset({
    "google.com", "youtube.com", "gmail.com", "googleblog.com",
    "facebook.com", "instagram.com", "whatsapp.com", "meta.com",
    "twitter.com", "x.com",
    "amazon.com", "amazonaws.com",
    "microsoft.com", "microsoftonline.com", "office.com", "live.com", "outlook.com",
    "bing.com", "msn.com", "azure.com", "onedrive.com",
    "github.com", "github.io",
    "paypal.com",
    "apple.com",
    "linkedin.com",
    "reddit.com",
    "wikipedia.org",
    "netflix.com",
    "adobe.com",
    "dropbox.com",
    "slack.com",
    "zoom.us",
    "atlassian.com", "bitbucket.org", "jira.com", "confluence.com",
    "stackoverflow.com",
    "cloudflare.com",
    "openai.com",
    "anthropic.com",
    "shopify.com",
    "wordpress.com",
    "medium.com",
    "twitch.tv",
    "discord.com",
    "notion.so",
    "figma.com",
    "vercel.com",
    "heroku.com",
    "stripe.com",
    "hubspot.com",
    "salesforce.com",
    "zendesk.com",
})


def _count_chars(text: str, prefix: str) -> dict:
    return {f"qty_{name}_{prefix}": text.count(char) for char, name in CHAR_NAMES.items()}


def _split_url_parts(url: str) -> tuple[str, str, str]:
    parsed = urlparse(url)
    raw_path = parsed.path or ""
    stripped = raw_path.lstrip("/")
    segments = [part for part in stripped.split("/") if part]

    file_part = ""
    if segments and "." in segments[-1]:
        file_part = segments[-1]
        directory_part = "/".join(segments[:-1])
    else:
        directory_part = "/".join(segments)

    params = parsed.query or ""
    return directory_part, file_part, params


def _shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    counts = Counter(text)
    n = len(text)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def extract_ml_url_features(url: str) -> dict:
    lower_url = url.lower()
    ctx = build_host_context(url)
    host = ctx["host"]
    registered_domain = ctx["registered_domain"]
    directory_part, file_part, params = _split_url_parts(url)
    parsed = urlparse(url)

    features = {}

    # --- URL char counts ---
    features.update(_count_chars(lower_url, "url"))
    features["length_url"] = len(url)

    # --- Domain features ---
    features.update(_count_chars(host, "domain"))
    features["qty_vowels_domain"] = sum(ch in "aeiou" for ch in host)
    features["domain_length"] = len(host)
    features["domain_in_ip"] = int(bool(IP_PATTERN.fullmatch(host)))
    features["server_client_domain"] = int("server" in host or "client" in host)

    # --- Directory / file / params ---
    features.update(_count_chars(directory_part, "directory"))
    features["directory_length"] = len(directory_part)
    features.update(_count_chars(file_part, "file"))
    features["file_length"] = len(file_part)
    features.update(_count_chars(params, "params"))
    features["params_length"] = len(params)
    features["tld_present_params"] = int(bool(TLD_PATTERN.search(params)))
    features["qty_params"] = 0 if not params else len([p for p in params.split("&") if p])
    features["email_in_url"] = int(bool(EMAIL_PATTERN.search(url)))
    features["url_shortened"] = int(registered_domain in SHORTENER_DOMAINS)

    # --- New high-signal features ---
    url_len = len(url) or 1
    letters = sum(c.isalpha() for c in url)
    digits = sum(c.isdigit() for c in url)
    special = sum(c in _SPECIAL_CHARS for c in url)

    features["letter_ratio"] = letters / url_len
    features["digit_ratio"] = digits / url_len
    features["special_char_ratio"] = special / url_len

    # Consecutive same-char pairs
    if len(url) > 1:
        continuation = sum(1 for i in range(len(url) - 1) if url[i] == url[i + 1])
        features["char_continuation_rate"] = continuation / (len(url) - 1)
    else:
        features["char_continuation_rate"] = 0.0

    # Percent-encoded obfuscation
    obfuscated = OBFUSCATION_PATTERN.findall(url)
    features["has_obfuscation"] = float(bool(obfuscated))
    features["obfuscation_ratio"] = len(obfuscated) / url_len

    # TLD legitimacy probability (from PhiUSIIL dataset statistics)
    tld = host.split(".")[-1].lower() if "." in host else ""
    features["tld_legit_prob"] = TLD_LEGIT_PROB.get(tld, 0.40)

    # Structural signals
    features["has_port"] = float(bool(parsed.port))
    features["has_fragment"] = float(bool(parsed.fragment))

    # Shannon entropy of URL characters (high entropy → obfuscated / random)
    features["url_entropy"] = _shannon_entropy(lower_url)

    # URL similarity index: 100 = known trusted domain, 50 = unknown.
    # At training time this is overridden by the dataset's pre-computed value.
    features["url_similarity_idx"] = (
        100.0 if registered_domain in _TRUSTED_REGISTERED_DOMAINS else 50.0
    )

    return {name: float(features.get(name, 0)) for name in ML_FEATURE_NAMES}
