import os
from dataclasses import dataclass
from functools import lru_cache


DEFAULT_TRUSTED_DOMAINS = (
    "amazon.com",
    "amazonaws.com",
    "adobe.com",
    "apple.com",
    "atlassian.com",
    "bankofamerica.com",
    "docs.python.org",
    "dropbox.com",
    "github.com",
    "gitlab.com",
    "google.com",
    "googleblog.com",
    "irs.gov",
    "linkedin.com",
    "live.com",
    "microsoft.com",
    "microsoftonline.com",
    "mozilla.org",
    "nytimes.com",
    "office.com",
    "openai.com",
    "outlook.com",
    "paypal.com",
    "python.org",
    "reddit.com",
    "salesforce.com",
    "slack.com",
    "steampowered.com",
    "upwork.com",
    "visa.com",
    "vercel.com",
    "youtube.com",
    "yahoo.com",
    "zoom.us",
)


def _read_bool(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _read_float(name: str, default: float) -> float:
    raw = os.getenv(name)
    if raw is None:
        return default
    try:
        return float(raw)
    except ValueError:
        return default


def _load_trusted_domains() -> tuple[str, ...]:
    items = {domain.lower() for domain in DEFAULT_TRUSTED_DOMAINS}

    extra_csv = os.getenv("PDAS_TRUSTED_DOMAINS", "")
    for value in extra_csv.split(","):
        value = value.strip().lower()
        if value:
            items.add(value)

    file_path = os.getenv("PDAS_TRUSTED_DOMAINS_FILE", "").strip()
    if file_path and os.path.exists(file_path):
        with open(file_path, "r", encoding="utf-8") as fh:
            for line in fh:
                value = line.strip().lower()
                if value and not value.startswith("#"):
                    items.add(value)

    return tuple(sorted(items))


def _read_csv(name: str) -> tuple[str, ...]:
    raw = os.getenv(name, "")
    return tuple(item.strip() for item in raw.split(",") if item.strip())


def _read_int(name: str, default: int) -> int:
    raw = os.getenv(name)
    if raw is None:
        return default
    try:
        return int(raw)
    except ValueError:
        return default


@dataclass(frozen=True)
class Settings:
    environment: str
    require_api_key: bool
    api_keys: tuple[str, ...]
    url_policy_version: str
    expose_model_diagnostics: bool
    request_log_details: bool
    hide_raw_features: bool
    url_warn_threshold: float
    url_block_threshold: float
    file_warn_threshold: float
    file_block_threshold: float
    trusted_score_discount: float
    ai_only_discount: float
    rate_limit_per_minute: int
    trusted_domains: tuple[str, ...]


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    environment = os.getenv("PDAS_ENV", "development").strip().lower() or "development"
    debug_mode = environment != "production"
    api_keys = _read_csv("PDAS_API_KEYS")
    return Settings(
        environment=environment,
        require_api_key=_read_bool("PDAS_REQUIRE_API_KEY", False),
        api_keys=api_keys,
        url_policy_version=os.getenv("PDAS_URL_POLICY_VERSION", "url-api-v1").strip() or "url-api-v1",
        expose_model_diagnostics=_read_bool("PDAS_EXPOSE_MODEL_DIAGNOSTICS", debug_mode),
        request_log_details=_read_bool("PDAS_REQUEST_LOG_DETAILS", debug_mode),
        hide_raw_features=_read_bool("PDAS_HIDE_RAW_FEATURES", not debug_mode),
        url_warn_threshold=_read_float("PDAS_URL_WARN_THRESHOLD", 45.0),
        url_block_threshold=_read_float("PDAS_URL_BLOCK_THRESHOLD", 70.0),
        file_warn_threshold=_read_float("PDAS_FILE_WARN_THRESHOLD", 50.0),
        file_block_threshold=_read_float("PDAS_FILE_BLOCK_THRESHOLD", 80.0),
        trusted_score_discount=_read_float("PDAS_TRUSTED_SCORE_DISCOUNT", 12.0),
        ai_only_discount=_read_float("PDAS_AI_ONLY_DISCOUNT", 12.0),
        rate_limit_per_minute=_read_int("PDAS_RATE_LIMIT_PER_MINUTE", 60),
        trusted_domains=_load_trusted_domains(),
    )
