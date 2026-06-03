import ipaddress
import re
from urllib.parse import urlsplit, urlunsplit

from pydantic import BaseModel, Field, field_validator

_MAX_URL_LENGTH = 2048
_CONTROL_OR_SPACE = re.compile(r"[\x00-\x20\x7f]")
_IPV4_LIKE = re.compile(r"(?:\d{1,3}\.){3}\d{1,3}")
_DOMAIN_LABEL = re.compile(r"^[a-z0-9-]{1,63}$")


def _normalize_netloc(parsed) -> str:
    host = (parsed.hostname or "").encode("idna").decode("ascii").lower()
    netloc_host = f"[{host}]" if ":" in host else host
    userinfo = ""
    if parsed.username:
        userinfo = parsed.username
        if parsed.password:
            userinfo += f":{parsed.password}"
        userinfo += "@"
    port = f":{parsed.port}" if parsed.port is not None else ""
    return f"{userinfo}{netloc_host}{port}"


def _validate_host(host: str) -> None:
    if len(host) > 253:
        raise ValueError("URL host is too long")

    if _IPV4_LIKE.fullmatch(host) or ":" in host:
        try:
            ipaddress.ip_address(host)
        except ValueError as exc:
            raise ValueError("URL host is not a valid IP address") from exc
        return

    labels = host.split(".")
    for label in labels:
        if not _DOMAIN_LABEL.fullmatch(label) or label.startswith("-") or label.endswith("-"):
            raise ValueError("URL host is not a valid domain name")


class URLScanRequest(BaseModel):
    url: str

    @field_validator("url")
    @classmethod
    def validate_url(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("URL cannot be empty")
        if len(v) > _MAX_URL_LENGTH:
            raise ValueError(f"URL exceeds maximum length of {_MAX_URL_LENGTH} characters")
        if _CONTROL_OR_SPACE.search(v):
            raise ValueError("URL cannot contain spaces or control characters")

        try:
            parsed = urlsplit(v)
            scheme = parsed.scheme.lower()
            host = parsed.hostname
            _ = parsed.port
        except ValueError as exc:
            raise ValueError(f"Invalid URL: {exc}") from exc

        if scheme not in {"http", "https"}:
            raise ValueError("URL must start with http:// or https://")
        if not host:
            raise ValueError("URL must include a host")

        try:
            netloc = _normalize_netloc(parsed)
            _validate_host(host.encode("idna").decode("ascii").lower())
        except UnicodeError as exc:
            raise ValueError("URL host is not a valid domain name") from exc

        return urlunsplit((scheme, netloc, parsed.path, parsed.query, parsed.fragment))


class ScanResult(BaseModel):
    score: float
    verdict: str
    signals: dict
    risk_level: str | None = None
    reasons: list[str] = Field(default_factory=list)
    request_id: str | None = None
    normalized_url: str | None = None
    host: str | None = None
    registered_domain: str | None = None
    ai_probability: float | None = None
    ai_score: float | None = None
    rule_score: float | None = None
    confidence: str | None = None
    decision_reason: str | None = None
    policy_version: str | None = None
