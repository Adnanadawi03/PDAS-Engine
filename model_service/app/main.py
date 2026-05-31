import logging
import time
from uuid import uuid4

from fastapi import FastAPI, UploadFile, File, Depends, Header, HTTPException, Request
from fastapi.responses import JSONResponse
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from fastapi.middleware.cors import CORSMiddleware
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address
from sqlalchemy.orm import Session
from .schemas import URLScanRequest, ScanResult
from .config import get_settings
from .utils.url_features import extract_url_features
from .utils.file_features import sniff_type_and_features
from .utils.url_utils import build_host_context
from ..models.url.ai_model import predict_proba as url_predict, get_model_diagnostics as url_model_diagnostics
from ..models.file.ai_model import predict_proba as file_predict, get_model_diagnostics as file_model_diagnostics
from ..rules.rules import rule_score_url, rule_score_file
from ..rules.rules import is_trusted_host
from fastapi.routing import APIRoute
from .database import SessionLocal, init_db, ScanEvent

_settings = get_settings()
_rate_limit = f"{_settings.rate_limit_per_minute}/minute"

limiter = Limiter(key_func=get_remote_address)
app = FastAPI(title="PDAS Model Service", version="1.0")
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# ── CORS — must be before any other middleware ──
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

logger = logging.getLogger("pdas.model_service")

if not logger.handlers:
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
    logger.addHandler(handler)
logger.setLevel(logging.INFO)

# Templates للـ Dashboard
templates = Jinja2Templates(directory="model_service/app/templates")

# تشغيل DB عند بدء السيرفر
@app.on_event("startup")
def startup():
    init_db()

# Dependency لفتح/إغلاق جلسة DB
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


@app.middleware("http")
async def add_request_context(request: Request, call_next):
    request_id = request.headers.get("X-Request-ID") or str(uuid4())
    request.state.request_id = request_id
    started = time.perf_counter()
    try:
        response = await call_next(request)
    except Exception:
        logger.exception("request_failed request_id=%s path=%s", request_id, request.url.path)
        return JSONResponse(status_code=500, content={"detail": "internal_error", "request_id": request_id})

    duration_ms = round((time.perf_counter() - started) * 1000, 2)
    response.headers["X-Request-ID"] = request_id
    if get_settings().request_log_details:
        logger.info(
            "request_completed request_id=%s method=%s path=%s status=%s duration_ms=%s",
            request_id,
            request.method,
            request.url.path,
            response.status_code,
            duration_ms,
        )
    return response


RULE_SCORE_WEIGHT = 0.25
AI_SCORE_WEIGHT = 0.75
HIGH_CONFIDENCE_SIGNALS = {
    "has_at",
    "punycode",
    "ip_host",
    "brand_impersonation",
    "suspicious_download_extension",
}


def combine_scores(rule_score: float, p_ai: float) -> float:
    return round(min(100.0, max(0.0, RULE_SCORE_WEIGHT * rule_score + AI_SCORE_WEIGHT * (p_ai * 100))), 1)

def thresholds_for(scan_type: str) -> dict:
    settings = get_settings()
    if scan_type == "url":
        return {"warn": settings.url_warn_threshold, "block": settings.url_block_threshold}
    return {"warn": settings.file_warn_threshold, "block": settings.file_block_threshold}


def decide(score: float, warn=50, block=80) -> str:
    if score >= block:
        return "block"
    if score >= warn:
        return "warn"
    return "allow"


def risk_level_for(score: float, warn: float, block: float) -> str:
    if score >= block:
        return "critical"
    if score >= warn:
        return "elevated"
    if score >= max(15.0, warn * 0.5):
        return "low"
    return "minimal"


def confidence_for(verdict: str, ai_probability: float, rule_signals: dict, adjustments: list[dict]) -> str:
    signal_names = set(rule_signals) - {"trusted_host"}
    adjustment_types = {item.get("type") for item in adjustments}
    if verdict == "block":
        if signal_names & HIGH_CONFIDENCE_SIGNALS:
            return "high"
        if ai_probability >= 0.95 and signal_names:
            return "high"
        return "medium"
    if verdict == "warn":
        if "no_rules_block_cap" in adjustment_types:
            return "medium"
        if signal_names:
            return "medium"
        return "low"
    if rule_signals.get("trusted_host") and ai_probability <= 0.2:
        return "high"
    if ai_probability <= 0.05 and not signal_names:
        return "medium"
    return "low"


def apply_url_score_adjustments(url: str, combined_score: float, ai_probability: float, rule_signals: dict) -> tuple[float, list[dict], dict]:
    settings = get_settings()
    ctx = build_host_context(url)
    adjustments = []
    adjusted_score = combined_score
    severe_signals = {"ip_host", "punycode", "has_at", "brand_impersonation", "suspicious_download_extension"}

    trusted = is_trusted_host(ctx["host"])
    if trusted and not any(signal in rule_signals for signal in severe_signals):
        discount = settings.trusted_score_discount
        adjusted_score = max(0.0, adjusted_score - discount)
        adjustments.append({
            "type": "trusted_host_discount",
            "delta": -discount,
            "reason": f"trusted host {ctx['registered_domain'] or ctx['host']}",
        })

    non_trust_signals = {key: value for key, value in rule_signals.items() if key != "trusted_host"}
    if trusted and set(non_trust_signals).issubset({"suspicious_words"}) and non_trust_signals:
        discount = settings.ai_only_discount
        adjusted_score = max(0.0, adjusted_score - discount)
        adjustments.append({
            "type": "trusted_keyword_context_discount",
            "delta": -discount,
            "reason": "trusted help/account page with lure-like wording",
        })

    if trusted and set(non_trust_signals).issubset({"suspicious_words"}):
        cap = settings.url_warn_threshold - 1.0
        if adjusted_score > cap:
            delta = round(cap - adjusted_score, 1)
            adjusted_score = cap
            adjustments.append({
                "type": "trusted_host_allow_cap",
                "delta": delta,
                "reason": "trusted host without severe URL evidence capped below warn",
            })

    if not non_trust_signals and ai_probability < 0.92:
        discount = settings.ai_only_discount
        adjusted_score = max(0.0, adjusted_score - discount)
        adjustments.append({
            "type": "ai_only_discount",
            "delta": -discount,
            "reason": "no explicit rule signals matched",
        })

    if not non_trust_signals and adjusted_score >= settings.url_block_threshold:
        capped = settings.url_block_threshold - 1.0
        delta = round(capped - adjusted_score, 1)
        adjusted_score = capped
        adjustments.append({
            "type": "no_rules_block_cap",
            "delta": delta,
            "reason": "AI-only concern — no rule signal corroboration, capped below block",
        })

    warn_floor_reasons = []
    if "brand_impersonation" in rule_signals and ("brand_plus_lure_words" in rule_signals or "risky_tld" in rule_signals):
        warn_floor_reasons.append("brand_impersonation_combo")
    if "ip_host" in rule_signals and "no_https" in rule_signals:
        warn_floor_reasons.append("ip_over_http")
    if "punycode" in rule_signals and ("brand_impersonation" in rule_signals or "suspicious_words" in rule_signals):
        warn_floor_reasons.append("punycode_impersonation")
    if "has_at" in rule_signals:
        warn_floor_reasons.append("userinfo_obfuscation")
    if "punycode" in rule_signals:
        warn_floor_reasons.append("idn_obfuscation")
    if "suspicious_download_extension" in rule_signals and ai_probability >= 0.35:
        warn_floor_reasons.append("direct_executable_download")
    if "url_shortener" in rule_signals:
        warn_floor_reasons.append("url_shortener")
    if "risky_tld" in rule_signals and "suspicious_words" in rule_signals:
        warn_floor_reasons.append("risky_tld_lure_words")
    if "brand_impersonation" in rule_signals and "deep_subdomain" in rule_signals:
        warn_floor_reasons.append("brand_in_deep_subdomain")
    if warn_floor_reasons and adjusted_score < settings.url_warn_threshold:
        delta = round(settings.url_warn_threshold - adjusted_score, 1)
        adjusted_score = settings.url_warn_threshold
        adjustments.append({
            "type": "warn_floor",
            "delta": delta,
            "reason": ",".join(warn_floor_reasons),
        })

    obvious_block = (
        ("brand_impersonation" in rule_signals and "brand_plus_lure_words" in rule_signals and "risky_tld" in rule_signals and ai_probability >= 0.5)
        or ("has_at" in rule_signals and ai_probability >= 0.8)
        or ("punycode" in rule_signals and ai_probability >= 0.45)
        or ("ip_host" in rule_signals and "no_https" in rule_signals and ai_probability >= 0.8)
        or ("brand_impersonation" in rule_signals and "deep_subdomain" in rule_signals and ai_probability >= 0.8)
        or ("brand_impersonation" in rule_signals and ai_probability >= 0.9)
        or ("suspicious_download_extension" in rule_signals and ai_probability >= 0.75)
        or ("risky_tld" in rule_signals and "suspicious_words" in rule_signals and ai_probability >= 0.9)
        or ("risky_tld" in rule_signals and ai_probability >= 0.92)
        or ("no_https" in rule_signals and "risky_tld" in rule_signals and ai_probability >= 0.85)
        or ("url_shortener" in rule_signals and ai_probability >= 0.95)
    )
    if obvious_block and adjusted_score < settings.url_block_threshold:
        delta = round(settings.url_block_threshold - adjusted_score, 1)
        adjusted_score = settings.url_block_threshold
        adjustments.append({
            "type": "block_floor",
            "delta": delta,
            "reason": "obvious_brand_phishing_pattern",
        })

    context = {
        "trusted_host": trusted,
        "host": ctx["host"],
        "registered_domain": ctx["registered_domain"],
    }
    return round(adjusted_score, 1), adjustments, context


def build_analysis_payload(scan_type: str, rule_score: float, ai_probability: float) -> dict:
    thresholds = thresholds_for(scan_type)
    combined_score = combine_scores(rule_score, ai_probability)
    return {
        "scan_type": scan_type,
        "rule_score": round(rule_score, 1),
        "ai_probability": round(ai_probability, 4),
        "ai_score": round(ai_probability * 100, 1),
        "combined_score": combined_score,
        "weights": {"rules": RULE_SCORE_WEIGHT, "ai": AI_SCORE_WEIGHT},
        "thresholds": thresholds,
        "risk_level": risk_level_for(combined_score, thresholds["warn"], thresholds["block"]),
    }

def _build_signals(feats: dict, r_signals: dict, analysis: dict) -> dict:
    if get_settings().hide_raw_features:
        return {"rules": r_signals, "analysis": analysis}
    return {"features": feats, "rules": r_signals, "analysis": analysis}


def _save_scan_event(db: Session, event: ScanEvent, request_id: str | None = None) -> None:
    try:
        db.add(event)
        db.commit()
    except Exception:
        try:
            db.rollback()
        except Exception:
            pass
        logger.exception("scan_event_log_failed request_id=%s target=%s", request_id, event.target)


def require_api_key(x_api_key: str | None = Header(default=None, alias="X-API-Key")) -> None:
    settings = get_settings()
    if not settings.require_api_key:
        return
    if not settings.api_keys:
        raise HTTPException(status_code=503, detail="api_key_auth_not_configured")
    if x_api_key not in settings.api_keys:
        raise HTTPException(status_code=401, detail="invalid_api_key")


@app.post("/scan/file", response_model=ScanResult)
@limiter.limit(_rate_limit)
async def scan_file(request: Request, file: UploadFile = File(...), db: Session = Depends(get_db)):
    data = await file.read()
    _, feats = sniff_type_and_features(data, file.filename)
    p = file_predict(feats)
    r_score, r_signals = rule_score_file(feats)
    analysis = build_analysis_payload("file", r_score, p)
    if get_settings().expose_model_diagnostics:
        analysis["model"] = file_model_diagnostics()
    final = analysis["combined_score"]
    verdict = decide(final, **analysis["thresholds"])
    analysis["decision_reason"] = "rule_and_ai_blended_score"

    signals = _build_signals(feats, r_signals, analysis)
    event = ScanEvent(type="file", target=file.filename, verdict=verdict, score=final,
                      signals={"features": feats, "rules": r_signals, "analysis": analysis})
    _save_scan_event(db, event, getattr(request.state, "request_id", None))

    return ScanResult(
        score=final,
        verdict=verdict,
        signals=signals,
        risk_level=analysis["risk_level"],
        reasons=list(r_signals.keys()),
        request_id=getattr(request.state, "request_id", None),
        ai_probability=analysis["ai_probability"],
        ai_score=analysis["ai_score"],
        rule_score=analysis["rule_score"],
        confidence="medium" if verdict != "allow" else "low",
        decision_reason=analysis["decision_reason"],
        policy_version=get_settings().url_policy_version,
    )


@app.post("/scan/url", response_model=ScanResult)
@limiter.limit(_rate_limit)
async def scan_url(
    request: Request,
    req: URLScanRequest,
    db: Session = Depends(get_db),
    _auth: None = Depends(require_api_key),
):
    url = req.url
    request_id = getattr(request.state, "request_id", None)
    try:
        feats = extract_url_features(url)
        p = url_predict(feats)
        r_score, r_signals = rule_score_url(url)
        analysis = build_analysis_payload("url", r_score, p)
        adjusted_score, adjustments, trust_context = apply_url_score_adjustments(url, analysis["combined_score"], p, r_signals)
    except Exception:
        logger.exception("url_scan_engine_failed request_id=%s url=%s", request_id, url)
        settings = get_settings()
        analysis = {
            "scan_type": "url",
            "rule_score": 0.0,
            "ai_probability": 0.0,
            "ai_score": 0.0,
            "combined_score": settings.url_warn_threshold,
            "base_combined_score": 0.0,
            "weights": {"rules": RULE_SCORE_WEIGHT, "ai": AI_SCORE_WEIGHT},
            "thresholds": thresholds_for("url"),
            "risk_level": risk_level_for(settings.url_warn_threshold, settings.url_warn_threshold, settings.url_block_threshold),
            "adjustments": [{"type": "engine_error_fail_closed", "delta": settings.url_warn_threshold, "reason": "scan engine failed"}],
            "decision_reason": "engine_error_fail_closed",
        }
        signals = {"rules": {"engine_error": True}, "analysis": analysis}
        event = ScanEvent(type="url", target=url, verdict="warn", score=settings.url_warn_threshold,
                          signals=signals)
        _save_scan_event(db, event, request_id)
        return ScanResult(
            score=settings.url_warn_threshold,
            verdict="warn",
            signals=signals,
            risk_level=analysis["risk_level"],
            reasons=["engine_error"],
            request_id=request_id,
            normalized_url=url,
            ai_probability=0.0,
            ai_score=0.0,
            rule_score=0.0,
            confidence="low",
            decision_reason="engine_error_fail_closed",
            policy_version=settings.url_policy_version,
        )

    analysis["base_combined_score"] = analysis["combined_score"]
    analysis["combined_score"] = adjusted_score
    analysis["risk_level"] = risk_level_for(adjusted_score, analysis["thresholds"]["warn"], analysis["thresholds"]["block"])
    analysis["adjustments"] = adjustments
    analysis["host_context"] = trust_context
    if get_settings().expose_model_diagnostics:
        analysis["model"] = url_model_diagnostics()
    if adjustments:
        analysis["decision_reason"] = "score_adjusted_by_context"
    elif r_signals:
        analysis["decision_reason"] = "rule_and_ai_blended_score"
    else:
        analysis["decision_reason"] = "ai_only_low_risk"
    final = analysis["combined_score"]
    verdict = decide(final, **analysis["thresholds"])
    confidence = confidence_for(verdict, p, r_signals, adjustments)

    signals = _build_signals(feats, r_signals, analysis)
    event = ScanEvent(type="url", target=url, verdict=verdict, score=final,
                      signals={"features": feats, "rules": r_signals, "analysis": analysis})
    _save_scan_event(db, event, request_id)

    return ScanResult(
        score=final,
        verdict=verdict,
        signals=signals,
        risk_level=analysis["risk_level"],
        reasons=list(r_signals.keys()),
        request_id=request_id,
        normalized_url=url,
        host=trust_context["host"],
        registered_domain=trust_context["registered_domain"],
        ai_probability=analysis["ai_probability"],
        ai_score=analysis["ai_score"],
        rule_score=analysis["rule_score"],
        confidence=confidence,
        decision_reason=analysis["decision_reason"],
        policy_version=get_settings().url_policy_version,
    )

# Endpoint جديد يرجع آخر النتائج كـ JSON
@app.get("/events")
def get_events(limit: int = 20, db: Session = Depends(get_db)):
    events = db.query(ScanEvent).order_by(ScanEvent.timestamp.desc()).limit(limit).all()
    return [
        {
            "id": e.id,
            "type": e.type,
            "target": e.target,
            "verdict": e.verdict,
            "score": e.score,
            "timestamp": e.timestamp,
        }
        for e in events
    ]

# Dashboard HTML
@app.get("/dashboard", response_class=HTMLResponse)
def dashboard(request: Request):
    return templates.TemplateResponse("dashboard.html", {"request": request})

@app.get("/")
def root():
    return {"status": "ok", "service": "PDAS Model Service", "docs": "/docs"}

# ── Single /health route ──
@app.get("/health")
def health():
    settings = get_settings()
    return {
        "status": "healthy",
        "environment": settings.environment,
        "api_key_required": settings.require_api_key,
        "api_key_configured": bool(settings.api_keys),
        "diagnostics_exposed": settings.expose_model_diagnostics,
        "thresholds": {
            "url": thresholds_for("url"),
            "file": thresholds_for("file"),
        },
        "weights": {"rules": RULE_SCORE_WEIGHT, "ai": AI_SCORE_WEIGHT},
        "url_policy_version": settings.url_policy_version,
    }


@app.get("/ready")
def ready():
    settings = get_settings()
    url_model = url_model_diagnostics()
    issues = []
    warnings = []
    if settings.require_api_key and not settings.api_keys:
        issues.append("api_key_auth_not_configured")
    if url_model["feature_count"] <= 0:
        issues.append("url_model_has_no_features")
    if url_model.get("uses_url_similarity_idx"):
        warnings.append("url_similarity_idx_requires_external_validation")
    status = "ready" if not issues else "not_ready"
    return {
        "status": status,
        "service": "PDAS Model Service",
        "issues": issues,
        "warnings": warnings,
        "api_key_required": settings.require_api_key,
        "api_key_configured": bool(settings.api_keys),
        "trusted_domains_loaded": len(settings.trusted_domains),
        "url_policy_version": settings.url_policy_version,
        "url_model": {
            "model_name": url_model["model_name"],
            "feature_count": url_model["feature_count"],
            "uses_url_similarity_idx": url_model.get("uses_url_similarity_idx", False),
            "metadata": {
                "dataset": url_model.get("metadata", {}).get("dataset"),
                "test_auc": url_model.get("metadata", {}).get("test_auc"),
                "cv_auc_mean": url_model.get("metadata", {}).get("cv_auc_mean"),
                "feature_count": url_model.get("metadata", {}).get("feature_count"),
            },
        },
    }

@app.on_event("startup")
async def _print_routes():
    print("ROUTES_AT_STARTUP:", [r.path for r in app.routes if isinstance(r, APIRoute)])
