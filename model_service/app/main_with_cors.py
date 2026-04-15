from fastapi import FastAPI, UploadFile, File, Depends, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from fastapi.routing import APIRoute
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from .schemas import URLScanRequest, ScanResult
from .utils.url_features import extract_url_features
from .utils.file_features import sniff_type_and_features
from ..models.url.ai_model import predict_proba as url_predict
from ..models.file.ai_model import predict_proba as file_predict
from ..rules.rules import rule_score_url, rule_score_file
from .database import SessionLocal, init_db, ScanEvent
import traceback, logging

logging.basicConfig(level=logging.ERROR)

app = FastAPI(title="PDAS Model Service", version="0.5")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

templates = Jinja2Templates(directory="model_service/app/templates")

@app.on_event("startup")
def startup():
    init_db()

@app.on_event("startup")
async def _print_routes():
    print("ROUTES_AT_STARTUP:", [r.path for r in app.routes if isinstance(r, APIRoute)])

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def combine_scores(rule_score: float, p_ai: float) -> float:
    return round(min(100.0, max(0.0, 0.4 * rule_score + 0.6 * (p_ai * 100))), 1)

def decide(score: float, warn=50, block=80) -> str:
    if score >= block:
        return "block"
    if score >= warn:
        return "warn"
    return "allow"

@app.post("/scan/file", response_model=ScanResult)
async def scan_file(file: UploadFile = File(...), db: Session = Depends(get_db)):
    try:
        data = await file.read()
        ftype, feats = sniff_type_and_features(data, file.filename)
        p = file_predict(feats)
        r_score, r_signals = rule_score_file(feats)
        final = combine_scores(r_score, p)
        verdict = decide(final)
        event = ScanEvent(
            type="file", target=file.filename, verdict=verdict,
            score=final, signals={"features": feats, "rules": r_signals}
        )
        db.add(event)
        db.commit()
        return ScanResult(score=final, verdict=verdict, signals={"features": feats, "rules": r_signals})
    except Exception as e:
        logging.error("SCAN_FILE_ERROR: %s\n%s", e, traceback.format_exc())
        return {"error": str(e), "trace": traceback.format_exc()}

@app.post("/scan/url", response_model=ScanResult)
def scan_url(req: URLScanRequest, db: Session = Depends(get_db)):
    try:
        url = str(req.url)
        feats = extract_url_features(url)
        p = url_predict(feats)
        r_score, r_signals = rule_score_url(url)
        final = combine_scores(r_score, p)
        verdict = decide(final)
        event = ScanEvent(
            type="url", target=url, verdict=verdict,
            score=final, signals={"features": feats, "rules": r_signals}
        )
        db.add(event)
        db.commit()
        return ScanResult(score=final, verdict=verdict, signals={"features": feats, "rules": r_signals})
    except Exception as e:
        logging.error("SCAN_URL_ERROR: %s\n%s", e, traceback.format_exc())
        return {"error": str(e), "trace": traceback.format_exc()}

@app.get("/events")
def get_events(limit: int = 20, db: Session = Depends(get_db)):
    events = db.query(ScanEvent).order_by(ScanEvent.timestamp.desc()).limit(limit).all()
    return [
        {"id": e.id, "type": e.type, "target": e.target,
         "verdict": e.verdict, "score": e.score, "timestamp": e.timestamp}
        for e in events
    ]

@app.get("/dashboard", response_class=HTMLResponse)
def dashboard(request: Request):
    return templates.TemplateResponse("dashboard.html", {"request": request})

@app.get("/")
def root():
    return {"status": "ok", "service": "PDAS Model Service", "docs": "/docs"}

@app.get("/health")
def health():
    return {"status": "healthy"}
