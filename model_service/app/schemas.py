from pydantic import BaseModel, HttpUrl

class URLScanRequest(BaseModel):
    url: HttpUrl

class ScanResult(BaseModel):
    score: float
    verdict: str        # allow | caution | warn | danger | block
    risk_level: str     # SAFE | LOW | MEDIUM | HIGH | CRITICAL
    risk_label: str     # Human-readable label
    signals: dict
