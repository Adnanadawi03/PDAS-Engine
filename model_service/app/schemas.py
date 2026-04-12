from pydantic import BaseModel

class URLScanRequest(BaseModel):
    url: str
class ScanResult(BaseModel):
    score: float
    verdict: str
    signals: dict
    target: str        # ← this field is required but not being returned!
