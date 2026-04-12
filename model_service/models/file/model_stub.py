import math

WEIGHTS = {
    "url_count": 0.8,
    "entropy": 0.6,
    "has_macros": 1.2,
    "pdf_has_js": 1.0,
    "pdf_has_openaction": 0.8,
    "pe_str_powershell": 1.5,
}
BIAS = -1.5

def predict_proba(features: dict) -> float:
    z = BIAS
    for k, w in WEIGHTS.items():
        v = features.get(k, False)
        if isinstance(v, bool):
            v = 1.0 if v else 0.0
        z += w * float(v)
    return 1.0 / (1.0 + math.exp(-z))
