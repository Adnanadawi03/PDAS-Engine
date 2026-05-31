import joblib
import os
import warnings

try:
    import pandas as pd
except Exception:
    pd = None

model_path = os.path.join(os.path.dirname(__file__), "url_model.pkl")
_load_warnings = []
with warnings.catch_warnings(record=True) as _caught:
    warnings.simplefilter("always")
    _artifact = joblib.load(model_path)

for _w in _caught:
    msg = str(_w.message)
    if msg not in _load_warnings:
        _load_warnings.append(msg)

warnings.filterwarnings("ignore", message="X has feature names", category=UserWarning, module="sklearn")

if isinstance(_artifact, dict) and "model" in _artifact:
    _model = _artifact["model"]
    _feature_names = list(_artifact.get("feature_names", []))
    _metadata = dict(_artifact.get("metadata", {}))
else:
    _model = _artifact
    _feature_names = list(getattr(_artifact, "feature_names_in_", []))
    _metadata = {}


def predict_proba(features: dict) -> float:
    row = {k: float(features.get(k, 0)) for k in _feature_names}
    if pd is not None:
        X = pd.DataFrame([row], columns=_feature_names)
    else:
        X = [[row[k] for k in _feature_names]]
    return float(_model.predict_proba(X)[0][1])


def get_model_diagnostics() -> dict:
    return {
        "model_name": type(_model).__name__,
        "feature_count": len(_feature_names),
        "input_adapter": "pandas" if pd is not None else "array_fallback",
        "load_warnings": list(_load_warnings),
        "uses_url_similarity_idx": "url_similarity_idx" in _feature_names,
        "metadata": _metadata,
    }
