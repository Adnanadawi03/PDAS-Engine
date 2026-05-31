"""
PDAS File Malware Detection — Model Training
=============================================
Uses a realistic synthetic dataset (5 000 samples) built from published
malware-analysis statistics.  Distributions are based on:
  - EMBER dataset feature statistics (Anderson et al. 2018)
  - PDFMalware2011 / Contagio corpus studies
  - VBA macro malware survey data

Feature set matches exactly what sniff_type_and_features() returns so
training ↔ inference are perfectly consistent.

Labels: 1 = malicious, 0 = benign
"""

import logging
import os
import sys
from collections import Counter

import joblib
import numpy as np
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.isotonic import IsotonicRegression
from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score
from sklearn.model_selection import StratifiedKFold, cross_val_score, train_test_split

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../../.."))
sys.path.insert(0, ROOT)

from model_service.models.calibration import CalibratedClassifier

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s  %(levelname)-8s  %(message)s",
                    datefmt="%H:%M:%S")
log = logging.getLogger("pdas.file_train")

OUT_MODEL = os.path.join(os.path.dirname(__file__), "file_model.pkl")

# ── fixed feature set (matches sniff_type_and_features output) ────────────────
FILE_FEATURE_NAMES = [
    "size",
    "entropy",
    "url_count",
    # PDF-specific
    "pdf_has_js",
    "pdf_has_openaction",
    # Office-specific
    "has_macros",
    "ooxml_word",
    "ooxml_excel",
    # PE-specific
    "pe_str_powershell",
    "pe_str_cmd_exe",
    "pe_str_rundll32",
    "pe_str_CreateRemoteThread",
    # structural
    "zip_broken",
    # file-type one-hot
    "is_pe",
    "is_pdf",
    "is_ole",
    "is_ooxml",
    "is_other",
]

rng = np.random.default_rng(42)


# ── synthetic sample generators ───────────────────────────────────────────────

def _zeros() -> dict:
    return {k: 0.0 for k in FILE_FEATURE_NAMES}


def _pe_malicious(n: int) -> list[dict]:
    rows = []
    for _ in range(n):
        r = _zeros()
        r["is_pe"] = 1.0
        # Packed/encrypted malware → high entropy (6.5–8.0)
        r["entropy"] = float(np.clip(rng.normal(7.2, 0.5), 6.0, 8.0))
        # Often small (dropper) or mid-size (rat/trojan)
        r["size"] = float(rng.choice([
            rng.integers(512, 30_000),           # dropper
            rng.integers(30_000, 500_000),        # trojan/rat
        ]))
        r["url_count"] = int(rng.integers(0, 5))
        r["pe_str_powershell"]       = float(rng.random() < 0.35)
        r["pe_str_cmd_exe"]          = float(rng.random() < 0.45)
        r["pe_str_rundll32"]         = float(rng.random() < 0.30)
        r["pe_str_CreateRemoteThread"] = float(rng.random() < 0.25)
        rows.append(r)
    return rows


def _pe_benign(n: int) -> list[dict]:
    rows = []
    for _ in range(n):
        r = _zeros()
        r["is_pe"] = 1.0
        # Benign executables: moderate entropy, larger size
        r["entropy"] = float(np.clip(rng.normal(5.5, 1.0), 3.0, 7.5))
        r["size"] = float(rng.integers(50_000, 10_000_000))
        r["url_count"] = int(rng.integers(0, 25))
        # Legitimate tools occasionally use these strings (installers, AV, etc.)
        r["pe_str_powershell"]       = float(rng.random() < 0.05)
        r["pe_str_cmd_exe"]          = float(rng.random() < 0.08)
        r["pe_str_rundll32"]         = float(rng.random() < 0.04)
        r["pe_str_CreateRemoteThread"] = float(rng.random() < 0.01)
        rows.append(r)
    return rows


def _pdf_malicious(n: int) -> list[dict]:
    rows = []
    for _ in range(n):
        r = _zeros()
        r["is_pdf"] = 1.0
        r["entropy"] = float(np.clip(rng.normal(6.2, 0.8), 4.0, 8.0))
        r["size"] = float(rng.integers(2_000, 300_000))
        r["url_count"] = int(rng.integers(1, 20))
        r["pdf_has_js"]         = float(rng.random() < 0.78)
        r["pdf_has_openaction"] = float(rng.random() < 0.58)
        rows.append(r)
    return rows


def _pdf_benign(n: int) -> list[dict]:
    rows = []
    for _ in range(n):
        r = _zeros()
        r["is_pdf"] = 1.0
        r["entropy"] = float(np.clip(rng.normal(4.5, 1.0), 2.0, 7.0))
        r["size"] = float(rng.integers(5_000, 15_000_000))
        r["url_count"] = int(rng.integers(0, 8))
        # Legitimate PDFs with JS (interactive forms, embedded viewers)
        r["pdf_has_js"]         = float(rng.random() < 0.09)
        r["pdf_has_openaction"] = float(rng.random() < 0.04)
        rows.append(r)
    return rows


def _ole_malicious(n: int) -> list[dict]:
    """OLE (Office 97-2003) — almost always malicious via macros."""
    rows = []
    for _ in range(n):
        r = _zeros()
        r["is_ole"] = 1.0
        r["entropy"]    = float(np.clip(rng.normal(6.0, 0.7), 4.0, 7.8))
        r["size"]       = float(rng.integers(5_000, 800_000))
        r["url_count"]  = int(rng.integers(0, 12))
        r["has_macros"] = float(rng.random() < 0.95)
        rows.append(r)
    return rows


def _ole_benign(n: int) -> list[dict]:
    rows = []
    for _ in range(n):
        r = _zeros()
        r["is_ole"] = 1.0
        r["entropy"]    = float(np.clip(rng.normal(4.2, 1.0), 2.0, 6.5))
        r["size"]       = float(rng.integers(10_000, 5_000_000))
        r["url_count"]  = int(rng.integers(0, 4))
        # Corporate templates with macros (legitimate)
        r["has_macros"] = float(rng.random() < 0.12)
        rows.append(r)
    return rows


def _ooxml_malicious(n: int) -> list[dict]:
    """OOXML (Office 2007+) malware — typically macro-based."""
    rows = []
    for _ in range(n):
        r = _zeros()
        r["is_ooxml"]   = 1.0
        r["entropy"]    = float(np.clip(rng.normal(5.8, 0.6), 4.0, 7.5))
        r["size"]       = float(rng.integers(5_000, 600_000))
        r["url_count"]  = int(rng.integers(0, 10))
        r["has_macros"] = float(rng.random() < 0.90)
        r["ooxml_word"] = float(rng.random() < 0.70)
        r["ooxml_excel"]= float(rng.random() < 0.30)
        rows.append(r)
    return rows


def _ooxml_benign(n: int) -> list[dict]:
    rows = []
    for _ in range(n):
        r = _zeros()
        r["is_ooxml"]   = 1.0
        r["entropy"]    = float(np.clip(rng.normal(4.0, 0.9), 2.0, 6.0))
        r["size"]       = float(rng.integers(5_000, 20_000_000))
        r["url_count"]  = int(rng.integers(0, 6))
        r["has_macros"] = float(rng.random() < 0.09)
        r["ooxml_word"] = float(rng.random() < 0.60)
        r["ooxml_excel"]= float(rng.random() < 0.40)
        rows.append(r)
    return rows


def _other_malicious(n: int) -> list[dict]:
    """Scripts, shellcode blobs, unknown formats."""
    rows = []
    for _ in range(n):
        r = _zeros()
        r["is_other"]  = 1.0
        r["entropy"]   = float(np.clip(rng.normal(7.0, 0.6), 5.5, 8.0))
        r["size"]      = float(rng.integers(100, 50_000))
        r["url_count"] = int(rng.integers(0, 8))
        rows.append(r)
    return rows


def _other_benign(n: int) -> list[dict]:
    rows = []
    for _ in range(n):
        r = _zeros()
        r["is_other"]  = 1.0
        r["entropy"]   = float(np.clip(rng.normal(4.8, 1.2), 1.5, 7.5))
        r["size"]      = float(rng.integers(100, 50_000_000))
        r["url_count"] = int(rng.integers(0, 10))
        rows.append(r)
    return rows


# ── dataset assembly ──────────────────────────────────────────────────────────

def build_dataset() -> tuple[np.ndarray, np.ndarray]:
    malicious = (
        _pe_malicious(700)    + _pdf_malicious(550)  +
        _ole_malicious(450)   + _ooxml_malicious(550) +
        _other_malicious(250)
    )
    benign = (
        _pe_benign(700)   + _pdf_benign(550)  +
        _ole_benign(450)  + _ooxml_benign(550) +
        _other_benign(250)
    )

    X_mal = np.array([[r[k] for k in FILE_FEATURE_NAMES] for r in malicious], dtype=np.float32)
    X_ben = np.array([[r[k] for k in FILE_FEATURE_NAMES] for r in benign],    dtype=np.float32)
    y_mal = np.ones(len(malicious),  dtype=np.int32)
    y_ben = np.zeros(len(benign),    dtype=np.int32)

    X = np.vstack([X_mal, X_ben])
    y = np.concatenate([y_mal, y_ben])

    # Shuffle
    idx = rng.permutation(len(y))
    return X[idx], y[idx]


# ── main ──────────────────────────────────────────────────────────────────────

def main() -> None:
    log.info("Building synthetic dataset …")
    X, y = build_dataset()
    log.info("Dataset: %s  |  labels: %s", X.shape, Counter(y.tolist()))

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.20, stratify=y, random_state=42
    )

    # Fit + calibration split
    X_fit, X_cal, y_fit, y_cal = train_test_split(
        X_train, y_train, test_size=0.15, stratify=y_train, random_state=0
    )

    base = HistGradientBoostingClassifier(
        max_iter=300,
        learning_rate=0.05,
        max_depth=6,
        min_samples_leaf=15,
        l2_regularization=0.1,
        class_weight="balanced",
        random_state=42,
    )

    log.info("Training HistGradientBoostingClassifier …")
    base.fit(X_fit, y_fit)

    calibrator = IsotonicRegression(out_of_bounds="clip")
    calibrator.fit(base.predict_proba(X_cal)[:, 1], y_cal)
    log.info("Calibration fitted on %d samples.", len(y_cal))

    # Evaluation
    y_proba = calibrator.predict(base.predict_proba(X_test)[:, 1])
    y_pred  = (y_proba >= 0.5).astype(int)
    auc     = roc_auc_score(y_test, y_proba)

    log.info("ROC AUC  : %.4f", auc)
    log.info("Confusion matrix:\n%s", confusion_matrix(y_test, y_pred))
    log.info("Classification report:\n%s",
             classification_report(y_test, y_pred,
                                   target_names=["benign", "malicious"], digits=4))

    # 5-fold CV
    cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=0)
    cv_scores = cross_val_score(base, X_train, y_train, cv=cv,
                                scoring="roc_auc", n_jobs=1)
    log.info("CV AUC: %.4f ± %.4f  (per fold: %s)",
             cv_scores.mean(), cv_scores.std(),
             "  ".join(f"{s:.4f}" for s in cv_scores))

    # Save
    calibrated = CalibratedClassifier(base, calibrator)
    artifact = {
        "model": calibrated,
        "feature_names": list(FILE_FEATURE_NAMES),
        "metadata": {
            "dataset": "synthetic_realistic_v1",
            "total_samples": len(y),
            "label_counts": dict(Counter(y.tolist())),
            "test_auc": round(float(auc), 6),
            "cv_auc_mean": round(float(cv_scores.mean()), 6),
            "cv_auc_std": round(float(cv_scores.std()), 6),
            "model_type": "HistGradientBoostingClassifier+IsotonicCalibration",
            "feature_count": len(FILE_FEATURE_NAMES),
        },
    }
    joblib.dump(artifact, OUT_MODEL, compress=3)
    log.info("Model saved → %s  (%.1f KB)",
             OUT_MODEL, os.path.getsize(OUT_MODEL) / 1000)


if __name__ == "__main__":
    main()
