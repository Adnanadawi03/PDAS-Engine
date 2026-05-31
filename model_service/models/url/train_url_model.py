"""
PDAS URL Phishing Detection — Model Training v2
================================================
Dataset : PhiUSIIL_Phishing_URL_Dataset  (235 K URLs, label 0=phishing / 1=legit)
Model   : HistGradientBoostingClassifier
Features: 98 URL-only features (no page-fetch required at inference)
"""

import csv
import logging
import os
import sys
from collections import Counter

import joblib
import numpy as np
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    roc_auc_score,
)
from sklearn.model_selection import StratifiedKFold, cross_val_score, train_test_split

# ── path setup ────────────────────────────────────────────────────────────────
ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../../.."))
sys.path.insert(0, ROOT)

from model_service.app.utils.url_features import extract_url_features
from model_service.app.utils.url_ml_features import ML_FEATURE_NAMES, extract_ml_url_features
from model_service.models.calibration import CalibratedClassifier

# ── config ────────────────────────────────────────────────────────────────────
DATASET = r"E:\pdas\pdas\PhiUSIIL_Phishing_URL_Dataset 2.csv"
OUT_MODEL = os.path.join(os.path.dirname(__file__), "url_model.pkl")

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("pdas.train")

# Basic features from url_features.py that are NOT already in ML_FEATURE_NAMES
# These add complementary signal without duplicating the char-count features.
EXTRA_FEATURE_NAMES = [
    "tld_len",
    "path_len",
    "susp_words",
    "subdomain_depth",
    "starts_https",
    "registered_domain_len",
    "path_segments",
    "has_suspicious_extension",
]

ALL_FEATURE_NAMES = ML_FEATURE_NAMES + EXTRA_FEATURE_NAMES


# ── feature extraction ────────────────────────────────────────────────────────

def extract_all(url: str) -> list[float]:
    try:
        basic = extract_url_features(url)        # includes ml features inside
        ml = extract_ml_url_features(url)
        row = {}
        row.update(ml)
        for k in EXTRA_FEATURE_NAMES:
            row[k] = float(basic.get(k, 0))
        return [row.get(k, 0.0) for k in ALL_FEATURE_NAMES]
    except Exception:
        return [0.0] * len(ALL_FEATURE_NAMES)


# ── augmented legitimate URLs ─────────────────────────────────────────────────
# The PhiUSIIL dataset contains only root-level legitimate URLs (no paths).
# We add representative examples of well-known sites with paths so the model
# learns that paths alone don't indicate phishing for trusted domains.

_AUGMENT_DOMAINS = [
    "google.com", "youtube.com", "gmail.com",
    "facebook.com", "instagram.com", "twitter.com",
    "amazon.com", "paypal.com", "apple.com",
    "microsoft.com", "github.com", "linkedin.com",
    "reddit.com", "netflix.com", "adobe.com",
    "dropbox.com", "slack.com", "zoom.us",
    "stackoverflow.com", "openai.com", "stripe.com",
    "shopify.com", "notion.so", "figma.com",
    "atlassian.com", "vercel.com", "cloudflare.com",
]

_AUGMENT_PATHS = [
    "/", "/signin", "/login", "/logout", "/account",
    "/dashboard", "/settings", "/profile", "/home",
    "/help", "/about", "/contact", "/news", "/blog",
    "/search?q=test", "/products", "/pricing",
    "/en/home", "/en-us/account", "/docs", "/api",
    "/security", "/password/reset", "/2fa", "/notifications",
    "/trending", "/explore", "/marketplace",
    "/help/articles/reset-password",
    "/account/settings/security",
    "/en-us/microsoft-365",
    "/docs/getting-started",
    "/blog/2024/update",
]

_AUGMENT_PREFIXES = [
    "https://",
    "https://www.",
    "https://app.",
    "https://my.",
]

SIM_IDX_COL = "URLSimilarityIndex"   # pre-computed in PhiUSIIL dataset


def _build_augmented_data() -> tuple[list[list[float]], list[int]]:
    """Generate legitimate URL examples with paths for augmentation.

    Uses multiple URL prefixes (with/without www, app., my.) to cover
    the diversity of real-world legitimate URL patterns.
    """
    X_aug, y_aug = [], []
    sim_idx_pos = ALL_FEATURE_NAMES.index("url_similarity_idx")
    seen: set[str] = set()
    for prefix in _AUGMENT_PREFIXES:
        for domain in _AUGMENT_DOMAINS:
            for path in _AUGMENT_PATHS:
                url = f"{prefix}{domain}{path}"
                if url in seen:
                    continue
                seen.add(url)
                try:
                    feats = list(extract_all(url))
                    # Force url_similarity_idx=100 (confirmed legitimate)
                    feats[sim_idx_pos] = 100.0
                    X_aug.append(feats)
                    y_aug.append(0)   # legitimate
                except Exception:
                    pass
    return X_aug, y_aug


def load_dataset(path: str) -> tuple[list[list[float]], list[int]]:
    X, y = [], []
    skipped = 0
    log.info("Reading %s …", path)
    with open(path, encoding="utf-8-sig", newline="") as fh:
        reader = csv.DictReader(fh)
        for i, row in enumerate(reader):
            url = (row.get("URL") or "").strip()
            label_raw = (row.get("label") or "").strip()
            if not url or not label_raw:
                skipped += 1
                continue
            try:
                # PhiUSIIL: 0 = phishing, 1 = legitimate
                # Our convention: 1 = phishing, 0 = legitimate  → invert
                y.append(1 - int(label_raw))
                feats = extract_all(url)
                # Override url_similarity_idx with the dataset's pre-computed
                # value (0–100 scale), which captures legitimacy independent of
                # URL path structure.  At inference this slot is filled by a
                # trusted-domain lookup in url_ml_features.py.
                sim_raw = row.get(SIM_IDX_COL, "").strip()
                if sim_raw:
                    sim_idx = ALL_FEATURE_NAMES.index("url_similarity_idx")
                    feats[sim_idx] = float(sim_raw)
                X.append(feats)
            except Exception:
                skipped += 1
            if (i + 1) % 20_000 == 0:
                log.info("  processed %d rows …", i + 1)
    log.info("Loaded %d rows  |  skipped %d", len(y), skipped)
    return X, y


# ── main ──────────────────────────────────────────────────────────────────────

def main() -> None:
    if not os.path.exists(DATASET):
        raise FileNotFoundError(f"Dataset not found: {DATASET}")

    X_raw, y_raw = load_dataset(DATASET)

    # Augment with legitimate URLs that have paths (fixes path-length bias)
    log.info("Building augmented legitimate examples …")
    X_aug, y_aug = _build_augmented_data()
    log.info("  added %d augmented legitimate examples", len(y_aug))
    X_raw.extend(X_aug)
    y_raw.extend(y_aug)

    X = np.array(X_raw, dtype=np.float32)
    y = np.array(y_raw, dtype=np.int32)

    log.info("Feature matrix: %s  |  label counts: %s", X.shape, Counter(y_raw))

    # ── train / test split (stratified) ──────────────────────────────────────
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.20, stratify=y, random_state=42
    )
    log.info("Train: %d  |  Test: %d", len(y_train), len(y_test))

    # ── model ─────────────────────────────────────────────────────────────────
    # HistGradientBoostingClassifier: fast native boosting, handles float32,
    # no scaling needed, built-in class_weight support (sklearn ≥ 1.2).
    base = HistGradientBoostingClassifier(
        max_iter=400,
        learning_rate=0.05,
        max_depth=7,
        min_samples_leaf=25,
        l2_regularization=0.15,
        max_features=0.8,           # subsample features per split → less overfit
        class_weight="balanced",
        random_state=42,
    )

    log.info("Training HistGradientBoostingClassifier …")
    # Split train into fit (85%) + calibration (15%) sets.
    # HistGBT probabilities are reasonable out of the box, but a small
    # held-out calibration fold aligns probabilities to the true positive rate.
    X_fit, X_cal, y_fit, y_cal = train_test_split(
        X_train, y_train, test_size=0.15, stratify=y_train, random_state=0
    )
    base.fit(X_fit, y_fit)

    # Isotonic calibration on the held-out calibration set
    from sklearn.isotonic import IsotonicRegression
    raw_cal = base.predict_proba(X_cal)[:, 1]
    calibrator = IsotonicRegression(out_of_bounds="clip")
    calibrator.fit(raw_cal, y_cal)
    log.info("Calibration fitted on %d samples.", len(y_cal))

    # ── evaluation ────────────────────────────────────────────────────────────
    raw_test = base.predict_proba(X_test)[:, 1]
    y_proba = calibrator.predict(raw_test)  # calibrated probabilities
    y_pred = (y_proba >= 0.5).astype(int)

    auc = roc_auc_score(y_test, y_proba)
    log.info("ROC AUC  : %.4f", auc)
    log.info("Confusion matrix:\n%s", confusion_matrix(y_test, y_pred))
    log.info(
        "Classification report:\n%s",
        classification_report(y_test, y_pred, target_names=["legit", "phishing"], digits=4),
    )

    # ── 5-fold cross-validation (on training set) ─────────────────────────────
    log.info("Running 5-fold CV on training set (AUC) …")
    cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=0)
    cv_scores = cross_val_score(base, X_train, y_train, cv=cv, scoring="roc_auc", n_jobs=1)
    log.info("CV AUC: %.4f ± %.4f  (per fold: %s)", cv_scores.mean(), cv_scores.std(),
             "  ".join(f"{s:.4f}" for s in cv_scores))

    # ── feature importance (top 20) ───────────────────────────────────────────
    try:
        from sklearn.inspection import permutation_importance
        perm = permutation_importance(base, X_test, y_test, n_repeats=5,
                                      scoring="roc_auc", random_state=0, n_jobs=1)
        top_idx = np.argsort(perm.importances_mean)[::-1][:20]
        log.info("Top-20 features by permutation importance (AUC drop):")
        for rank, idx in enumerate(top_idx, 1):
            log.info("  %2d. %-35s %.4f ± %.4f", rank, ALL_FEATURE_NAMES[idx],
                     perm.importances_mean[idx], perm.importances_std[idx])
    except Exception as exc:
        log.warning("Feature importance skipped: %s", exc)

    # ── save artifact ─────────────────────────────────────────────────────────
    # Wrap base + calibrator into CalibratedClassifier (defined in
    # model_service/models/calibration.py) so joblib can always unpickle
    # the class without importing train_url_model.
    calibrated = CalibratedClassifier(base, calibrator)

    artifact = {
        "model": calibrated,
        "feature_names": list(ALL_FEATURE_NAMES),
        "metadata": {
            "dataset": "PhiUSIIL_Phishing_URL_Dataset_2",
            "total_rows": len(y_raw),
            "label_counts": dict(Counter(y_raw)),
            "test_auc": round(float(auc), 6),
            "cv_auc_mean": round(float(cv_scores.mean()), 6),
            "cv_auc_std": round(float(cv_scores.std()), 6),
            "model_type": "HistGradientBoostingClassifier+IsotonicCalibration",
            "feature_count": len(ALL_FEATURE_NAMES),
        },
    }
    joblib.dump(artifact, OUT_MODEL, compress=3)
    log.info("Model saved → %s  (%.1f MB)", OUT_MODEL, os.path.getsize(OUT_MODEL) / 1e6)


if __name__ == "__main__":
    main()
