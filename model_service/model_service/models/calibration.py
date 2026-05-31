"""
Standalone calibration wrapper — kept separate from training scripts
so joblib can unpickle the class regardless of which script ran training.
"""
import numpy as np


class CalibratedClassifier:
    """Wraps a fitted sklearn classifier with isotonic calibration."""

    def __init__(self, clf, calibrator):
        self._clf = clf
        self._cal = calibrator

    def predict_proba(self, X):
        raw = self._clf.predict_proba(X)[:, 1]
        cal = self._cal.predict(raw)
        return np.column_stack([1.0 - cal, cal])
