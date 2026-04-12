import joblib
import os

model_path = os.path.join(os.path.dirname(__file__), "file_model.pkl")
model = joblib.load(model_path)

def predict_proba(features: dict) -> float:
    keys = model.feature_names_in_
    row = [[features.get(k, 0) for k in keys]]
    return float(model.predict_proba(row)[0][1])
