import pandas as pd
from sklearn.ensemble import RandomForestClassifier
import joblib
import os, sys

# إضافة المسار عشان يلاقي utils
sys.path.append(os.path.join(os.path.dirname(__file__), "../../app"))
from model_service.app.utils.file_features import sniff_type_and_features

# بيانات مبدئية (تحتاج داتا أكبر من VirusShare أو EMBER Dataset)
samples = [
    {"filename": "malicious.exe", "bytes": b"MZ...powershell", "label": 1},
    {"filename": "invoice.pdf", "bytes": b"%PDF-1.4 /JavaScript", "label": 1},
    {"filename": "report.docx", "bytes": b"PK\x03\x04word/document.xml", "label": 0},
    {"filename": "clean.pdf", "bytes": b"%PDF-1.4 content", "label": 0},
]

rows = []
for s in samples:
    _, feats = sniff_type_and_features(s["bytes"], s["filename"])
    feats["label"] = s["label"]
    rows.append(feats)

df = pd.DataFrame(rows)

# 🛠️ حذف الأعمدة النصية (ext, type) مؤقتاً لأنها Strings
if "ext" in df.columns:
    df = df.drop("ext", axis=1)
if "type" in df.columns:
    df = df.drop("type", axis=1)

X = df.drop("label", axis=1).fillna(0)
y = df["label"]

# تدريب الموديل
model = RandomForestClassifier(n_estimators=200, random_state=42)
model.fit(X, y)

# حفظ الموديل
os.makedirs(os.path.dirname(__file__), exist_ok=True)
joblib.dump(model, os.path.join(os.path.dirname(__file__), "file_model.pkl"))
print("✅ File model saved!")
