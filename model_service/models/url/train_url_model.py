import os, sys, csv, joblib
import pandas as pd
from tqdm import tqdm
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, roc_auc_score

# إضافة مسار utils
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../app")))
from model_service.app.utils.url_features import extract_url_features

# -------- CONFIG --------
# ضع ملفات البيانات هنا
PHISHTANK_CSV = os.path.join(os.path.dirname(__file__), "phish_urls.csv")   # روابط خبيثة
BENIGN_CSV    = os.path.join(os.path.dirname(__file__), "benign_urls.csv")  # روابط نظيفة
OUT_MODEL     = os.path.join(os.path.dirname(__file__), "url_model.pkl")
# ------------------------

def load_urls_from_csv(path, url_col_name="url", limit=None):
    """قراءة روابط من CSV"""
    urls = []
    if not os.path.exists(path):
        print("⚠️ الملف غير موجود:", path)
        return urls
    with open(path, "r", encoding="utf8", errors="ignore") as fh:
        reader = csv.DictReader(fh)
        for i, row in enumerate(reader):
            urls.append(row.get(url_col_name) or list(row.values())[0])
            if limit and i+1 >= limit:
                break
    return urls

def featurize_list(urls, label):
    """تحويل كل URL إلى features"""
    rows = []
    for u in tqdm(urls, desc=f"featurize label={label}", unit="url"):
        try:
            feats = extract_url_features(u)
            feats["label"] = int(label)
            rows.append(feats)
        except Exception as e:
            print("❌ خطأ في URL:", u, e)
    return rows

def main():
    print("📥 تحميل البيانات...")
    phish_urls = load_urls_from_csv(PHISHTANK_CSV, url_col_name="url")
    benign_urls = load_urls_from_csv(BENIGN_CSV, url_col_name="url")

    print(f"✔️ روابط خبيثة: {len(phish_urls)} | روابط نظيفة: {len(benign_urls)}")

    # استخراج الخصائص
    rows = []
    rows += featurize_list(phish_urls, label=1)
    rows += featurize_list(benign_urls, label=0)

    df = pd.DataFrame(rows)
    print("📊 إجمالي العينات:", len(df))

    # تجهيز البيانات
    df = df.fillna(0)
    for c in df.columns:
        if df[c].dtype == 'bool':
            df[c] = df[c].astype(int)

    X = df.drop(columns=["label"])
    y = df["label"].astype(int)

    # تقسيم Train/Test
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, stratify=y, random_state=42
    )

    # تدريب الموديل
    print("🤖 تدريب RandomForest...")
    model = RandomForestClassifier(n_estimators=300, n_jobs=-1, random_state=42)
    model.fit(X_train, y_train)

    # تقييم
    y_pred = model.predict(X_test)
    y_proba = model.predict_proba(X_test)[:,1]

    print("\n📈 تقرير التقييم:")
    print(classification_report(y_test, y_pred, digits=3))
    print("ROC AUC:", roc_auc_score(y_test, y_proba))

    # حفظ الموديل
    joblib.dump(model, OUT_MODEL)
    print("✅ موديل محفوظ في:", OUT_MODEL)

if __name__ == "__main__":
    main()
