# C:\Program Files\PDAS\agent\agent.py
import os
import time
import shutil
import requests
import traceback
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# ----- إعدادات (عدلها لو احتجت) -----
DOWNLOADS_DIR = os.path.join(os.path.expanduser("~"), "Downloads")  # مجلد المراقبة الافتراضي
PDAS_BASE = os.environ.get("PDAS_BASE", r"C:\ProgramData\PDAS")    # قاعدة للاحتفاظ بالـ logs و quarantine
QUARANTINE_DIR = os.path.join(PDAS_BASE, "Quarantine")
LOG_FILE = os.path.join(PDAS_BASE, "pdas_agent.log")
SCAN_URL = "http://127.0.0.1:8000/scan/file"  # نقطة فحص FastAPI المحلية (غيرها لو السيرفر داخلي)
READ_BYTES = 200_000  # أقصى بايت نقرأها من الملف للفحص الأولي
# -------------------------------------

os.makedirs(QUARANTINE_DIR, exist_ok=True)
os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)

def log(msg: str):
    ts = time.strftime('%Y-%m-%d %H:%M:%S')
    line = f"[{ts}] {msg}"
    try:
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(line + "\n")
    except Exception:
        # لا نخرب الآن لو فشل اللوق
        pass
    print(line)

class DownloadHandler(FileSystemEventHandler):
    def on_created(self, event):
        if event.is_directory:
            return
        filepath = event.src_path
        filename = os.path.basename(filepath)
        log(f"اكتشف ملف جديد: {filepath}")

        # حاول التعامل مع الأخطاء بعناية
        try:
            # انتظر حتى يثبت حجم الملف (يعني التحميل انتهى نسبيًا)
            stable_count = 0
            last_size = -1
            for _ in range(120):  # حتى ~120 ثانية انتظار كحد أقصى
                try:
                    size = os.path.getsize(filepath)
                except FileNotFoundError:
                    log(f"الملف اختفى قبل الفحص: {filepath}")
                    return
                if size == last_size:
                    stable_count += 1
                else:
                    stable_count = 0
                last_size = size
                if stable_count >= 2 and size > 0:
                    break
                time.sleep(1)

            # اقرأ أول READ_BYTES بايت
            with open(filepath, "rb") as f:
                sample = f.read(READ_BYTES)

            files = {"file": (filename, sample)}
            log(f"إرسال ملف للفحص: {filename} (حجم العينة {len(sample)} بايت)")
            try:
                resp = requests.post(SCAN_URL, files=files, timeout=30)
                resp.raise_for_status()
                result = resp.json()
            except Exception as e:
                log(f"خطأ في الاتصال بخدمة الفحص: {e}")
                return

            verdict = result.get("verdict")
            score = result.get("score")
            log(f"نتيجة الفحص ({filename}): verdict={verdict}, score={score}")

            if verdict == "block":
                # حاول أن تنقل الملف إلى قرصنة/عزل
                dest_name = f"{int(time.time())}_{filename}"
                quarantine_path = os.path.join(QUARANTINE_DIR, dest_name)
                try:
                    shutil.move(filepath, quarantine_path)
                    log(f"تم عزل الملف: {quarantine_path}")
                except Exception as e:
                    log(f"فشل نقل الملف إلى quarantine: {e}; محاولة حذف الملف")
                    try:
                        os.remove(filepath)
                        log("تم حذف الملف بعد الفشل.")
                    except Exception as e2:
                        log(f"فشل حذف الملف أيضاً: {e2}")

        except Exception as e:
            log(f"استثناء خلال معالجة الملف {filename}: {e}\n{traceback.format_exc()}")

if __name__ == "__main__":
    log("🚀 بدأ تشغيل PDAS Agent - مراقبة التنزيلات")
    event_handler = DownloadHandler()
    observer = Observer()
    observer.schedule(event_handler, DOWNLOADS_DIR, recursive=False)
    observer.start()
    try:
        while True:
            time.sleep(5)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()
    log("PDAS Agent توقف.")
