import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import threading, subprocess, sys, os, webbrowser
from api_client import scan_url, scan_file, get_events

def run_agent():
    agent_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "agent", "agent.py")
    if not os.path.exists(agent_path):
        print("[ERR] agent.py not found:", agent_path)
        return
    subprocess.Popen([sys.executable, agent_path], stdout=subprocess.PIPE, stderr=subprocess.PIPE)

def refresh_events(tree):
    try:
        events = get_events(20)
        for row in tree.get_children():
            tree.delete(row)
        for e in events:
            tree.insert("", "end", values=(e["id"], e["type"], e["target"], e["verdict"], e["score"], e["timestamp"]))
    except Exception as ex:
        messagebox.showerror("خطأ", f"فشل في تحميل الأحداث: {ex}")

def scan_url_action(entry, tree):
    url = entry.get().strip()
    if not url:
        messagebox.showwarning("تنبيه", "أدخل رابط للفحص")
        return
    try:
        result = scan_url(url)
        messagebox.showinfo("النتيجة", f"{url}\nVerdict: {result['verdict']} (Score: {result['score']})")
        refresh_events(tree)
    except Exception as ex:
        messagebox.showerror("خطأ", f"فشل في فحص الرابط: {ex}")

def scan_file_action(tree):
    path = filedialog.askopenfilename()
    if not path:
        return
    try:
        result = scan_file(path)
        messagebox.showinfo("النتيجة", f"{path}\nVerdict: {result['verdict']} (Score: {result['score']})")
        refresh_events(tree)
    except Exception as ex:
        messagebox.showerror("خطأ", f"فشل في فحص الملف: {ex}")

def open_dashboard():
    webbrowser.open("http://127.0.0.1:8000/dashboard")

def main():
    root = tk.Tk()
    root.title("PDAS Desktop App")
    root.geometry("850x600")

    # تشغيل الـ Agent بالخلفية
    threading.Thread(target=run_agent, daemon=True).start()

    # إدخال رابط
    frame_url = tk.Frame(root)
    frame_url.pack(pady=10)
    entry = tk.Entry(frame_url, width=50)
    entry.pack(side=tk.LEFT, padx=5)
    tk.Button(frame_url, text="افحص الرابط", command=lambda: scan_url_action(entry, tree)).pack(side=tk.LEFT)

    # زر فحص الملفات
    tk.Button(root, text="اختر ملف للفحص", command=lambda: scan_file_action(tree)).pack(pady=5)

    # زر فتح Dashboard
    tk.Button(root, text="افتح الـ Dashboard", command=open_dashboard).pack(pady=5)

    # جدول الأحداث
    columns = ("ID", "النوع", "المستهدف", "النتيجة", "الدرجة", "الوقت")
    tree = ttk.Treeview(root, columns=columns, show="headings", height=15)
    for col in columns:
        tree.heading(col, text=col)
        tree.column(col, width=120)
    tree.pack(expand=True, fill="both", pady=10)

    # زر تحديث
    tk.Button(root, text="تحديث الأحداث", command=lambda: refresh_events(tree)).pack(pady=5)

    # تحديث أولي
    threading.Thread(target=lambda: refresh_events(tree), daemon=True).start()

    root.mainloop()

if __name__ == "__main__":
    main()
