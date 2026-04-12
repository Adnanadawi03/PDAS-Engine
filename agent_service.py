import win32serviceutil
import win32service
import win32event
import servicemanager
import subprocess
import sys
import os

class PDASAgentService(win32serviceutil.ServiceFramework):
    _svc_name_ = "PDASAgent"
    _svc_display_name_ = "PDAS Security Agent"
    _svc_description_ = "Monitors Downloads and Clipboard, scans files/URLs via PDAS Model Service."

    def __init__(self, args):
        win32serviceutil.ServiceFramework.__init__(self, args)
        self.hWaitStop = win32event.CreateEvent(None, 0, 0, None)

    def SvcStop(self):
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
        win32event.SetEvent(self.hWaitStop)

    def SvcDoRun(self):
        servicemanager.LogInfoMsg("PDAS Agent Service starting...")
        python_exe = sys.executable
        agent_path = os.path.join(os.path.dirname(__file__), "agent.py")
        # نشغّل agent.py كـ subprocess
        p = subprocess.Popen([python_exe, agent_path])
        win32event.WaitForSingleObject(self.hWaitStop, win32event.INFINITE)
        p.terminate()
        servicemanager.LogInfoMsg("PDAS Agent Service stopped.")

if __name__ == '__main__':
    win32serviceutil.HandleCommandLine(PDASAgentService)
