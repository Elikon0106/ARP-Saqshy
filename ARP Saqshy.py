import os
import time
import re
import sys
import platform
from PyQt5.QtWidgets import QApplication, QWidget, QVBoxLayout, QPushButton, QTextEdit, QLabel
from PyQt5.QtCore import QTimer
from win10toast import ToastNotifier
import winreg

title = "ARP-Detector"
SCAN_INTERVAL = 10  # seconds
arp_table = {}

class ARPDetectorApp(QWidget):
    def __init__(self):
        super().__init__()
        self.notifier = ToastNotifier()
        self.initUI()
        self.monitoring = False
        self.timer = QTimer()
        self.timer.timeout.connect(self.detect_arp_spoofing)
        self.setup_autostart()
        self.start_monitoring()  # start automatically

    def initUI(self):
        self.setWindowTitle("ARP Spoofing Detector")
        self.setGeometry(100, 100, 500, 400)
        layout = QVBoxLayout()

        self.label = QLabel("ARP Spoofing Monitor")
        layout.addWidget(self.label)

        self.log_area = QTextEdit()
        self.log_area.setReadOnly(True)
        layout.addWidget(self.log_area)

        self.start_btn = QPushButton("Start Monitoring")
        self.start_btn.clicked.connect(self.start_monitoring)
        layout.addWidget(self.start_btn)

        self.stop_btn = QPushButton("Stop Monitoring")
        self.stop_btn.clicked.connect(self.stop_monitoring)
        self.stop_btn.setEnabled(False)
        layout.addWidget(self.stop_btn)

        self.arp_table_btn = QPushButton("Show ARP Table")
        self.arp_table_btn.clicked.connect(self.show_arp_table)
        layout.addWidget(self.arp_table_btn)

        self.setLayout(layout)

    def log(self, message):
        timestamp = time.strftime("[%H:%M:%S] ")
        log_message = f"{timestamp}{message}"
        self.log_area.append(log_message)
        print(log_message)
        try:
            with open("arp_log.txt", "a", encoding="utf-8") as f:
                f.write(log_message + "\n")
        except Exception as e:
            print(f"[❌] Failed to write log: {e}")

    def get_arp_table(self):
        try:
            output = os.popen("arp -a").read()
            if not output:
                self.log("[⚠] ARP table is empty or unreadable.")
                return {}
            matches = re.findall(r"(\d+\.\d+\.\d+\.\d+)\s+([0-9A-Fa-f:-]+)", output)
            return {ip: mac.lower() for ip, mac in matches}
        except Exception as e:
            self.log(f"[❌] Failed to read ARP table: {e}")
            return {}

    def show_arp_table(self):
        self.log("[📜] Current ARP Table:")
        arp_data = self.get_arp_table()
        for ip, mac in arp_data.items():
            self.log(f"    {ip} → {mac}")

    def notify(self, title, message):
        try:
            self.notifier.show_toast(title, message, duration=5, threaded=True)
        except Exception as e:
            self.log(f"[❌] Notification failed: {e}")

    def disconnect_wifi(self):
        self.log("[⚠] Disconnecting from Wi-Fi due to ARP attack!")
        try:
            if platform.system() == "Windows":
                os.system("netsh wlan disconnect")
            elif platform.system() == "Linux":
                os.system("nmcli radio wifi off")
            self.notify("⚠ Wi-Fi Disconnected!", "ARP attack detected. Wi-Fi has been turned off.")
        except Exception as e:
            self.log(f"[❌] Failed to disconnect Wi-Fi: {e}")

    def detect_arp_spoofing(self):
        try:
            self.log("[⏱] Running ARP check...")
            global arp_table
            new_arp_table = self.get_arp_table()

            if not new_arp_table:
                self.log("[⚠] Empty ARP table, skipping check.")
                return

            for ip, mac in new_arp_table.items():
                if ip in arp_table and arp_table[ip] != mac:
                    alert_msg = f"[⚠] ARP-spoofing detected! {ip} → {mac} (Was: {arp_table[ip]})"
                    self.log(alert_msg)
                    self.notify("⚠ ARP-spoofing detected!", f"IP: {ip}\nNew MAC: {mac}\nOld MAC: {arp_table[ip]}")
                    self.disconnect_wifi()

            arp_table = new_arp_table
        except Exception as e:
            self.log(f"[❌] Error in ARP detection: {e}")

    def start_monitoring(self):
        if not self.monitoring:
            self.monitoring = True
            self.start_btn.setEnabled(False)
            self.stop_btn.setEnabled(True)
            self.log("[🔍] Monitoring started...")
            self.timer.start(SCAN_INTERVAL * 1000)

    def stop_monitoring(self):
        if self.monitoring:
            self.monitoring = False
            self.start_btn.setEnabled(True)
            self.stop_btn.setEnabled(False)
            self.timer.stop()
            self.log("[⏹] Monitoring stopped.")

    def setup_autostart(self):
        if platform.system() == "Windows":
            self.setup_autostart_windows()
        elif platform.system() == "Linux":
            self.setup_autostart_linux()

    def setup_autostart_windows(self):
        key = r"Software\Microsoft\Windows\CurrentVersion\Run"
        exe_path = sys.executable
        app_name = "ARP-Detector"
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key, 0, winreg.KEY_SET_VALUE) as reg_key:
                winreg.SetValueEx(reg_key, app_name, 0, winreg.REG_SZ, exe_path)
                self.log("[✔] Auto-start enabled (Windows)")
        except Exception as e:
            self.log(f"[❌] Failed to enable auto-start: {e}")

    def setup_autostart_linux(self):
        service_content = f"""
        [Unit]
        Description=ARP Detector Service
        After=network.target

        [Service]
        ExecStart={sys.executable} {os.path.abspath(__file__)}
        Restart=always

        [Install]
        WantedBy=default.target
        """
        service_path = "/etc/systemd/system/arp_detector.service"
        try:
            with open(service_path, "w") as f:
                f.write(service_content)
            os.system("systemctl enable arp_detector.service")
            os.system("systemctl start arp_detector.service")
            self.log("[✔] Auto-start enabled (Linux)")
        except Exception as e:
            self.log(f"[❌] Failed to enable auto-start: {e}")

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = ARPDetectorApp()
    window.show()
    sys.exit(app.exec_())
