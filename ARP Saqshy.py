import os
import time
import platform
import re
from plyer import notification  # Библиотека для уведомлений

SCAN_INTERVAL = 10
arp_table = {}

def get_arp_table():
    """Собирает ARP-таблицу через команду arp -a (для Windows)"""
    print("[🔍] Обновление ARP-таблицы...")

    output = os.popen("arp -a").read()
    matches = re.findall(r"(\d+\.\d+\.\d+\.\d+)\s+([0-9A-Fa-f:-]+)", output)

    new_table = {ip: mac for ip, mac in matches}

    if not new_table:
        print("    ❌ ARP-таблица пуста! Возможно, нет доступа к сети.")

    print("[ℹ] Текущая ARP-таблица:")
    for ip, mac in new_table.items():
        print(f"    {ip} → {mac}")

    return new_table

def notify(title, message):
    """Функция для вывода уведомлений"""
    notification.notify(
        title=title,
        message=message,
        app_name="ARP-Detector",
        timeout=5  # Время показа уведомления (секунды)
    )

def detect_arp_spoofing():
    """Обнаружение ARP-spoofing"""
    global arp_table
    new_arp_table = get_arp_table()

    for ip, mac in new_arp_table.items():
        if ip in arp_table and arp_table[ip] != mac:
            alert_msg = f"[⚠] Обнаружен ARP-spoofинг!\n{ip} → {mac} (Было: {arp_table[ip]})"
            print(alert_msg)
            notify("⚠ ARP-spoofing обнаружен!", f"IP: {ip}\nНовый MAC: {mac}\nСтарый MAC: {arp_table[ip]}")

    arp_table = new_arp_table

if __name__ == "__main__":
    print("[🔍] Запуск мониторинга ARP-таблицы...")
    while True:
        detect_arp_spoofing()
        time.sleep(SCAN_INTERVAL)
