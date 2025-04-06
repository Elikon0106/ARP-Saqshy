# ARP Spoofing Detector: Установка и Настройка

**ARP Spoofing Detector** — это инструмент, предназначенный для обнаружения атак ARP Spoofing и защиты вашего устройства. Программа периодически проверяет ARP-таблицу и уведомляет пользователя, если происходит подозрительная активность, такая как изменение MAC-адреса, что может указывать на попытку ARP-спуфинга.

## 📦 Установка

### Шаг 1: Создание исполняемого файла с помощью **PyInstaller**

1. Убедитесь, что у вас установлен **Python** и необходимые библиотеки:
   ```bash
   pip install PyQt5 win10toast
   ```

2. Установите **PyInstaller** для создания исполняемого файла:
   ```bash
   pip install pyinstaller
   ```

3. После того как вы создали файл `ARP_Saqshy.py`, выполните следующую команду для создания исполняемого файла:
   ```bash
   pyinstaller --noconfirm --windowed --onefile --icon=icon.ico ARP_Saqshy.py
   ```
   Это создаст исполняемый файл **`ARPDetector.exe`**, который не будет открывать консольное окно.

### Шаг 2: Настройка Автозапуска на **Windows**

Чтобы приложение автоматически запускалось при включении компьютера, выполните следующие шаги:

#### 1. Ручной метод

- Откройте **Реестр Windows** (нажмите `Win + R`, введите `regedit` и нажмите Enter).
- Перейдите в раздел:
  ```
  HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run
  ```
- Создайте новый строковый параметр (String Value):
  - **Правый клик** → Новый → Строковый параметр.
  - Назовите его **`ARPDetector`**.
  - В значении укажите полный путь к файлу **`ARPDetector.exe`**. Пример:
    ```
    C:\path\to\your\ARPDetector.exe
    ```

### Шаг 3: Настройка Автозапуска на **Linux**

Для Linux вы можете настроить автозапуск с использованием **systemd**.

#### 1. Автоматическая настройка

Код включает функцию, которая создает системный сервис для автозапуска:
```python
self.setup_autostart_linux()
```
Эта функция создаст и активирует сервис с помощью `systemd`, который будет автоматически запускать программу при старте системы.

#### 2. Ручной метод

Если вы хотите настроить автозапуск вручную:

- Создайте файл сервиса в `/etc/systemd/system/arp_detector.service` с содержимым:
  ```ini
  [Unit]
  Description=ARP Detector Service
  After=network.target

  [Service]
  ExecStart=/usr/bin/python3 /path/to/ARP_Saqshy.py
  Restart=always

  [Install]
  WantedBy=default.target
  ```

- Активируйте и запустите сервис с помощью следующих команд:
  ```bash
  sudo systemctl enable arp_detector.service
  sudo systemctl start arp_detector.service
  ```

---

## 🚀 Использование

1. Запустите исполняемый файл **`ARPDetector.exe`** (или соответствующий файл для вашей ОС).
2. Откроется графический интерфейс с кнопками для управления:
   - **Start Monitoring** — начало мониторинга ARP-таблицы.
   - **Stop Monitoring** — остановка мониторинга.
   - **Show ARP Table** — отображение текущей ARP-таблицы.
   
3. Программа будет регулярно проверять ARP-таблицу на наличие изменений.

4. Если будет обнаружен **ARP Spoofing** (например, изменение MAC-адреса), приложение уведомит вас через всплывающее уведомление и автоматически отключит Wi-Fi.

---

## 🔔 Уведомления и действия

- При обнаружении ARP-спуфинга программа:
  - Выведет уведомление с подробной информацией о нарушении.
  - Отключит Wi-Fi для предотвращения дальнейших атак.

---

## 💡 Примечания

- Программа работает как в **Windows**, так и в **Linux**.
- Убедитесь, что ваше устройство подключено к сети, чтобы ARP-таблица была доступна для мониторинга.

---

Если у вас возникли проблемы с установкой или настройкой, не стесняйтесь обратиться за помощью.

