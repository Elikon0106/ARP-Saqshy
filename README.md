##ARP Spoofing Detector: Установка и Настройка##
Этот инструмент предназначен для обнаружения атак ARP Spoofing и уведомления пользователя о возможных угрозах. Программа мониторит ARP-таблицу устройства и уведомляет о любых изменениях, которые могут свидетельствовать о попытке ARP-спуфинга.

Шаг 1: Создание исполняемого файла с помощью PyInstaller
Убедитесь, что у вас установлен Python и все необходимые библиотеки:

PyQt5

win10toast

Вы можете установить их с помощью pip:

pip install PyQt5 win10toast
Установите PyInstaller для создания исполняемого файла:

pip install pyinstaller
После того, как вы создали файл ARP_Saqshy.py, используйте следующую команду для создания исполняемого файла:

pyinstaller --onefile --noconsole --name ARPDetector ARP_Saqshy.py
Эта команда создаст исполняемый файл без консоли, который будет называться ARPDetector.exe.

Шаг 2: Настройка Автозапуска на Windows
Чтобы приложение запускалось автоматически при включении компьютера:

Ручной метод:

Откройте редактор реестра Windows (нажмите Win + R, введите regedit и нажмите Enter).

Перейдите по следующему пути:

HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run
Создайте новый строковый параметр:

Правый клик → Новый → Строковый параметр.

Назовите его ARPDetector.

В значении укажите путь к файлу ARPDetector.exe, который вы создали с помощью PyInstaller. Например:

C:\path\to\your\ARPDetector.exe
Автоматическая настройка (через код): Если вы хотите настроить автозапуск прямо из приложения, код уже содержит функцию для этого:

Для Windows приложение добавит запись в реестр автоматически при запуске. Это будет выполнено с помощью winreg в коде:

self.setup_autostart_windows()
Это добавит ARPDetector в реестр и обеспечит его автоматический запуск при старте Windows.

Шаг 3: Настройка Автозапуска на Linux
Для Linux вы можете настроить автозапуск приложения с помощью системных сервисов.

Автоматическая настройка через код: В коде есть функция, которая создает системный сервис для Linux:

Программа создает файл arp_detector.service, который будет запускать вашу программу при старте системы:

self.setup_autostart_linux()
Сервис будет настроен с использованием systemd. Для его активации будет выполнено несколько команд:

sudo systemctl enable arp_detector.service
sudo systemctl start arp_detector.service
Ручной метод: Если вы хотите вручную настроить автозапуск:

Создайте файл сервиса в /etc/systemd/system/arp_detector.service с содержимым:

[Unit]
Description=ARP Detector Service
After=network.target

[Service]
ExecStart=/usr/bin/python3 /path/to/ARP_Saqshy.py
Restart=always

[Install]
WantedBy=default.target
Активируйте и запустите сервис:

sudo systemctl enable arp_detector.service
sudo systemctl start arp_detector.service
Шаг 4: Использование
Запустите ARPDetector.exe или соответствующий исполняемый файл на вашем устройстве.

Откройте окно приложения. Вы можете начать мониторинг, нажимая кнопку "Start Monitoring".

Приложение будет регулярно проверять ARP-таблицу на наличие изменений.

Если обнаружен ARP-спуфинг, приложение уведомит вас через всплывающее уведомление и отключит Wi-Fi.
