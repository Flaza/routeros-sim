[app]

# Имя приложения (видно под иконкой)
title = RouterOS Simulator

# Имя пакета — должно быть уникальным, в формате обратного домена
package.name = routerossim

# Домен (обычно org, com, net). Влияет на итоговый package id
package.domain = org.example

# Точка входа — наш main.py
source.dir = .

# Какие .py файлы включать (все из папки проекта)
source.include_exts = py,png,jpg,kv,atlas,json,rsc,txt

# Файлы, которые нужно исключить
source.exclude_dirs = bin,.buildozer,tests,__pycache__

# Версия приложения
version = 0.1

# Требования: kivy — обязателен, остальное подтягивается автоматически
requirements = python3==3.12.9,hostpython3==3.12.9,kivy

# Ориентация экрана
orientation = portrait

# Полноэкранный режим
fullscreen = 0

# Минимальная и целевая версия Android
android.minapi = 21
android.api = 33
android.ndk = 25b
android.ndk_api = 21
android.archs = arm64-v8a, armeabi-v7a

# Разрешения Android (для вашего случая — минимум)
android.permissions = INTERNET

# Разрешить установку на внешнюю SD-карту
android.allow_backup = True

# Оставить ли лог Android в файле
android.logcat_filters = *:S python:D

# Запуск в фоне
android.wakelock = False

# Тема
android.apptheme = "@android:style/Theme.NoTitleBar"

# Иконка (если положите icon.png в папку проекта)
# icon.filename = %(source.dir)s/icon.png

# Экран приветствия (опционально)
# presplash.filename = %(source.dir)s/presplash.png


[buildozer]

# Уровень логов: 1 — кратко, 2 — подробно
log_level = 2

# Собирать ли APK в debug-режиме (True) или release (False)
# Для отладки оставьте True
warn_on_root = 1

# Автоматически принимать лицензии Android SDK
android.accept_sdk_license = True
