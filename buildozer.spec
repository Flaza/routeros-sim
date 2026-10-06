[app]

title = RouterOS Simulator
package.name = routerossim
package.domain = org.example

source.dir = .
source.include_exts = py,png,jpg,kv,atlas,json,rsc,txt
source.exclude_dirs = bin,.buildozer,tests,__pycache__,.github,.git

version = 0.1

# Никаких жёстких версий python/hostpython — P4A сам разберётся
requirements = python3,kivy==2.3.0

orientation = portrait
fullscreen = 0

android.minapi = 21
android.api = 33
android.ndk = 25b
android.ndk_api = 21
# Только arm64 — быстрее и покрывает 99% современных телефонов
android.archs = arm64-v8a

android.permissions = INTERNET
android.allow_backup = True
android.logcat_filters = *:S python:D
android.wakelock = False
android.apptheme = "@android:style/Theme.NoTitleBar"
android.accept_sdk_license = True

# Раскомментируй, если положишь иконку в корень
# icon.filename = %(source.dir)s/icon.png

[buildozer]
log_level = 2
warn_on_root = 1
