[app]
title = Mi ONU de fibra
package.name = onufibra
package.domain = com.onuchanger
source.dir = .
source.include_exts = py
source.exclude_dirs = tests, bin, .buildozer, .github, .git, __pycache__
version = 0.1.0

# Dependencias que python-for-android empaqueta dentro del APK.
# pycryptodome (receta nativa en p4a): login FiberHome, clave Wi‑Fi cifrada y firma Check de ZTE.
requirements = python3,kivy,pyjnius,android,requests,urllib3,idna,certifi,charset-normalizer,pycryptodome

orientation = portrait
fullscreen = 0

# INTERNET: hablar con la ONU. ACCESS_WIFI_STATE: leer la IP del gateway.
android.permissions = INTERNET, ACCESS_NETWORK_STATE, ACCESS_WIFI_STATE
android.api = 36
android.minapi = 24
android.ndk = 28c
android.archs = arm64-v8a, armeabi-v7a
android.accept_sdk_license = True
android.allow_backup = False
android.release_artifact = aab
android.debug_artifact = apk

p4a.branch = develop

[buildozer]
log_level = 2
warn_on_root = 1
