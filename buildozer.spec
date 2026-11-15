[app]
title = MaxsFibra
package.name = onufibra
package.domain = com.onuchanger
source.dir = .
source.include_exts = py,png
source.exclude_dirs = tests, bin, .buildozer, .github, .git, __pycache__
version = 0.2.0

icon.filename = %(source.dir)s/icon.png
presplash.filename = %(source.dir)s/presplash.png
android.presplash_color = #FFFFFF

# Dependencias que python-for-android empaqueta dentro del APK.
# pycryptodome (receta nativa en p4a): login FiberHome, clave Wi‑Fi cifrada y firma Check de ZTE.
requirements = python3,kivy,pyjnius,android,requests,urllib3,idna,certifi,charset-normalizer,pycryptodome

orientation = portrait
fullscreen = 0

# INTERNET: hablar con la ONU. ACCESS_WIFI_STATE: leer la IP del gateway.
# CHANGE_WIFI_STATE: guardar la red con el nombre/clave nuevos y reconectar el celular.
android.permissions = INTERNET, ACCESS_NETWORK_STATE, ACCESS_WIFI_STATE, CHANGE_WIFI_STATE, REQUEST_INSTALL_PACKAGES
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
