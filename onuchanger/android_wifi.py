"""Reconectar el celular a la red con el nombre/clave nuevos.

Android no deja a las apps cambiar la red Wi‑Fi del teléfono sin intervención
del usuario desde Android 10, así que según la versión:

  Android 11+ (API 30+)  Panel del sistema "¿Guardar red?" (ACTION_WIFI_ADD_NETWORKS).
                         El usuario toca Guardar: la red queda guardada con los datos
                         nuevos (si el nombre no cambió, se actualiza la clave) y el
                         teléfono se conecta solo.
  Android 10 (API 29)    Sugerencia de red (addNetworkSuggestions). La primera vez el
                         sistema muestra una notificación para permitirla; luego se
                         conecta solo cuando la red anterior deja de funcionar.
  Android 9 o menos      Conexión directa (addNetwork + enableNetwork).

Fuera de Android (PC / pruebas) no hace nada y lo indica.
"""
from __future__ import annotations

import os


def on_android() -> bool:
    return "ANDROID_ARGUMENT" in os.environ or "ANDROID_PRIVATE" in os.environ


def _autoclass(name):
    from jnius import autoclass
    return autoclass(name)


def save_and_connect(creds: list[tuple[str, str]], autoclass=None) -> str:
    """creds: [(ssid, clave)]. Devuelve el mensaje para el usuario."""
    creds = [(s, p) for s, p in creds if s and p][:5]   # el panel del sistema acepta hasta 5
    if not creds:
        return ""
    if autoclass is None:
        if not on_android():
            return "Conecta este equipo a la red con los datos nuevos."
        autoclass = _autoclass

    sdk = autoclass("android.os.Build$VERSION").SDK_INT
    activity = autoclass("org.kivy.android.PythonActivity").mActivity
    names = ", ".join(s for s, _ in creds)

    if sdk >= 29:
        Builder = autoclass("android.net.wifi.WifiNetworkSuggestion$Builder")
        ArrayList = autoclass("java.util.ArrayList")
        suggestions = ArrayList()
        for ssid, password in creds:
            b = Builder()
            b.setSsid(ssid)
            b.setWpa2Passphrase(password)   # también sirve para redes mixtas WPA2/WPA3
            suggestions.add(b.build())
        if sdk >= 30:
            Intent = autoclass("android.content.Intent")
            Settings = autoclass("android.provider.Settings")
            intent = Intent(Settings.ACTION_WIFI_ADD_NETWORKS)
            intent.putParcelableArrayListExtra(Settings.EXTRA_WIFI_NETWORK_LIST, suggestions)
            activity.startActivity(intent)
            return f"Toca «Guardar» en el aviso del sistema y el celular se conectará solo a {names}."
        Context = autoclass("android.content.Context")
        wm = activity.getApplicationContext().getSystemService(Context.WIFI_SERVICE)
        status = wm.addNetworkSuggestions(suggestions)
        if status != 0:   # STATUS_NETWORK_SUGGESTIONS_SUCCESS
            return f"No se pudo guardar la red automáticamente (código {status}). Conéctate a {names} desde Ajustes."
        return (f"Si aparece una notificación «¿Permitir redes sugeridas?», tócala y elige Permitir: "
                f"el celular se conectará solo a {names}.")

    # Android 9 o menos: conexión directa
    WifiConfiguration = autoclass("android.net.wifi.WifiConfiguration")
    Context = autoclass("android.content.Context")
    wm = activity.getApplicationContext().getSystemService(Context.WIFI_SERVICE)
    first_id = -1
    for ssid, password in creds:
        conf = WifiConfiguration()
        conf.SSID = f'"{ssid}"'
        conf.preSharedKey = f'"{password}"'
        net_id = wm.addNetwork(conf)
        if net_id != -1 and first_id == -1:
            first_id = net_id
    if first_id == -1:
        return f"No se pudo guardar la red automáticamente. Conéctate a {names} desde Ajustes."
    wm.saveConfiguration()
    wm.disconnect()
    wm.enableNetwork(first_id, True)
    wm.reconnect()
    return f"Conectando el celular a {creds[0][0]} con los datos nuevos…"
