"""Operaciones de alto nivel que usa la interfaz (Android o escritorio).
Sin dependencias de Kivy, para poder probarlas en el PC."""
from __future__ import annotations

from dataclasses import dataclass, field

import requests

from .base import (Device, NotSupportedError, OnuError, WifiNetwork, normalize_mac, validate_ssid,
                   validate_wifi_password)
from .detect import DRIVERS, default_gateway, get_driver

BRAND_KEYS = {"Detectar marca": None, "Huawei": "huawei", "ZTE": "zte", "FiberHome": "fiberhome"}
USER_HINTS = {
    "huawei": "Usuario de la etiqueta (p. ej. Epuser, root)",
    "zte": "Usuario de la etiqueta (p. ej. user, admin)",
    "fiberhome": "Usuario de la etiqueta (p. ej. user, admin)",
}

CUT_MSG = ("La ONU cortó el Wi‑Fi al aplicar el cambio (es normal si este teléfono estaba en esa red). "
           "Reconéctate con el nombre y la clave nuevos y pulsa Conectar para comprobarlo.")


@dataclass
class Connection:
    host: str
    brand_key: str | None
    username: str
    password: str
    brand_name: str = ""


@dataclass
class Overview:
    networks: list[WifiNetwork] = field(default_factory=list)
    wifi_note: str = ""            # por qué no se puede cambiar el Wi‑Fi (si aplica)
    devices: list[Device] = field(default_factory=list)
    devices_note: str = ""


def suggest_host() -> str:
    return default_gateway() or "192.168.1.1"


def _driver(conn: Connection):
    if not conn.password:
        raise OnuError("Escribe la contraseña de la etiqueta de la ONU.")
    d = get_driver(conn.host, conn.username.strip(), conn.password, conn.brand_key)
    conn.brand_name = d.brand
    conn.brand_key = next(k for k, cls in DRIVERS.items() if isinstance(d, cls))
    conn.username = d.username
    return d


def _merge_devices(d) -> list[Device]:
    devices = d.get_devices()
    seen = {x.mac for x in devices}
    return devices + [b for b in d.get_blocked() if b.mac not in seen]


def connect(conn: Connection) -> Overview:
    """Inicia sesión y trae redes y equipos. Rellena conn.brand_name."""
    d = _driver(conn)
    ov = Overview()
    with d:
        if d.can_change_wifi:
            try:
                ov.networks = d.get_wifi_networks()
            except NotSupportedError as e:
                ov.wifi_note = str(e)
        else:
            ov.wifi_note = (f"Cambiar el nombre y la clave del Wi‑Fi aún no está disponible para {d.brand}. "
                            "Puedes ver y bloquear equipos.")
        try:
            ov.devices = _merge_devices(d)
        except NotSupportedError as e:
            ov.devices_note = str(e)
    return ov


def change_wifi(conn: Connection, changes: list[tuple[WifiNetwork, str | None]],
                new_password: str, confirm: str) -> str:
    """changes: [(red, nuevo_nombre o None)]. Si new_password está vacío, no se cambia la clave."""
    if new_password or confirm:
        if new_password != confirm:
            raise ValueError("Las claves no coinciden.")
        validate_wifi_password(new_password)
    password = new_password or None
    todo = [(n, s if s and s != n.ssid else None) for n, s in changes]
    todo = [(n, s) for n, s in todo if s is not None or password is not None]
    if not todo:
        raise ValueError("No hay cambios: escribe un nombre nuevo o una clave nueva.")
    for _, s in todo:
        if s is not None:
            validate_ssid(s)

    d = _driver(conn)
    done = []
    try:
        d.login()
        # Primero 5 GHz: si el teléfono está en 2.4 GHz conserva la conexión hasta el final.
        for net, ssid in sorted(todo, key=lambda t: t[0].band != "5GHz"):
            d.set_wifi(net, ssid=ssid, password=password)
            what = " y ".join(x for x, on in (("nombre", ssid), ("clave", password)) if on)
            done.append(f"{ssid or net.ssid} ({net.band}: {what})")
    except (requests.ConnectionError, requests.Timeout):
        return CUT_MSG
    finally:
        d.close()
    return ("Listo. Cambios guardados en " + ", ".join(done) +
            ". Los equipos conectados deberán reconectarse" + (" con la nueva clave." if password else "."))


def list_devices(conn: Connection) -> list[Device]:
    with _driver(conn) as d:
        return _merge_devices(d)


def block(conn: Connection, device: Device) -> list[Device]:
    mac = normalize_mac(device.mac)
    with _driver(conn) as d:
        d.block_device(mac, device.name)
        return _merge_devices(d)


def unblock(conn: Connection, device: Device) -> list[Device]:
    mac = normalize_mac(device.mac)
    with _driver(conn) as d:
        d.unblock_device(mac)
        return _merge_devices(d)
