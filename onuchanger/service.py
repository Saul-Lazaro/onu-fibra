"""Operaciones de alto nivel que usa la interfaz (Android o escritorio).
Sin dependencias de Kivy, para poder probarlas en el PC."""
from __future__ import annotations

from dataclasses import dataclass, field

import requests

from .base import (AuthError, CaptchaRequired, Device, NotSupportedError, OnuError, WifiNetwork, normalize_mac, validate_ssid,
                   validate_wifi_password)
from .detect import DRIVERS, default_gateway, get_driver

BRAND_KEYS = {"Detectar marca": None, "Huawei": "huawei", "ZTE": "zte", "FiberHome": "fiberhome",
              "V‑SOL": "realtek", "OptiTimes": "realtek"}
USER_HINTS = {
    "huawei": "Usuario de la etiqueta (p. ej. Epuser, root)",
    "zte": "Usuario de la etiqueta (p. ej. user, admin)",
    "fiberhome": "Usuario de la etiqueta (p. ej. user, admin)",
    "realtek": "Usuario de la etiqueta (p. ej. admin, user)",
}

CUT_MSG = ("La ONU reinició el Wi‑Fi al aplicar el cambio (es normal si este teléfono estaba en esa red).")


@dataclass
class Connection:
    host: str
    brand_key: str | None
    username: str
    password: str
    brand_name: str = ""
    captcha: str = ""                     # código de verificación escrito por el cliente
    # ONUs con código: la sesión se mantiene abierta entre acciones (si no, habría que
    # escribir el código en cada una). `pending`: driver esperando el código.
    live: object = field(default=None, compare=False, repr=False)
    pending: object = field(default=None, compare=False, repr=False)


@dataclass
class Overview:
    networks: list[WifiNetwork] = field(default_factory=list)
    wifi_note: str = ""            # por qué no se puede cambiar el Wi‑Fi (si aplica)
    devices: list[Device] = field(default_factory=list)
    devices_note: str = ""
    can_rename: bool = True        # False: solo se puede cambiar la clave
    can_block: bool = True         # False: la lista de equipos es solo para ver


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


def _open(conn: Connection):
    """Driver con la sesión iniciada. Puede lanzar CaptchaRequired (se guarda el driver
    en conn.pending para reintentar con conn.captcha)."""
    if conn.live is not None:
        return conn.live
    d = conn.pending or _driver(conn)
    conn.pending = None
    d.captcha = conn.captcha.strip()
    conn.captcha = ""
    try:
        d.login()
    except CaptchaRequired:
        conn.pending = d
        raise
    if getattr(d, "captcha_used", False):
        conn.live = d
    return d


def disconnect(conn: Connection | None) -> None:
    """Cierra la sesión que se mantenía abierta (ONUs con código)."""
    if conn is None:
        return
    for d in (conn.live, conn.pending):
        if d is not None:
            try:
                d.close()
            except Exception:
                pass
    conn.live = conn.pending = None


def _with(conn: Connection, fn):
    """Ejecuta fn(driver) con sesión. Si la sesión mantenida venció, inicia otra vez
    (lo que en ONUs con código vuelve a pedirlo)."""
    for attempt in (0, 1):
        d = _open(conn)
        kept = d is conn.live
        try:
            return fn(d)
        except AuthError as e:
            if kept and attempt == 0 and not isinstance(e, CaptchaRequired):
                conn.live = None             # venció: abrir una sesión nueva
                try:
                    d.session.close()
                except Exception:
                    pass
                continue
            raise
        finally:
            if not kept:
                d.close()


def _merge_devices(d) -> list[Device]:
    devices = d.get_devices()
    seen = {x.mac for x in devices}
    return devices + [b for b in d.get_blocked() if b.mac not in seen]


def connect(conn: Connection) -> Overview:
    """Inicia sesión y trae redes y equipos. Rellena conn.brand_name."""
    if conn.pending is None:
        disconnect(conn)            # «Conectar» de nuevo: sesión nueva
    ov = Overview()

    def work(d):
        conn.brand_name = d.brand   # algunos drivers afinan la marca al iniciar sesión
        ov.can_rename = d.can_rename_wifi
        ov.can_block = d.can_block
        if not d.can_block and not ov.devices_note:
            ov.devices_note = "En este modelo de ONU la app aún no puede bloquear equipos; aquí puedes verlos."
        if d.can_change_wifi:
            try:
                # Solo las redes encendidas: las apagadas no se muestran.
                ov.networks = [n for n in d.get_wifi_networks() if n.enabled]
                if not ov.networks:
                    ov.wifi_note = "No hay redes Wi‑Fi encendidas en esta ONU."
            except NotSupportedError as e:
                ov.wifi_note = str(e)
            if ov.networks and not d.can_rename_wifi:
                ov.wifi_note = (f"En {d.brand} la app por ahora solo cambia la clave; el nombre de la red "
                                "se cambia desde el panel web.")
        else:
            ov.wifi_note = (f"Cambiar el nombre y la clave del Wi‑Fi aún no está disponible para {d.brand}. "
                            "Puedes ver y bloquear equipos.")
        try:
            ov.devices = _merge_devices(d)
        except NotSupportedError as e:
            ov.devices_note = str(e)

    _with(conn, work)
    return ov


@dataclass
class ChangeResult:
    message: str
    creds: list[tuple[str, str]]   # (nombre, clave) finales, para reconectar el celular
    cut: bool = False              # la ONU cortó el Wi‑Fi durante el cambio


def change_wifi(conn: Connection, changes: list[tuple[WifiNetwork, str | None]],
                new_password: str, confirm: str) -> ChangeResult:
    """changes: [(red, nuevo_nombre o None)] con la misma clave para todas (vacía = no cambiarla)."""
    return change_wifi_each(conn, [(n, s, new_password, confirm) for n, s in changes])


def change_wifi_each(conn: Connection,
                     items: list[tuple[WifiNetwork, str | None, str, str]]) -> ChangeResult:
    """items: [(red, nuevo_nombre o None, clave, repetir_clave)]; cada red con su propia clave.

    Clave vacía = esa red conserva su clave. Las redes sin cambios se omiten.
    """
    todo = []
    for net, ssid, pw, confirm in items:
        pw, confirm = pw or "", confirm or ""
        if pw or confirm:
            if pw != confirm:
                raise ValueError(f"Red {net.band}: las claves no coinciden.")
            try:
                validate_wifi_password(pw)
            except ValueError as e:
                raise ValueError(f"Red {net.band}: {e}") from None
        ssid = ssid.strip() if ssid else None
        ssid = ssid if ssid and ssid != net.ssid else None
        if ssid is not None:
            try:
                validate_ssid(ssid)
            except ValueError as e:
                raise ValueError(f"Red {net.band}: {e}") from None
        if ssid is not None or pw:
            todo.append((net, ssid, pw or None))
    if not todo:
        raise ValueError("No hay cambios: escribe un nombre nuevo o una clave nueva.")

    # Datos finales de cada red, para que el celular se reconecte solo.
    creds = []
    for net, ssid, password in todo:
        key = password or net.extra.get("psk", "")
        if key and (ssid or net.ssid, key) not in creds:
            creds.append((ssid or net.ssid, key))

    done = []

    def work(d):
        # Primero 5 GHz: si el teléfono está en 2.4 GHz conserva la conexión hasta el final.
        for net, ssid, password in sorted(todo, key=lambda t: t[0].band != "5GHz"):
            d.set_wifi(net, ssid=ssid, password=password)
            if password:
                net.extra["psk"] = password
            what = " y ".join(x for x, on in (("nombre", ssid), ("clave", password)) if on)
            done.append(f"{ssid or net.ssid} ({net.band}: {what})")

    try:
        _with(conn, work)
    except (requests.ConnectionError, requests.Timeout):
        disconnect(conn)            # el Wi‑Fi cambió: la sesión mantenida ya no sirve
        return ChangeResult(CUT_MSG, creds, cut=True)
    return ChangeResult("Listo. Cambios guardados en " + ", ".join(done) + ".", creds)


def list_devices(conn: Connection) -> list[Device]:
    return _with(conn, _merge_devices)


def block(conn: Connection, device: Device, own_ip: str = "") -> list[Device]:
    """Bloquea un equipo. Nunca el celular donde corre la app (`own_ip`): perdería la conexión."""
    mac = normalize_mac(device.mac)
    if own_ip and device.ip == own_ip:
        raise ValueError("Ese equipo es este celular: no se puede bloquear desde la app.")
    def work(d):
        if own_ip:   # la IP puede haber cambiado desde que se mostró la lista
            now = next((x for x in d.get_devices() if x.mac == mac), None)
            if now is not None and now.ip == own_ip:
                raise ValueError("Ese equipo es este celular: no se puede bloquear desde la app.")
        d.block_device(mac, device.name)
        return _merge_devices(d)

    return _with(conn, work)


def unblock(conn: Connection, device: Device) -> list[Device]:
    mac = normalize_mac(device.mac)
    def work(d):
        d.unblock_device(mac)
        return _merge_devices(d)

    return _with(conn, work)
