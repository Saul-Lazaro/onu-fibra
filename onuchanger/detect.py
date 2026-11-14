"""Detección del gateway y de la marca de la ONU."""
from __future__ import annotations

import os
import platform
import re
import socket
import struct
import subprocess

import requests
import urllib3

from .base import OnuDriver, OnuError
from .drivers.fiberhome import FiberhomeDriver
from .drivers.huawei import HuaweiDriver
from .drivers.zte import ZteDriver

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

DRIVERS: dict[str, type[OnuDriver]] = {
    "huawei": HuaweiDriver,
    "zte": ZteDriver,
    "fiberhome": FiberhomeDriver,
}


def android_gateway() -> str | None:
    """En Android 10+ /proc/net/route está bloqueado para las apps; se usa WifiManager."""
    try:
        from jnius import autoclass, cast
        activity = autoclass("org.kivy.android.PythonActivity").mActivity
        context = autoclass("android.content.Context")
        wm = cast("android.net.wifi.WifiManager",
                  activity.getApplicationContext().getSystemService(context.WIFI_SERVICE))
        gw = wm.getDhcpInfo().gateway  # int de Java, little-endian
        return socket.inet_ntoa(struct.pack("<i", gw)) if gw else None
    except Exception:
        return None


def default_gateway() -> str | None:
    """IP del gateway por defecto (Android, Linux, macOS y Windows)."""
    if "ANDROID_ARGUMENT" in os.environ or "ANDROID_PRIVATE" in os.environ:
        return android_gateway()
    system = platform.system()
    try:
        if system == "Linux":
            with open("/proc/net/route") as fh:
                for line in fh.readlines()[1:]:
                    parts = line.split()
                    if parts[1] == "00000000" and int(parts[3], 16) & 2:
                        return socket.inet_ntoa(struct.pack("<L", int(parts[2], 16)))
        elif system == "Darwin":
            out = subprocess.run(["route", "-n", "get", "default"], capture_output=True, text=True).stdout
            m = re.search(r"gateway:\s*(\S+)", out)
            return m.group(1) if m else None
        elif system == "Windows":
            out = subprocess.run(["ipconfig"], capture_output=True, text=True).stdout
            m = re.search(r"(?:Default Gateway|Puerta de enlace predeterminada)[ .]*:\s*(\d+\.\d+\.\d+\.\d+)", out)
            return m.group(1) if m else None
    except OSError:
        pass
    return None


def _base(host: str) -> str:
    host = host.strip().rstrip("/")
    return host if host.startswith("http") else f"http://{host}"


def detect_brand(host: str, timeout: int = 6) -> str | None:
    """Huella de la página de inicio y, si no basta, sondas sin credenciales."""
    url = _base(host)
    s = requests.Session()
    s.verify = False
    try:
        r = s.get(url + "/", timeout=timeout, allow_redirects=True)
    except requests.RequestException as e:
        raise OnuError(f"No se pudo conectar con {url}. ¿Estás conectado al Wi‑Fi de la ONU? ({e.__class__.__name__})") from e
    html = r.text
    # Huawei suele redirigir con JS a la página de login real.
    if len(html) < 600:
        m = re.search(r"location(?:\.href|\.replace)?\s*\(?\s*=?\s*['\"]([^'\"]+)['\"]", html)
        if m and not m.group(1).startswith("http"):
            try:
                html += s.get(url + "/" + m.group(1).lstrip("/"), timeout=timeout).text
            except requests.RequestException:
                pass
    for key in ("zte", "huawei", "fiberhome"):
        if DRIVERS[key].matches(html, dict(r.headers)):
            return key
    for key in ("zte", "fiberhome"):
        if DRIVERS[key].probe(s, url, timeout):
            return key
    return None


def get_driver(host: str | None, username: str, password: str, brand: str | None = None) -> OnuDriver:
    host = (host or default_gateway() or "").strip()
    if not host:
        raise OnuError("No se encontró la IP de la ONU; escríbela (suele ser 192.168.1.1 o 192.168.100.1).")
    brand = brand or detect_brand(host)
    if brand not in DRIVERS:
        raise OnuError(f"No se reconoció la marca de la ONU en {host}. Elige la marca manualmente "
                       "(Huawei, ZTE o FiberHome).")
    return DRIVERS[brand](host, username, password)
