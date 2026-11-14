"""Núcleo común: modelos, errores, validaciones e interfaz de cada driver de ONU."""
from __future__ import annotations

import re
from abc import ABC, abstractmethod
from dataclasses import dataclass, field

import requests


class Band:
    B24 = "2.4GHz"
    B5 = "5GHz"


@dataclass
class WifiNetwork:
    id: str                 # identificador interno del equipo (p. ej. WLANConfiguration.1, DEV.WIFI.AP1)
    band: str               # "2.4GHz" / "5GHz"
    ssid: str
    enabled: bool = True
    extra: dict = field(default_factory=dict, repr=False)  # datos crudos que el driver necesita


@dataclass
class Device:
    mac: str                # AA:BB:CC:DD:EE:FF
    name: str = ""
    ip: str = ""
    interface: str = ""     # "2.4GHz", "5GHz", "LAN"…
    online: bool = True
    blocked: bool = False


class OnuError(Exception):
    """Error genérico de la ONU."""


class AuthError(OnuError):
    """Usuario o contraseña incorrectos, o cuenta bloqueada temporalmente."""


class NotSupportedError(OnuError):
    """El modelo o firmware no permite esta operación por la interfaz web."""


# --- validaciones ----------------------------------------------------------

def validate_wifi_password(password: str) -> None:
    """WPA/WPA2/WPA3-Personal: 8-63 caracteres ASCII imprimibles."""
    if not 8 <= len(password) <= 63:
        raise ValueError("La clave Wi‑Fi debe tener entre 8 y 63 caracteres.")
    if not all(32 <= ord(c) <= 126 for c in password):
        raise ValueError("La clave Wi‑Fi solo admite letras, números y símbolos comunes (sin tildes ni ñ).")


def validate_ssid(ssid: str) -> None:
    if not 1 <= len(ssid) <= 32:
        raise ValueError("El nombre de la red debe tener entre 1 y 32 caracteres.")
    if not all(32 <= ord(c) <= 126 for c in ssid):
        raise ValueError("El nombre de la red solo admite letras, números y símbolos comunes (sin tildes ni ñ).")
    if ssid != ssid.strip():
        raise ValueError("El nombre de la red no puede empezar ni terminar con espacios.")


_MAC_RE = re.compile(r"^[0-9A-Fa-f]{2}([:-]?[0-9A-Fa-f]{2}){5}$")


def normalize_mac(mac: str) -> str:
    mac = (mac or "").strip()
    if not _MAC_RE.match(mac):
        raise ValueError(f"Dirección MAC no válida: {mac!r}")
    hexs = re.sub(r"[^0-9A-Fa-f]", "", mac).upper()
    return ":".join(hexs[i:i + 2] for i in range(0, 12, 2))


# --- utilidades para páginas que incrustan JS ------------------------------

_HEX_ESCAPE = re.compile(r"\\x([0-9a-fA-F]{2})")
_QUOTED = re.compile(r'"((?:[^"\\]|\\.)*)"')


def decode_js(s: str) -> str:
    """Decodifica las cadenas \\xHH que usan Huawei y ZTE en sus páginas."""
    return _HEX_ESCAPE.sub(lambda m: chr(int(m.group(1), 16)), s)


def js_constructors(text: str, name: str) -> list[list[str]]:
    """Argumentos de cada `new <name>("a","b",...)` del texto, ya decodificados.
    Nunca se evalúa el JS del equipo."""
    out = []
    for m in re.finditer(r"new\s+" + re.escape(name) + r"\s*\(", text):
        depth, i, start = 1, m.end(), m.end()
        in_str = False
        while i < len(text) and depth:
            c = text[i]
            if in_str:
                if c == "\\":
                    i += 1
                elif c == '"':
                    in_str = False
            elif c == '"':
                in_str = True
            elif c == "(":
                depth += 1
            elif c == ")":
                depth -= 1
            i += 1
        out.append([decode_js(a) for a in _QUOTED.findall(text[start:i - 1])])
    return out


# --- interfaz ---------------------------------------------------------------

class OnuDriver(ABC):
    """Contrato de cada marca. Usa siempre las credenciales del cliente
    (las de la etiqueta del equipo)."""

    brand: str = "generic"
    default_username: str = "admin"
    # Qué sabe hacer este driver: la interfaz oculta lo que no esté.
    can_change_wifi: bool = True
    can_rename_wifi: bool = True
    can_block: bool = True

    def __init__(self, host: str, username: str, password: str, timeout: int = 15):
        self.host = host.rstrip("/") if host.startswith("http") else f"http://{host.strip().rstrip('/')}"
        self.username = username or self.default_username
        self.password = password
        self.timeout = timeout
        self.session = requests.Session()
        # Un solo socket: Huawei ata el token de login a la conexión TCP.
        adapter = requests.adapters.HTTPAdapter(pool_connections=1, pool_maxsize=1, max_retries=0)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)
        self.session.verify = False
        self.session.headers["User-Agent"] = (
            "Mozilla/5.0 (Linux; Android 13) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130 Mobile Safari/537.36")

    # --- detección
    @classmethod
    @abstractmethod
    def matches(cls, homepage_html: str, headers: dict) -> bool:
        """True si la página de inicio del equipo parece de esta marca."""

    # --- sesión
    @abstractmethod
    def login(self) -> None: ...

    def logout(self) -> None:
        pass

    def close(self) -> None:
        try:
            self.logout()
        except Exception:
            pass
        finally:
            self.session.close()

    def __enter__(self):
        self.login()
        return self

    def __exit__(self, *exc):
        self.close()

    # --- Wi-Fi
    @abstractmethod
    def get_wifi_networks(self) -> list[WifiNetwork]: ...

    @abstractmethod
    def set_wifi(self, network: WifiNetwork, ssid: str | None = None, password: str | None = None) -> None:
        """Cambia el nombre y/o la clave de una red, sin tocar el resto de su configuración."""

    # --- dispositivos
    @abstractmethod
    def get_devices(self) -> list[Device]:
        """Equipos conectados, con `blocked` marcado si ya están en la lista de bloqueo."""

    @abstractmethod
    def get_blocked(self) -> list[Device]:
        """Equipos en la lista de bloqueo (aunque no estén conectados ahora)."""

    @abstractmethod
    def block_device(self, mac: str, name: str = "") -> None: ...

    @abstractmethod
    def unblock_device(self, mac: str) -> None: ...

    # --- utilidades comunes
    def _url(self, path: str) -> str:
        return self.host + (path if path.startswith("/") else "/" + path)
