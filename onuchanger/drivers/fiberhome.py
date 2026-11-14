"""Driver FiberHome (HG6145F, HG6145F1, HG6145D2, HG6143D… con panel /cgi-bin/ajax).

  Login     GET  /cgi-bin/ajax?ajaxmethod=get_acs_random      -> llave AES (firmware RP4552+)
            GET  /cgi-bin/ajax?ajaxmethod=get_refresh_sessionid
            POST /cgi-bin/ajax  ajaxmethod=do_login  loginpd = AES-128-CBC(clave), hex en mayúsculas
                 llave = IV = acsRandom[6:22]  (firmwares antiguos: "opqrstuvwxyz{|}~")
  Equipos   GET  ajaxmethod=get_lan_status                     (IP con "_point_" en vez de ".")
  Bloqueo   GET  ajaxmethod=get_ipv4_mac_filter_info
            POST ajaxmethod=set_ipv4_mac_filter_info  action=add|delete|enable
  Cada POST pide antes un sessionid nuevo y lleva todos los campos en el cuerpo.

Cambiar el nombre/clave del Wi‑Fi: los métodos de esa página no están
documentados en ninguna fuente pública. Para no enviar peticiones adivinadas
a equipos de clientes, el driver lo marca como no soportado hasta tener una
captura real (ver README).
"""
from __future__ import annotations

import json
import random

from ..base import (AuthError, Device, NotSupportedError, OnuDriver, OnuError, WifiNetwork,
                    normalize_mac)

LEGACY_KEY = b"opqrstuvwxyz{|}~"


def fh_encrypt(password: str, key: bytes = LEGACY_KEY) -> str:
    from Crypto.Cipher import AES
    data = password.encode()
    pad = 16 - len(data) % 16
    data += bytes([pad]) * pad
    return AES.new(key, AES.MODE_CBC, key).encrypt(data).hex().upper()


def _json(text: str) -> dict:
    start = text.find("{")
    if start < 0:
        return {}
    try:
        return json.loads(text[start:])
    except ValueError:
        return {}


def _find_list(obj, key: str):
    """Busca la primera lista llamada `key` en cualquier nivel del JSON."""
    if isinstance(obj, dict):
        if isinstance(obj.get(key), list):
            return obj[key]
        for v in obj.values():
            found = _find_list(v, key)
            if found is not None:
                return found
    return None


class FiberhomeDriver(OnuDriver):
    brand = "FiberHome"
    default_username = "user"
    can_change_wifi = False

    def __init__(self, *a, **kw):
        super().__init__(*a, **kw)
        self.session.headers.update({"X-Requested-With": "XMLHttpRequest"})

    @classmethod
    def matches(cls, homepage_html: str, headers: dict) -> bool:
        h = homepage_html.lower()
        return "cgi-bin/ajax" in h or "fiberhome" in h or "login_inter" in h or "fhencrypt" in h

    @classmethod
    def probe(cls, session, host: str, timeout: int = 5) -> bool:
        try:
            r = session.get(f"{host}/cgi-bin/ajax?ajaxmethod=get_refresh_sessionid&_={random.random()}",
                            timeout=timeout)
            return "sessionid" in _json(r.text)
        except Exception:
            return False

    # --- transporte ---------------------------------------------------------
    def _get(self, method: str) -> dict:
        r = self.session.get(self._url(f"/cgi-bin/ajax?ajaxmethod={method}&_={random.random()}"),
                             timeout=self.timeout, headers={"Referer": self._url("/")})
        if r.status_code in (403, 404):
            raise NotSupportedError(f"Esta ONU FiberHome no tiene el método {method}.")
        data = _json(r.text)
        if str(data.get("session_valid", "1")) == "0" and method not in ("get_refresh_sessionid", "get_acs_random"):
            raise AuthError("La sesión con la ONU expiró. Vuelve a pulsar Conectar.")
        return data

    def _sessionid(self) -> str:
        sid = self._get("get_refresh_sessionid").get("sessionid", "")
        if not sid:
            raise NotSupportedError("La ONU FiberHome no entregó un identificador de sesión.")
        return sid

    def _post(self, method: str, fields: dict) -> dict:
        data = {"ajaxmethod": method, "sessionid": self._sessionid(), "_": str(random.random())}
        data.update(fields)
        r = self.session.post(self._url("/cgi-bin/ajax"), data=data, timeout=self.timeout,
                              headers={"Referer": self._url("/"), "Origin": self.host})
        if r.status_code >= 400:
            raise OnuError(f"La ONU rechazó el cambio (HTTP {r.status_code}).")
        res = _json(r.text)
        if str(res.get("session_valid", "1")) == "0":
            raise AuthError("La sesión con la ONU expiró. Vuelve a pulsar Conectar.")
        return res

    # --- sesión -------------------------------------------------------------
    def login(self) -> None:
        self.session.get(self._url("/"), timeout=self.timeout)
        key = LEGACY_KEY
        try:
            acs = str(self._get("get_acs_random").get("acsRandom", ""))
            if len(acs) >= 22:
                key = acs[6:22].encode()
        except (NotSupportedError, OnuError):
            pass
        res = self._post("do_login", {"username": self.username, "loginpd": fh_encrypt(self.password, key),
                                      "port": "0"})
        result = str(res.get("login_result", ""))
        if result == "0":
            return
        if result == "2":
            raise AuthError("La ONU FiberHome bloqueó el acceso por intentos fallidos. Espera 1 minuto.")
        if result in ("1", "3"):
            raise AuthError("La ONU FiberHome rechazó el usuario o la contraseña.")
        if result == "4":
            raise AuthError("Otra persona tiene abierta la configuración de la ONU. Ciérrala e intenta de nuevo.")
        raise AuthError(f"La ONU FiberHome no aceptó el inicio de sesión (código {result or 'desconocido'}).")

    def logout(self) -> None:
        self._post("do_logout", {})

    # --- Wi-Fi --------------------------------------------------------------
    def get_wifi_networks(self) -> list[WifiNetwork]:
        raise NotSupportedError("Cambiar el Wi‑Fi en FiberHome todavía no está disponible en la app.")

    def set_wifi(self, network: WifiNetwork, ssid: str | None = None, password: str | None = None) -> None:
        raise NotSupportedError("Cambiar el Wi‑Fi en FiberHome todavía no está disponible en la app.")

    # --- dispositivos -------------------------------------------------------
    def get_devices(self) -> list[Device]:
        blocked = {d.mac for d in self.get_blocked()}
        rows = _find_list(self._get("get_lan_status"), "dhcp_user_list") or []
        devices: dict[str, Device] = {}
        for row in rows:
            try:
                mac = normalize_mac(str(row.get("MACAddress", "")))
            except ValueError:
                continue
            access = str(row.get("AccessType") or row.get("InterfaceType") or "")
            iface = {"2.4G": "2.4GHz", "5G": "5GHz"}.get(access, "Cable" if "ether" in access.lower() else access)
            name = str(row.get("HostName") or "")
            devices[mac] = Device(mac=mac, name="" if name.lower() == "unknown" else name,
                                  ip=str(row.get("IPAddress", "")).replace("_point_", "."), interface=iface,
                                  online=str(row.get("Active", "1")) == "1", blocked=mac in blocked)
        return sorted((d for d in devices.values() if d.online or d.blocked),
                      key=lambda d: (not d.online, d.name.lower()))

    def _filter(self) -> tuple[bool, str, list[tuple[str, str]]]:
        data = self._get("get_ipv4_mac_filter_info")
        info = data.get("ipv4_mac_filter_info", data)
        entries = []
        for e in info.get("mac_filter_data", []) or []:
            try:
                entries.append((str(e.get("ipv4_mac_filter_index", "")), normalize_mac(str(e.get("MAC", "")))))
            except ValueError:
                continue
        return str(info.get("MACFEnable", "0")) == "1", str(info.get("MACFMode", "black")).lower(), entries

    def get_blocked(self) -> list[Device]:
        try:
            enabled, mode, entries = self._filter()
        except NotSupportedError:
            return []
        if mode != "black":
            return []
        return [Device(mac=m, online=False, blocked=True) for m in dict.fromkeys(e[1] for e in entries)]

    def block_device(self, mac: str, name: str = "") -> None:
        mac = normalize_mac(mac)
        enabled, mode, entries = self._filter()
        if mode == "white" and (enabled or entries):
            raise NotSupportedError("El filtro MAC de esta ONU está en modo lista blanca (solo permite los "
                                    "equipos de la lista). Bloquear desde aquí haría lo contrario; no se cambió nada.")
        if mac not in {e[1] for e in entries}:
            self._post("set_ipv4_mac_filter_info", {"action": "add", "MAC": mac, "TimeStart": "00:00",
                                                    "TimeStop": "23:59", "Enable": "1"})
        if not enabled or mode != "black":
            self._post("set_ipv4_mac_filter_info", {"action": "enable", "ipv4_mac_filter_enable": "1",
                                                    "ipv4_mac_filter_mode": "black"})
        if mac not in {d.mac for d in self.get_blocked()}:
            raise OnuError("La ONU aceptó la petición pero el equipo no aparece en la lista de bloqueo.")

    def unblock_device(self, mac: str) -> None:
        mac = normalize_mac(mac)
        for _ in range(8):   # los índices pueden cambiar tras cada borrado
            _, _, entries = self._filter()
            idx = next((i for i, m in entries if m == mac), None)
            if idx is None:
                return
            self._post("set_ipv4_mac_filter_info", {"action": "delete", "ipv4_mac_filter_index": idx})
        raise OnuError("No se pudieron borrar todas las reglas de bloqueo de este equipo.")
