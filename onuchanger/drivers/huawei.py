"""Driver Huawei EchoLife / OptiXstar (HG8145V5, EG8145V5, HG8145X6, HG8546M, HG8245H…).

El panel web no tiene API REST: cada página .asp incrusta su estado como
constructores JS (`new stWlan("…")`) y los cambios se envían como formularios a
set.cgi / add.cgi / del.cgi. Flujo reproducido de su propio JavaScript y de
proyectos que lo verificaron en equipos reales:

  Login       GET /  ->  POST /asp/GetRandCount.asp (token)  ->  POST /login.cgi
              UserName / base64(PassWord) / Language / x.X_HW_Token
  Wi-Fi       GET  /html/amp/wlanbasic/WlanBasic.asp?2G|5G     (stWlan, hwonttoken)
              POST /html/amp/wlanbasic/set.cgi?x=<WLANConfiguration.N>&k=<…PreSharedKey.1>
  Equipos     POST /html/bbsp/common/GetLanUserDevInfo.asp     (USERDevice)
  Bloqueo     /html/bbsp/wlanmacfilter/wlanmacfilter.asp + add.cgi / del.cgi / set.cgi
              (filtro MAC de Wi‑Fi: el equipo bloqueado no puede asociarse)

Detalles que el firmware exige: el token de login va en la misma conexión TCP
(el driver usa un solo socket), x.X_HW_Token va al final del formulario y
RequestFile se envía con "/" literal (sin %2F).
"""
from __future__ import annotations

import base64
import re
from urllib.parse import quote

from ..base import (AuthError, Band, Device, NotSupportedError, OnuDriver, OnuError, WifiNetwork,
                    js_constructors, normalize_mac, validate_ssid, validate_wifi_password)

WLAN_PAGES = ("/html/amp/wlanbasic/WlanBasic.asp?2G", "/html/amp/wlanbasic/WlanBasic.asp?5G")
WLAN_BBSP_PAGE = "/html/bbsp/wlanbasic/wlanbasic.asp"
MACF_PAGE = "/html/bbsp/wlanmacfilter/wlanmacfilter.asp"
MACF_DOMAIN = "InternetGatewayDevice.X_HW_Security.WLANMacFilter"

_TOKEN_RE = re.compile(r'id="?(?:hwonttoken|onttoken)"?\s+value="([^"]+)"', re.I)
_INSTANCE_RE = re.compile(r"WLANConfiguration\.(\d+)$")


def _enc(v: str) -> str:
    return quote(str(v), safe="-_.!~*'()")


class HuaweiDriver(OnuDriver):
    brand = "Huawei"
    default_username = "Epuser"

    @classmethod
    def matches(cls, homepage_html: str, headers: dict) -> bool:
        h = homepage_html.lower()
        return any(k in h for k in ("getrandcount", "x_hw_token", "hwonttoken", "echolife", "optixstar")) or (
            "login.cgi" in h and "huawei" in h)

    # --- sesión -------------------------------------------------------------
    def login(self) -> None:
        s = self.session
        s.cookies.set("Cookie", "body:Language:english:id=-1", path="/")
        s.get(self._url("/"), timeout=self.timeout)
        r = s.post(self._url("/asp/GetRandCount.asp"), timeout=self.timeout)
        # Viene con BOM UTF‑8 y sin charset: leer los bytes, no r.text (que lo trataría como latin‑1).
        m = re.search(r"[0-9A-Za-z]{8,128}", r.content.decode("utf-8-sig", "ignore"))
        if r.status_code != 200 or not m:
            raise NotSupportedError("Esta ONU Huawei no entregó el token de inicio de sesión (firmware no compatible).")
        token = m.group(0)
        body = "&".join([
            "UserName=" + _enc(self.username),
            "PassWord=" + _enc(base64.b64encode(self.password.encode()).decode()),
            "Language=english",
            "x.X_HW_Token=" + token,
        ])
        r = s.post(self._url("/login.cgi"), data=body, timeout=self.timeout,
                   headers={"Content-Type": "application/x-www-form-urlencoded", "Referer": self._url("/")})
        if self._is_login_page(r.text):
            raise AuthError("La ONU Huawei rechazó el usuario o la contraseña. Tras 3 intentos fallidos se "
                            "bloquea alrededor de 1 minuto.")
        if "Cookie" in r.cookies:   # la ONU entregó la cookie de sesión: quitar la de idioma inicial
            try:
                s.cookies.clear(domain="", path="/", name="Cookie")
            except KeyError:
                pass
        # Confirmar que la sesión quedó abierta.
        self._get("/index.asp")

    def logout(self) -> None:
        token = self._token_from(self.session.get(self._url("/index.asp"), timeout=self.timeout).text)
        data = "x.X_HW_Token=" + token if token else ""
        self.session.post(self._url("/logout.cgi?RequestFile=html/logout.html"), data=data, timeout=self.timeout,
                          headers={"Content-Type": "application/x-www-form-urlencoded"})

    @staticmethod
    def _is_login_page(html: str) -> bool:
        h = html.lower()
        return ("txt_password" in h or "txt_username" in h
                or re.search(r"var\s+pagename\s*=\s*'/'\s*;\s*top\.location\.replace", h) is not None)

    def _get(self, path: str, method: str = "GET") -> str:
        r = self.session.request(method, self._url(path), timeout=self.timeout,
                                 headers={"Referer": self._url("/index.asp")})
        if r.status_code == 404:
            raise FileNotFoundError(path)
        if self._is_login_page(r.text):
            raise AuthError("La sesión con la ONU expiró. Vuelve a pulsar Conectar.")
        r.encoding = r.encoding or "utf-8"
        return r.text

    @staticmethod
    def _token_from(html: str) -> str:
        m = _TOKEN_RE.search(html)
        return m.group(1) if m else ""

    def _token(self, page: str) -> str:
        token = self._token_from(self._get(page))
        if not token:
            raise NotSupportedError("No se encontró el token de seguridad en la página de la ONU.")
        return token

    def _post_form(self, path: str, fields: list[tuple[str, str]], referer: str) -> str:
        """Formulario en el orden exacto del panel (el token siempre al final)."""
        body = "&".join(f"{k}={_enc(v)}" for k, v in fields)
        r = self.session.post(self._url(path), data=body, timeout=self.timeout,
                              headers={"Content-Type": "application/x-www-form-urlencoded",
                                       "Referer": self._url(referer), "Origin": self.host})
        if r.status_code == 404:
            raise FileNotFoundError(path)
        if r.status_code != 200:
            raise OnuError(f"La ONU respondió HTTP {r.status_code} al guardar.")
        if self._is_login_page(r.text):
            raise AuthError("La sesión con la ONU expiró. Vuelve a pulsar Conectar.")
        return r.text

    # --- Wi-Fi --------------------------------------------------------------
    def get_wifi_networks(self) -> list[WifiNetwork]:
        nets: dict[int, WifiNetwork] = {}
        mode = "amp"
        for page in WLAN_PAGES:
            try:
                html = self._get(page)
            except FileNotFoundError:
                continue
            self._parse_wlans(html, nets, page)
        if not nets:
            mode = "bbsp"
            try:
                self._parse_wlans(self._get(WLAN_BBSP_PAGE), nets, WLAN_BBSP_PAGE)
            except FileNotFoundError:
                pass
        if not nets:
            raise NotSupportedError("No se encontró la configuración Wi‑Fi en esta ONU Huawei.")
        for n in nets.values():
            n.extra["mode"] = mode
        return [nets[k] for k in sorted(nets)]

    @staticmethod
    def _parse_wlans(html: str, nets: dict, page: str) -> None:
        rows = [(a, True) for a in js_constructors(html, "stWlan")]
        rows += [(a, False) for a in js_constructors(html, "stWlanWifi")]
        for args, has_enable in rows:
            if len(args) < 4:
                continue
            m = _INSTANCE_RE.search(args[0])
            if not m or not args[3]:
                continue
            inst = int(m.group(1))
            if inst in nets and not has_enable:
                continue
            nets[inst] = WifiNetwork(
                id=args[0], band=Band.B24 if inst <= 4 else Band.B5, ssid=args[3],
                enabled=(args[2] == "1") if has_enable else True,
                extra={"instance": inst, "page": page})

    def set_wifi(self, network: WifiNetwork, ssid: str | None = None, password: str | None = None) -> None:
        if ssid is None and password is None:
            return
        if ssid is not None:
            validate_ssid(ssid)
        if password is not None:
            validate_wifi_password(password)
        dom = network.id
        if network.extra.get("mode") == "bbsp":
            base, request_file, page = "/html/bbsp/wlanbasic/set.cgi", "html/bbsp/wlanbasic/wlanbasic.asp", WLAN_BBSP_PAGE
        else:
            page = WLAN_PAGES[0] if network.band == Band.B24 else WLAN_PAGES[1]
            base, request_file = "/html/amp/wlanbasic/set.cgi", "html/amp/wlanbasic/WlanBasic.asp"
        query = f"?x={dom}" + (f"&k={dom}.PreSharedKey.1" if password is not None else "")
        fields = []
        if ssid is not None:
            fields.append(("x.SSID", ssid))
        if password is not None:
            fields.append(("k.PreSharedKey", password))
        fields.append(("x.X_HW_Token", self._token(page)))
        self._post_form(base + query + "&RequestFile=" + request_file, fields, page)

        if ssid is not None:  # comprobar que el cambio quedó guardado
            now = {n.id: n for n in self.get_wifi_networks()}
            if dom in now and now[dom].ssid != ssid:
                raise OnuError("La ONU aceptó la petición pero el nombre de la red no cambió.")

    # --- dispositivos -------------------------------------------------------
    def get_devices(self) -> list[Device]:
        blocked = {d.mac for d in self.get_blocked()}
        devices: dict[str, Device] = {}
        try:
            for a in js_constructors(self._get("/html/bbsp/common/GetLanUserDevInfo.asp", "POST"), "USERDevice"):
                # domain, ip, mac, port, source, type, status, porttype, time, hostname, …
                if len(a) < 10:
                    continue
                self._add_device(devices, a[2], a[9], a[1], a[3], a[6])
        except FileNotFoundError:
            pass
        if not devices:
            try:
                html = self._get("/html/bbsp/userdevinfo/getuserdevinfo.asp", "POST")
                for a in js_constructors(html, "stUserDevInfoPTVDF"):
                    # name, type, ip, mac, mac2, status, interface, …
                    if len(a) >= 7:
                        self._add_device(devices, a[3], a[0], a[2], a[6], a[5])
            except FileNotFoundError:
                pass
        for d in devices.values():
            d.blocked = d.mac in blocked
        return sorted((d for d in devices.values() if d.online or d.blocked),
                      key=lambda d: (not d.online, d.name.lower()))

    @staticmethod
    def _add_device(devices: dict, mac: str, name: str, ip: str, port: str, status: str) -> None:
        try:
            mac = normalize_mac(mac)
        except ValueError:
            return
        online = "online" in status.lower()
        p = port.upper()
        if p.startswith("SSID"):
            n = int(re.sub(r"\D", "", p) or 1)
            iface = Band.B24 if n <= 4 else Band.B5
        elif p.startswith("LAN") or p.startswith("ETH"):
            iface = "Cable"
        else:
            iface = port
        name = "" if name in ("--", "") else name
        prev = devices.get(mac)
        if prev is None or (online and not prev.online):
            devices[mac] = Device(mac=mac, name=name or (prev.name if prev else ""), ip=ip if ip != "--" else "",
                                  interface=iface, online=online)

    def _macfilter(self) -> tuple[bool, str, list[tuple[str, str, str]], str]:
        html = self._get(MACF_PAGE)
        enabled = re.search(r"var\s+enableFilter\s*=\s*'(\d)'", html)
        mode = re.search(r"var\s+Mode\s*=\s*'(\d)'", html)
        entries = []
        for a in js_constructors(html, "stMacFilter"):
            if len(a) >= 3 and a[0]:
                try:
                    entries.append((a[0], a[1], normalize_mac(a[2])))
                except ValueError:
                    continue
        return (bool(enabled and enabled.group(1) == "1"), mode.group(1) if mode else "0",
                entries, self._token_from(html))

    def get_blocked(self) -> list[Device]:
        try:
            enabled, mode, entries, _ = self._macfilter()
        except FileNotFoundError:
            return []
        if mode != "0":   # lista blanca: sus entradas son equipos permitidos, no bloqueados
            return []
        return [Device(mac=m, online=False, blocked=True) for m in dict.fromkeys(e[2] for e in entries)]

    def block_device(self, mac: str, name: str = "") -> None:
        mac = normalize_mac(mac)
        try:
            enabled, mode, entries, _ = self._macfilter()
        except FileNotFoundError as e:
            raise NotSupportedError("Esta ONU Huawei no tiene filtro MAC de Wi‑Fi.") from e
        if mode == "1" and (enabled or entries):
            raise NotSupportedError("El filtro Wi‑Fi de esta ONU está en modo lista blanca (solo permite los "
                                    "equipos de la lista). Bloquear desde aquí haría lo contrario; no se cambió nada.")
        ssids = [f"SSID-{n.extra['instance']}" for n in self.get_wifi_networks() if n.enabled]
        have = {(e[1], e[2]) for e in entries}
        for ssid_name in ssids or ["SSID-1"]:
            if (ssid_name, mac) in have:
                continue
            fields = [("x.SourceMACAddress", mac), ("x.SSIDName", ssid_name), ("x.Enable", "1"),
                      ("x.X_HW_Token", self._token(MACF_PAGE))]
            self._post_form(f"/html/bbsp/wlanmacfilter/add.cgi?x={MACF_DOMAIN}"
                            f"&RequestFile=html/bbsp/wlanmacfilter/wlanmacfilter.asp", fields, MACF_PAGE)
        if not enabled or mode != "0":
            fields = [("x.WlanMacFilterRight", "1"), ("x.WlanMacFilterPolicy", "0"),
                      ("x.X_HW_Token", self._token(MACF_PAGE))]
            self._post_form("/html/bbsp/wlanmacfilter/set.cgi?x=InternetGatewayDevice.X_HW_Security"
                            "&RequestFile=html/bbsp/wlanmacfilter/wlanmacfilter.asp", fields, MACF_PAGE)
        if mac not in {d.mac for d in self.get_blocked()}:
            raise OnuError("La ONU aceptó la petición pero el equipo no aparece en la lista de bloqueo.")

    def unblock_device(self, mac: str) -> None:
        mac = normalize_mac(mac)
        _, _, entries, token = self._macfilter()
        domains = [e[0] for e in entries if e[2] == mac]
        if not domains:
            return
        fields = [(d, "") for d in domains] + [("x.X_HW_Token", token)]
        self._post_form(f"/html/bbsp/wlanmacfilter/del.cgi?x={MACF_DOMAIN}"
                        f"&RequestFile=html/bbsp/wlanmacfilter/wlanmacfilter.asp", fields, MACF_PAGE)
        if mac in {d.mac for d in self.get_blocked()}:
            raise OnuError("La ONU aceptó la petición pero el equipo sigue en la lista de bloqueo.")
