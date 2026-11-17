"""Driver ZTE con el panel web antiguo (páginas .gch): F670L/F660/F609/F677 con firmware viejo.

Se reconoce porque la página de inicio trae `Frm_Logintoken` (encabezado verde
«Please login to continue…»). El token cambia en cada petición: se lee justo antes de
enviar el formulario.

  Login     GET  /                     -> Frm_Logintoken (y Frm_Loginchecktoken si existe)
            POST /                     action=login, Username, Password, Frm_Logintoken,
                                       UserRandomNum; Password = sha256(clave+num) | md5(clave+num)
                                       | clave (según el JavaScript de la página). Éxito: cookie SID.
  Páginas   GET  /getpage.gch?pid=1002&nextpage=<pagina>.gch
            Los valores vienen como  Transfer_meaning('Campo<n>','valor');  (n = instancia)
  Cambios   POST a la misma página con el formulario de la página (IF_ACTION=apply,
            _InstID, campo cambiado, _SESSION_TOKEN). Se vuelve a leer para confirmar.

Solo se hace UN intento de inicio de sesión por vez: tras 3 fallos la ONU se bloquea.
"""
from __future__ import annotations

import hashlib
import html as _html
import random
import re
from html.parser import HTMLParser

from ..base import (AuthError, Band, CaptchaRequired, Device, NotSupportedError, OnuDriver, OnuError, WifiNetwork,
                    normalize_mac, validate_ssid, validate_wifi_password)

PAGE = "/getpage.gch?pid=1002&nextpage={}"
CODE_FIELDS = ("Validatecode", "ValidateCode", "Frm_Validatecode", "verifycode", "VerifyCode", "checkcode")
SSID_PAGES = ("net_wlanm_essid1_t.gch", "net_wlanm_essid_t.gch")
SEC_PAGES = ("net_wlanm_secrity1_t.gch", "net_wlanm_secrity_t.gch")
STATUS_PAGES = ("status_wlanm_info1_t.gch", "status_wlanm_info_t.gch")
LAN_PAGES = ("status_lan_info_t.gch", "net_dhcp_dynamic_t.gch", "pon_status_lan_info_t.gch")

_TM = re.compile(r"Transfer_meaning\s*\(\s*['\"]([A-Za-z_][\w.]*?)(\d*)['\"]\s*,\s*['\"]((?:\\.|[^'\"\\])*)['\"]")


def _unescape(v: str) -> str:
    v = re.sub(r"\\x([0-9a-fA-F]{2})", lambda m: chr(int(m.group(1), 16)), v)
    v = re.sub(r"\\(.)", r"\1", v)
    return _html.unescape(v)


def transfer_values(page: str) -> dict[int, dict[str, str]]:
    """{instancia: {campo: valor}} desde las llamadas Transfer_meaning('CampoN','valor')."""
    out: dict[int, dict[str, str]] = {}
    for name, idx, val in _TM.findall(page):
        out.setdefault(int(idx) if idx else -1, {})[name] = _unescape(val)
    return out


def _token(page: str, name: str) -> str | None:
    for pat in (rf'{name}["\']?\)\.value\s*=\s*["\']?(\w+)', rf'{name}["\']\s*,\s*["\'](\w+)["\']',
                rf'name=["\']?{name}["\']?[^>]*value=["\']?(\w+)', rf'id=["\']?{name}["\']?[^>]*value=["\']?(\w+)'):
        m = re.search(pat, page, re.I)
        if m:
            return m.group(1)
    return None


class _Forms(HTMLParser):
    def __init__(self):
        super().__init__()
        self.forms: list[dict] = []
        self._cur = None

    def handle_starttag(self, tag, attrs):
        a = {k.lower(): (v or "") for k, v in attrs}
        if tag == "form":
            self._cur = {"name": a.get("name", "") or a.get("id", ""), "inputs": []}
            self.forms.append(self._cur)
        elif tag in ("input", "select", "textarea") and a.get("name"):
            target = self._cur if self._cur is not None else (self.forms[-1] if self.forms else None)
            if target is None:
                self._cur = {"name": "", "inputs": []}
                self.forms.append(self._cur)
                target = self._cur
            target["inputs"].append(a)

    def handle_endtag(self, tag):
        if tag == "form":
            self._cur = None


def _band_for(inst: str, idx: int) -> str:
    m = re.search(r"AP(\d+)", inst or "")
    n = int(m.group(1)) if m else idx + 1
    return Band.B5 if n >= 5 else Band.B24


class ZteLegacyDriver(OnuDriver):
    brand = "ZTE"
    default_username = "admin"
    can_block = False

    def __init__(self, *a, **kw):
        super().__init__(*a, **kw)
        self.session_token = ""
        self.session.headers.update({"Referer": self.host + "/"})

    @classmethod
    def matches(cls, homepage_html: str, headers: dict) -> bool:
        h = homepage_html
        return "Frm_Logintoken" in h or ("getpage.gch" in h and "ZTE" in h.upper())

    @classmethod
    def probe(cls, session, host: str, timeout: int = 5) -> bool:
        try:
            return "Frm_Logintoken" in session.get(host + "/", timeout=timeout).text
        except Exception:
            return False

    # --- sesión -------------------------------------------------------------
    def _home(self) -> str:
        r = self.session.get(self._url("/"), timeout=self.timeout)
        r.encoding = r.apparent_encoding if "gb" in (r.headers.get("Content-Type", "").lower()) else (r.encoding or "utf-8")
        return r.text

    def login(self) -> None:
        page = self._home()
        if "Frm_Logintoken" not in page:
            if "_type=loginData" in page or "login_entry" in page:
                raise NotSupportedError("Esta ONU ZTE usa el panel nuevo: elige la marca ZTE y vuelve a intentar.")
            raise NotSupportedError("No se encontró el formulario de inicio de sesión de esta ONU ZTE.")
        if re.search(r"login failed for three times|locked|lockingTime\s*=\s*['\"]?[1-9]", page, re.I):
            raise AuthError("La ONU está bloqueada por intentos fallidos. Espera unos minutos y vuelve a intentar.")
        # Código de verificación (algunos ZTE antiguos, p. ej. F602W/F680 de ciertos ISP)
        code_field = next((f for f in CODE_FIELDS if re.search(rf"name=[\"']?{f}\b", page)), None)
        if code_field:
            from .realtek import find_captcha_image
            src = find_captcha_image(page) or "/getValidateCode.gch"
            if not self.captcha:
                url = src if src.startswith("http") else self._url(src if src.startswith("/") else "/" + src.lstrip("./"))
                r = self.session.get(url, timeout=self.timeout, headers={"Referer": self.host + "/"})
                ctype = r.headers.get("Content-Type", "").lower()
                ext = "jpg" if ("jpeg" in ctype or r.content[:3] == b"\xff\xd8\xff") else \
                    "gif" if r.content[:4] == b"GIF8" else "bmp" if r.content[:2] == b"BM" else "png"
                raise CaptchaRequired("Esta ONU pide un código de verificación para iniciar sesión.",
                                      image=r.content, ext=ext)
            page = self._home()        # token nuevo; el código sigue siendo el de la imagen mostrada
        token = _token(page, "Frm_Logintoken") or ""
        check = _token(page, "Frm_Loginchecktoken")
        low = page.lower()
        rnd = str(random.randint(10000000, 99999999))
        if "sha256" in low:
            pw, salted = hashlib.sha256((self.password + rnd).encode()).hexdigest(), True
        elif "hex_md5" in low or "md5(" in low:
            pw, salted = hashlib.md5((self.password + rnd).encode()).hexdigest(), True
        else:
            pw, salted = self.password, "userrandomnum" in low
        data = {"frashnum": "", "action": "login", "Frm_Logintoken": token, "Username": self.username,
                "Password": pw}
        if salted or "userrandomnum" in low:
            data["UserRandomNum"] = rnd
        if check is not None:
            data["Frm_Loginchecktoken"] = check
        if code_field:
            data[code_field.replace("Frm_", "") if code_field.startswith("Frm_") else code_field] = self.captcha
            if "checkValidateCode" in page:
                try:   # la página valida primero el código aparte, como hace el navegador
                    self.session.post(self._url("/checkValidateCode.gch"), data={code_field: self.captcha},
                                      timeout=self.timeout)
                except Exception:
                    pass
        r = self.session.post(self._url("/"), data=data, timeout=self.timeout,
                              headers={"Origin": self.host, "Referer": self.host + "/"})
        text = r.text
        if re.search(r"three times|tres veces|login failed for", text, re.I):
            raise AuthError("La ONU se bloqueó por intentos fallidos. Espera unos minutos y revisa la contraseña.")
        sid = self.session.cookies.get("SID")
        if code_field and (not sid or "Frm_Logintoken" in text) and not re.search(r"User information is error", text, re.I):
            self.captcha = ""
            try:
                self.login()                 # pide una imagen nueva
            except CaptchaRequired as e:
                e.wrong = True
                e.args = ("El código no es correcto. Escribe el nuevo código.",)
                raise
        if code_field:
            self.captcha_used = True
        if re.search(r"User information is error|username or password|error de usuario", text, re.I) or (
                not sid and "Frm_Logintoken" in text):
            raise AuthError("La ONU ZTE rechazó el usuario o la contraseña. Ojo: tras 3 intentos fallidos "
                            "se bloquea unos minutos. Si tienes el panel abierto en el navegador, ciérralo "
                            "(esta ONU acepta una sola sesión).")
        self.session_token = self._session_token(self._get("/template.gch", check=False))

    @staticmethod
    def _session_token(page: str) -> str:
        m = (re.search(r"session_token\s*=\s*['\"]?(\w+)", page, re.I)
             or re.search(r"_SESSION_TOKEN['\"]?\s*,\s*['\"](\w+)", page)
             or re.search(r"name=['\"]?_SESSION_TOKEN['\"]?[^>]*value=['\"]?(\w+)", page, re.I))
        return m.group(1) if m else ""

    def logout(self) -> None:
        try:
            self.session.post(self._url("/"), data={"logout": "1", "_SESSION_TOKEN": self.session_token},
                              timeout=4)
        except Exception:
            pass

    def _get(self, path: str, check: bool = True) -> str:
        r = self.session.get(self._url(path), timeout=self.timeout)
        text = r.text
        if check and ("Frm_Logintoken" in text or "SessionTimeout" in text):
            raise AuthError("La sesión con la ONU venció. Vuelve a intentar.")
        tok = self._session_token(text)
        if tok:
            self.session_token = tok
        return text

    def _page(self, names: tuple[str, ...]) -> tuple[str, str]:
        last = None
        for n in names:
            try:
                t = self._get(PAGE.format(n))
            except AuthError:
                raise
            except Exception as e:
                last = e
                continue
            if "Transfer_meaning" in t or "IF_ACTION" in t:
                return n, t
        raise NotSupportedError("Esta versión del panel ZTE no tiene la página esperada"
                                + (f" ({last.__class__.__name__})." if last else "."))

    # --- Wi‑Fi --------------------------------------------------------------
    def get_wifi_networks(self) -> list[WifiNetwork]:
        ssid_name, ssid_page = self._page(SSID_PAGES)
        vals = transfer_values(ssid_page)
        try:
            sec_name, sec_page = self._page(SEC_PAGES)
            sec = transfer_values(sec_page)
        except NotSupportedError:
            sec_name, sec = "", {}
        enabled = {}
        try:
            _, st = self._page(STATUS_PAGES)
            for i, v in transfer_values(st).items():
                if "Enable" in v:
                    enabled[i] = v["Enable"]
        except NotSupportedError:
            pass
        nets = []
        for i, v in sorted(vals.items()):
            if i < 0 or "ESSID" not in v:
                continue
            inst = v.get("_InstID") or sec.get(i, {}).get("_InstID") or f"DEV.WIFI.AP{i + 1}"
            en = v.get("Enable", enabled.get(i, "1"))
            psk = sec.get(i, {}).get("KeyPassphrase", "") or (sec.get(-1, {}).get("KeyPassphrase", "") if i == 0 else "")
            nets.append(WifiNetwork(
                id=str(i), ssid=v["ESSID"], band=_band_for(inst, i), enabled=str(en).strip() in ("1", "true"),
                extra={"psk": psk, "inst": inst, "ssid_page": ssid_name, "sec_page": sec_name}))
        if not nets:
            raise NotSupportedError("No se encontraron redes Wi‑Fi en el panel de esta ONU ZTE.")
        return nets

    def _apply(self, page_name: str, idx: int, inst: str, changes: dict[str, str]) -> None:
        """Reenvía el formulario de la página con los valores actuales y `changes`."""
        page = self._get(PAGE.format(page_name))
        vals = transfer_values(page)
        cur = {**vals.get(-1, {}), **vals.get(idx, {})}
        p = _Forms()
        p.feed(page)
        form = next((f for f in p.forms if any(i.get("name") == "IF_ACTION" for i in f["inputs"])), None)
        fields: dict[str, str] = {}
        if form is not None:
            for i in form["inputs"]:
                name = i["name"]
                typ = i.get("type", "text").lower()
                if typ in ("button", "submit", "reset", "image") or name.startswith("Frm_"):
                    continue
                if typ in ("checkbox", "radio") and "checked" not in i:
                    continue
                fields[name] = cur.get(name, i.get("value", ""))
        fields.update({"IF_ACTION": "apply", "_InstID": inst})
        if "IF_INDEX" in fields:
            fields["IF_INDEX"] = str(idx)
        fields.update(changes)
        fields["_SESSION_TOKEN"] = self.session_token or self._session_token(page)
        r = self.session.post(self._url(PAGE.format(page_name)), data=fields, timeout=self.timeout,
                              headers={"Origin": self.host, "Referer": self._url(PAGE.format(page_name))})
        if "Frm_Logintoken" in r.text:
            raise AuthError("La sesión con la ONU venció. Vuelve a intentar.")
        m = re.search(r"Transfer_meaning\s*\(\s*['\"]IF_ERRORSTR['\"]\s*,\s*['\"]([^'\"]*)", r.text)
        if m and m.group(1) not in ("", "SUCC"):
            raise OnuError(f"La ONU rechazó el cambio ({_unescape(m.group(1))}).")

    def set_wifi(self, network: WifiNetwork, ssid: str | None = None, password: str | None = None) -> None:
        idx = int(network.id)
        inst = network.extra.get("inst") or f"DEV.WIFI.AP{idx + 1}"
        if ssid is not None:
            validate_ssid(ssid)
            self._apply(network.extra.get("ssid_page") or SSID_PAGES[0], idx, inst, {"ESSID": ssid})
        if password is not None:
            validate_wifi_password(password)
            if not network.extra.get("sec_page"):
                raise NotSupportedError("Esta versión del panel ZTE no permite cambiar la clave desde la app.")
            self._apply(network.extra["sec_page"], idx, inst, {"KeyPassphrase": password})
        # Confirmar leyendo otra vez (si la ONU ya cortó el Wi‑Fi, la lectura falla y se informa como corte).
        now = {n.id: n for n in self.get_wifi_networks()}.get(network.id)
        if now is not None:
            if ssid is not None and now.ssid != ssid:
                raise OnuError("La ONU no guardó el nombre nuevo. Esta versión del panel ZTE aún no está "
                               "probada: avísanos el modelo para ajustarlo.")
            if password is not None and now.extra.get("psk") and now.extra["psk"] != password:
                raise OnuError("La ONU no guardó la clave nueva. Esta versión del panel ZTE aún no está "
                               "probada: avísanos el modelo para ajustarlo.")

    # --- equipos ------------------------------------------------------------
    def get_devices(self) -> list[Device]:
        try:
            _, page = self._page(LAN_PAGES)
        except NotSupportedError:
            return []
        devs = []
        for i, v in sorted(transfer_values(page).items()):
            mac = v.get("MACAddr") or v.get("MACAddress") or v.get("MacAddr") or ""
            ip = v.get("IPAddr") or v.get("IPAddress") or v.get("IpAddr") or ""
            if not mac or mac.startswith("00:00:00:00"):
                continue
            port = (v.get("PhyPortName") or v.get("Interface") or v.get("PortName") or "").upper()
            m = re.search(r"SSID\s*(\d+)", port)
            iface = (("5GHz" if int(m.group(1)) >= 5 else "2.4GHz") if m else
                     "Cable" if "LAN" in port or "ETH" in port else port.title())
            devs.append(Device(mac=normalize_mac(mac), ip=ip, name=v.get("HostName", ""), interface=iface))
        return devs

    def get_blocked(self) -> list[Device]:
        return []

    def block_device(self, mac: str, name: str = "") -> None:
        raise NotSupportedError("Bloquear equipos aún no está disponible en el panel antiguo de ZTE.")

    def unblock_device(self, mac: str) -> None:
        raise NotSupportedError("Bloquear equipos aún no está disponible en el panel antiguo de ZTE.")
