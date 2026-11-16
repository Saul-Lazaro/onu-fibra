"""Driver para ONUs con SoC Realtek y panel "boa" (V‑SOL, OptiTimes y otras
marcas blancas: RTL9601D/9602C/9607C).

El panel es HTML renderizado en el equipo (`/admin/*.asp`) y formularios que
van a `/boaform/admin/<handler>`. Cada fabricante personaliza el HTML (nombres
de campos del login, csrftoken, código de verificación…), así que el driver
lee el formulario REAL que entrega el equipo y lo reenvía cambiando solo lo
necesario, como haría el navegador.

  Login     form action=…/formLogin(_en): username/psd (o username1/psd1),
            verification_code (= #check_code de la misma página), csrftoken
  Banda     GET /boaform/admin/formWlanRedirect?redirect-url=<página>&wlan_idx=N
  Clave     /admin/wlwpa.asp  ->  POST formWlEncrypt   (estado actual en _encrypt[k],
            _wpa2uCipher[k]…; se reenvía igual y solo cambia pskValue)
  Clientes  GET /boaform/admin/formWirelessTbl?submit-url=/admin/wlstatbl.asp&wlan_idx=N
  Bloqueo   /admin/wlactrl.asp -> POST formWlAc  (wlanAcEnabled 0=off 1=permitir 2=denegar;
            addFilterMac / deleteSelFilterMac + selectN=ON)

Cambiar el NOMBRE de la red (formWlanSetup) no se hace: ese formulario lleva
banda, canal, WMM, SSID oculto… que arma el JavaScript de la página y, si se
reenvían mal, el equipo los cambia. Queda pendiente de una captura real.
"""
from __future__ import annotations

import base64
import hashlib
import re
from html.parser import HTMLParser
from urllib.parse import quote

from ..base import (AuthError, Band, CaptchaRequired, Device, NotSupportedError, OnuDriver, OnuError, WifiNetwork,
                    normalize_mac, validate_wifi_password)

SEC_NONE, SEC_WEP, SEC_WPA, SEC_WPA2, SEC_WPA_MIXED = 0, 1, 2, 4, 6
CIPHER_TKIP, CIPHER_AES = 1, 2
AUTH_PSK = 2
AC_OFF, AC_ALLOW, AC_DENY = 0, 1, 2
LOGIN_PAGES = ("/", "/admin/login.asp", "/admin/login_en.asp")
# Campo donde se escribe el código de verificación y la imagen que lo muestra.
CAPTCHA_FIELD = re.compile(r"verif|captcha|vcode|checkcode|check_code|validat|randcode|yzm|safecode|"
                           r"securecode|^code$|imgcode|authcode", re.I)
CAPTCHA_IMG = re.compile(r"captcha|vcode|verif|checkcode|check_code|validat|randcode|getimg|imgcode|"
                         r"authcode|securi|code\.(?:jpg|jpeg|png|gif|bmp)|code\.cgi|code\.asp", re.I)


class _ImgParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.imgs = []

    def handle_starttag(self, tag, attrs):
        if tag == "img":
            self.imgs.append({k.lower(): (v or "") for k, v in attrs})


def find_captcha_image(html: str) -> str | None:
    """src de la imagen del código de verificación, si la página tiene una."""
    p = _ImgParser()
    p.feed(html)
    for img in p.imgs:
        if any(CAPTCHA_IMG.search(img.get(k, "")) for k in ("src", "id", "name", "class", "alt", "onclick")):
            if img.get("src"):
                return img["src"]
    # Imagen que se carga por JavaScript: getElementById("imgcode").src = "/getcode.cgi?" + Math.random()
    m = re.search(r"\.src\s*=\s*[\"']([^\"']*(?:captcha|vcode|verif|checkcode|code)[^\"']*)[\"']", html, re.I)
    return m.group(1) if m else None


# --- lector de formularios HTML -------------------------------------------

class _Forms(HTMLParser):
    """Formularios de la página: acción, inputs (con tipo/valor/checked) y selects."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.forms: list[dict] = []
        self.ids: dict[str, dict] = {}
        self._form = None
        self._select = None
        self._option = None

    def handle_starttag(self, tag, attrs):
        a = {k.lower(): (v if v is not None else "") for k, v in attrs}
        if "id" in a:
            self.ids[a["id"]] = a
        if tag == "form":
            self._form = {"action": a.get("action", ""), "name": a.get("name", ""), "inputs": [], "selects": {}}
            self.forms.append(self._form)
        elif tag == "input" and self._form is not None:
            self._form["inputs"].append(a)
        elif tag == "select" and self._form is not None:
            self._select = {"options": [], "name": a.get("name", "")}
            self._form["selects"][self._select["name"]] = self._select
        elif tag == "option" and self._select is not None:
            self._option = {"value": a.get("value"), "selected": "selected" in a, "text": ""}
            self._select["options"].append(self._option)

    def handle_data(self, data):
        if self._option is not None:
            self._option["text"] += data

    def handle_endtag(self, tag):
        if tag == "form":
            self._form = None
        elif tag == "select":
            self._select = None
        elif tag == "option":
            self._option = None


def parse_forms(html: str) -> _Forms:
    p = _Forms()
    p.feed(html)
    for f in p.forms:
        for s in f["selects"].values():
            for o in s["options"]:
                o["text"] = o["text"].strip()
                if o["value"] is None:
                    o["value"] = o["text"]
    return p


def find_form(forms: _Forms, action_part: str) -> dict | None:
    return next((f for f in forms.forms if action_part.lower() in f["action"].lower()), None)


def hidden_fields(form: dict) -> list[tuple[str, str]]:
    return [(i["name"], i.get("value", "")) for i in form["inputs"]
            if i.get("type", "text").lower() == "hidden" and i.get("name")]


def js_array(html: str, name: str) -> dict[int, str]:
    """Valores de `name[k]=valor;` que el equipo escribe en la página."""
    out = {}
    for m in re.finditer(re.escape(name) + r"\[(\d+)\]\s*=\s*('(?:[^'\\]|\\.)*'|\"(?:[^\"\\]|\\.)*\"|[^;\n]+)\s*;",
                         html):
        v = m.group(2).strip()
        if v[:1] in "'\"":
            v = v[1:-1]
        out[int(m.group(1))] = v
    return out


def _enc(v) -> str:
    return quote(str(v), safe="-_.!~*'()")


class RealtekDriver(OnuDriver):
    brand = "V‑SOL / OptiTimes"
    default_username = "admin"
    can_rename_wifi = False

    def __init__(self, *a, **kw):
        super().__init__(*a, **kw)
        self.prefix = "/boaform/admin"
        self.bands: dict[int, str] = {}   # wlan_idx -> banda

    @classmethod
    def matches(cls, homepage_html: str, headers: dict) -> bool:
        h = homepage_html.lower()
        return "boaform" in h or "formlogin" in h or "boa/" in str(headers.get("Server", "")).lower()

    # --- transporte ---------------------------------------------------------
    @staticmethod
    def _is_login(html: str) -> bool:
        return re.search(r"action\s*=\s*[\"']?[^\"'>\s]*formLogin", html, re.I) is not None

    def _get(self, path: str) -> str:
        r = self.session.get(self._url(path), timeout=self.timeout, headers={"Referer": self._url("/")})
        if r.status_code == 404:
            raise FileNotFoundError(path)
        text = r.text
        if self._is_login(text):
            raise AuthError("La sesión con la ONU expiró. Vuelve a pulsar Conectar.")
        return text

    def _page(self, page: str, wlan_idx: int | None = None) -> str:
        """Abre una página para una banda (el equipo guarda la banda elegida en su sesión)."""
        if wlan_idx is None:
            return self._get(page)
        return self._get(f"{self.prefix}/formWlanRedirect?redirect-url={page}&wlan_idx={wlan_idx}")

    def _post(self, handler: str, fields: list[tuple[str, str]], referer: str) -> str:
        body = "&".join(f"{k}={_enc(v)}" for k, v in fields)
        r = self.session.post(self._url(f"{self.prefix}/{handler}"), data=body, timeout=60,
                              headers={"Content-Type": "application/x-www-form-urlencoded",
                                       "Referer": self._url(referer), "Origin": self.host})
        if r.status_code >= 400:
            raise OnuError(f"La ONU rechazó el cambio (HTTP {r.status_code}).")
        text = r.text
        if self._is_login(text):
            raise AuthError("La sesión con la ONU expiró. Vuelve a pulsar Conectar.")
        # La página de error de boa es corta y empieza con "ERROR"/"Error!"; además
        # cada operación se comprueba releyendo el equipo.
        m = re.search(r"\b(?:ERROR|Error!)[^<]{0,160}", text)
        if m and len(text) < 4000:
            raise OnuError("La ONU no aplicó el cambio: " + re.sub(r"\s+", " ", m.group(0)).strip())
        return text

    # --- sesión -------------------------------------------------------------
    def _login_page(self) -> tuple[str, str]:
        for p in LOGIN_PAGES:
            try:
                r = self.session.get(self._url(p), timeout=self.timeout)
            except Exception:
                if p == "/":
                    raise
                continue
            if self._is_login(r.text):
                return r.text, r.url
        raise NotSupportedError("No se encontró el formulario de inicio de sesión de esta ONU.")

    def _captcha_error(self, html: str, page: str, wrong: bool) -> CaptchaRequired:
        """Descarga la imagen del código (con la misma sesión) y arma el aviso para la app."""
        src = find_captcha_image(html)
        image, ext = b"", "png"
        if src:
            url = src if src.startswith("http") else self._url(src if src.startswith("/") else
                                                                "/" + src.lstrip("./"))
            r = self.session.get(url, timeout=self.timeout, headers={"Referer": page})
            image = r.content
            ctype = r.headers.get("Content-Type", "").lower()
            ext = ("jpg" if "jpeg" in ctype or "jpg" in ctype else "gif" if "gif" in ctype else
                   "bmp" if "bmp" in ctype else "png")
            if image[:3] == b"\xff\xd8\xff":
                ext = "jpg"
            elif image[:4] == b"GIF8":
                ext = "gif"
            elif image[:2] == b"BM":
                ext = "bmp"
        self._login_ctx = (html, page)          # el código vale para ESTA página/sesión
        msg = ("El código no es correcto (o la contraseña). Escribe el nuevo código." if wrong else
               "Esta ONU pide un código de verificación para iniciar sesión.")
        return CaptchaRequired(msg, image=image, ext=ext, wrong=wrong)

    def login(self) -> None:
        ctx = getattr(self, "_login_ctx", None)
        if ctx and self.captcha:
            html, page = ctx                     # misma página en la que se mostró el código
        else:
            html, page = self._login_page()
        self._login_ctx = None
        forms = parse_forms(html)
        form = find_form(forms, "formLogin")
        action = form["action"]
        if not action.startswith("/"):
            action = "/" + action.lstrip("./")
        if "/boaform/" in action:
            self.prefix = action[:action.rfind("/")]
        low = html.lower()
        if "v-sol" in low or "vsol" in low:
            self.brand = "V‑SOL"
        elif "optictimes" in low or "optitimes" in low:
            self.brand = "OptiTimes"
        pw = self._encode_password(html)
        # ¿Código de verificación? Si la página ya trae el valor (#check_code oculto) se
        # completa solo; si es una imagen, lo escribe el cliente.
        auto_code = (forms.ids.get("check_code") or {}).get("value", "")
        has_img = find_captcha_image(html) is not None
        fields, needs_code = [], False
        for i in form["inputs"]:
            name = i.get("name")
            typ = i.get("type", "text").lower()
            if not name or typ in ("button", "submit", "reset", "image"):
                continue
            if typ in ("checkbox", "radio") and "checked" not in i:
                continue
            value = i.get("value", "")
            if name in ("username", "username1", "user", "Username"):
                value = self.username
            elif name in ("psd", "psd1", "password", "Password"):
                value = pw
            elif name == "sec_lang":
                value = "0"
            elif typ != "hidden" and CAPTCHA_FIELD.search(name):
                if auto_code and not has_img:
                    value = auto_code
                elif has_img:
                    needs_code = True
                    if not self.captcha:
                        raise self._captcha_error(html, page, wrong=False)
                    value = self.captcha
                else:
                    value = (forms.ids.get("check_code") or {}).get("value", value)
            fields.append((name, value))
        for name, opts in form["selects"].items():
            sel = next((o for o in opts["options"] if o["selected"]), opts["options"][0] if opts["options"] else None)
            if name and sel:
                fields.append((name, sel["value"]))
        body = "&".join(f"{k}={_enc(v)}" for k, v in fields)
        r = self.session.post(self._url(action), data=body,
                              timeout=self.timeout, headers={"Content-Type": "application/x-www-form-urlencoded",
                                                             "Referer": page, "Origin": self.host})
        text = r.text
        failed = self._is_login(text) or re.search(r"(bad|wrong|incorrect|error).{0,40}(password|user)", text, re.I)
        code_bad = needs_code and re.search(r"(verif|captcha|check.?code|validat|驗證|验证|código)", text, re.I) \
            and len(text) < 4000
        if needs_code and (failed or code_bad):
            self.captcha = ""
            fresh = text if (self._is_login(text) and find_captcha_image(text)) else None
            if fresh:
                raise self._captcha_error(text, r.url, wrong=True)
            html2, page2 = self._login_page()
            raise self._captcha_error(html2, page2, wrong=True)
        if failed:
            raise AuthError("La ONU rechazó el usuario o la contraseña. Tras varios intentos fallidos se "
                            "bloquea unos minutos.")
        self._get("/admin/wlwpa.asp")   # confirma la sesión
        self.captcha_used = needs_code

    def _encode_password(self, html: str) -> str:
        m = re.search(r"psd\.value\s*=\s*([A-Za-z_$][\w$.]*)\s*\(", html)
        if not m:
            return self.password
        fn = m.group(1).lower()
        if "base64" in fn or "b64" in fn:
            return base64.b64encode(self.password.encode()).decode()
        if "md5" in fn:
            return hashlib.md5(self.password.encode()).hexdigest()
        if "sha256" in fn:
            return hashlib.sha256(self.password.encode()).hexdigest()
        raise NotSupportedError("Esta ONU cifra la contraseña de una forma que la app aún no conoce.")

    def logout(self) -> None:
        try:
            html = self._get("/admin/top.asp")
            form = find_form(parse_forms(html), "formLogout")
            fields = hidden_fields(form) if form else []
        except Exception:
            fields = []
        self.session.post(self._url(f"{self.prefix}/formLogout"), data="&".join(f"{k}={_enc(v)}" for k, v in fields),
                          timeout=5, headers={"Content-Type": "application/x-www-form-urlencoded"})

    # --- bandas -------------------------------------------------------------
    def _wlan_indexes(self) -> dict[int, str]:
        """wlan_idx -> banda, leyendo el campo oculto Band2G5GSupport (1=2.4, 2=5)."""
        if self.bands:
            return self.bands
        for idx in (0, 1):
            try:
                html = self._page("/admin/wlbasic.asp", idx)
            except FileNotFoundError:
                break
            form = find_form(parse_forms(html), "formWlanSetup")
            if form is None:
                continue
            hid = dict(hidden_fields(form))
            if idx == 1 and hid.get("wlan_idx", "1") != "1":
                break   # equipo de una sola banda: ignoró el cambio
            band = Band.B5 if hid.get("Band2G5GSupport") == "2" else Band.B24
            if band in self.bands.values():
                continue
            self.bands[idx] = band
        if not self.bands:
            self.bands = {0: Band.B24}
        return self.bands

    # --- Wi-Fi --------------------------------------------------------------
    def _security(self, wlan_idx: int):
        html = self._page("/admin/wlwpa.asp", wlan_idx)
        forms = parse_forms(html)
        form = find_form(forms, "formWlEncrypt")
        if form is None:
            raise NotSupportedError("No se encontró la página de seguridad Wi‑Fi en esta ONU.")
        options = (form["selects"].get("wpaSSID") or {}).get("options", [])
        arrays = {n: js_array(html, n) for n in ("_encrypt", "_wpaAuth", "_wpaPSKFormat", "_wpaPSK", "_uCipher",
                                                   "_wpa2uCipher", "_wpaGroupRekeyTime", "_dotIEEE80211W",
                                                   "_sha256", "_wlan_isNmode", "_enable1X")}
        return form, options, arrays

    def get_wifi_networks(self) -> list[WifiNetwork]:
        nets = []
        for idx, band in self._wlan_indexes().items():
            form, options, arrays = self._security(idx)
            radio_off = dict(hidden_fields(form)).get("wlanDisabled", "").upper() == "ON"
            for k, opt in enumerate(options):
                extra = {"wlan_idx": idx, "k": k, "ssid_value": opt["value"],
                         "encrypt": int(arrays["_encrypt"].get(k, "0") or 0)}
                if arrays["_wpaPSK"].get(k):
                    extra["psk"] = arrays["_wpaPSK"][k]
                nets.append(WifiNetwork(id=f"{idx}:{opt['value']}", band=band, ssid=opt["text"],
                                        enabled=not radio_off, extra=extra))
        if not nets:
            raise NotSupportedError("El Wi‑Fi de esta ONU está apagado o no se pudo leer.")
        return nets

    def set_wifi(self, network: WifiNetwork, ssid: str | None = None, password: str | None = None) -> None:
        if ssid is not None and ssid != network.ssid:
            raise NotSupportedError("En esta ONU la app todavía solo puede cambiar la clave, no el nombre.")
        if password is None:
            return
        validate_wifi_password(password)
        idx = network.extra["wlan_idx"]
        form, options, arr = self._security(idx)
        k = next((i for i, o in enumerate(options) if o["value"] == network.extra["ssid_value"]), None)
        if k is None:
            raise OnuError("La red ya no existe en la ONU; vuelve a conectar.")
        enc = int(arr["_encrypt"].get(k, "0") or 0)
        if enc == SEC_WEP:
            raise NotSupportedError("Esta red usa WEP (inseguro). Cámbiala a WPA2 desde el panel web una vez.")
        if enc in (SEC_WPA, SEC_WPA2, SEC_WPA_MIXED) and int(arr["_wpaAuth"].get(k, AUTH_PSK) or AUTH_PSK) != AUTH_PSK:
            raise NotSupportedError("Esta red usa autenticación empresarial (RADIUS); no se cambia desde la app.")
        if enc == SEC_NONE:   # red abierta -> WPA2-AES
            enc, ucipher, u2cipher, dot11w, sha = SEC_WPA2, 0, CIPHER_AES, "0", "0"
        else:
            ucipher = int(arr["_uCipher"].get(k, "0") or 0)
            u2cipher = int(arr["_wpa2uCipher"].get(k, "0") or 0)
            dot11w = arr["_dotIEEE80211W"].get(k, "0") or "0"
            sha = arr["_sha256"].get(k, "0") or "0"

        fields = [(n, v) for n, v in hidden_fields(form) if n not in ("isNmode",)]
        fields.append(("isNmode", arr["_wlan_isNmode"].get(k, "0") or "0"))
        fields += [("wpaSSID", network.extra["ssid_value"]), ("security_method", str(enc)), ("wpaAuth", "psk")]
        if enc in (SEC_WPA, SEC_WPA_MIXED):
            if ucipher & CIPHER_TKIP:
                fields.append(("ciphersuite_t", "1"))
            if ucipher & CIPHER_AES:
                fields.append(("ciphersuite_a", "1"))
        if enc in (SEC_WPA2, SEC_WPA_MIXED):
            if u2cipher & CIPHER_TKIP:
                fields.append(("wpa2ciphersuite_t", "1"))
            if u2cipher & CIPHER_AES:
                fields.append(("wpa2ciphersuite_a", "1"))
        if enc == SEC_WPA2:
            fields += [("dotIEEE80211W", dot11w), ("sha256", sha)]
        rekey = arr["_wpaGroupRekeyTime"].get(k, "")
        if rekey:
            fields.append(("gk_rekey", rekey))
        fields += [("pskFormat", "0"), ("pskValue", password)]
        self._post("formWlEncrypt", fields, "/admin/wlwpa.asp")

        _, _, after = self._security(idx)
        if after["_wpaPSK"] and after["_wpaPSK"].get(k) != password:
            raise OnuError("La ONU aceptó la petición pero la clave no cambió.")

    # --- dispositivos -------------------------------------------------------
    def get_devices(self) -> list[Device]:
        blocked = {d.mac for d in self.get_blocked()}
        ips = self._dhcp_ips()
        devices: dict[str, Device] = {}
        for idx, band in self._wlan_indexes().items():
            try:
                html = self._get(f"{self.prefix}/formWirelessTbl?submit-url=/admin/wlstatbl.asp&wlan_idx={idx}")
            except FileNotFoundError:
                continue
            for m in re.finditer(r"<td[^>]*>(?:\s*<font[^>]*>)?\s*([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5})\s*<", html):
                mac = normalize_mac(m.group(1))
                devices.setdefault(mac, Device(mac=mac, ip=ips.get(mac, ""), interface=band, online=True,
                                               blocked=mac in blocked))
        return sorted(devices.values(), key=lambda d: d.mac)

    def _dhcp_ips(self) -> dict[str, str]:
        """MAC -> IP desde la tabla DHCP (/admin/dhcptbl.asp: filas IP | MAC | tiempo).
        Sirve para reconocer el celular donde corre la app y no dejar bloquearlo."""
        try:
            html = self._get("/admin/dhcptbl.asp")
        except (FileNotFoundError, OnuError):
            return {}
        out = {}
        for ip, mac in re.findall(r"<td[^>]*>(?:\s*<font[^>]*>)?\s*(\d{1,3}(?:\.\d{1,3}){3})\s*<.*?"
                                  r"<td[^>]*>(?:\s*<font[^>]*>)?\s*([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5})", html, re.S):
            try:
                out[normalize_mac(mac)] = ip
            except ValueError:
                continue
        return out

    def _acl(self, idx: int):
        html = self._page("/admin/wlactrl.asp", idx)
        forms = parse_forms(html)
        add = find_form(forms, "formWlAc")
        if add is None:
            raise NotSupportedError("Esta ONU no tiene control de acceso Wi‑Fi.")
        m = re.search(r"wlanAcEnabled\.selectedIndex\s*=\s*(\d)", html)
        if m:
            mode = int(m.group(1))
        else:
            opts = (add["selects"].get("wlanAcEnabled") or {}).get("options", [])
            sel = next((o for o in opts if o["selected"]), None)
            mode = int(sel["value"]) if sel and str(sel["value"]).isdigit() else AC_OFF
        entries = [(int(n), normalize_mac(mac)) for mac, n in re.findall(
            r"([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5})\s*(?:</font>)?\s*</td>\s*<td[^>]*>\s*<input[^>]*name=\"?select(\d+)",
            html)]
        delete = next((f for f in forms.forms if "formWlAc" in f["action"]
                       and any(i.get("name") == "deleteSelFilterMac" for i in f["inputs"])), add)
        return mode, entries, add, delete

    def get_blocked(self) -> list[Device]:
        out: dict[str, Device] = {}
        for idx in self._wlan_indexes():
            try:
                mode, entries, _, _ = self._acl(idx)
            except (NotSupportedError, FileNotFoundError):
                continue
            if mode == AC_DENY:
                for _, mac in entries:
                    out.setdefault(mac, Device(mac=mac, online=False, blocked=True))
        return list(out.values())

    @staticmethod
    def _base_fields(form: dict) -> list[tuple[str, str]]:
        return [(n, v) for n, v in hidden_fields(form)]

    def block_device(self, mac: str, name: str = "") -> None:
        mac = normalize_mac(mac)
        plan = []
        for idx in self._wlan_indexes():
            mode, entries, add, _ = self._acl(idx)
            if mode == AC_ALLOW:
                raise NotSupportedError("El control de acceso Wi‑Fi de esta ONU está en modo lista blanca "
                                        "(solo permite los equipos de la lista). Bloquear desde aquí haría lo "
                                        "contrario; no se cambió nada.")
            plan.append((idx, mode, mac in {m for _, m in entries}))
        for idx, mode, present in plan:
            if not present:
                _, _, add, _ = self._acl(idx)
                self._post("formWlAc", self._base_fields(add) + [("mac", mac.replace(":", "")),
                                                                  ("addFilterMac", "Add")], "/admin/wlactrl.asp")
            if mode != AC_DENY:
                _, _, add, _ = self._acl(idx)
                self._post("formWlAc", self._base_fields(add) + [("wlanAcEnabled", str(AC_DENY)),
                                                                  ("setFilterMode", "Apply")], "/admin/wlactrl.asp")
        if mac not in {d.mac for d in self.get_blocked()}:
            raise OnuError("La ONU aceptó la petición pero el equipo no aparece en la lista de bloqueo.")

    def unblock_device(self, mac: str) -> None:
        mac = normalize_mac(mac)
        for idx in self._wlan_indexes():
            _, entries, _, delete = self._acl(idx)
            sel = [n for n, m in entries if m == mac]
            if not sel:
                continue
            fields = self._base_fields(delete) + [(f"select{n}", "ON") for n in sel]
            fields.append(("deleteSelFilterMac", "Delete Selected"))
            self._post("formWlAc", fields, "/admin/wlactrl.asp")
        if mac in {d.mac for d in self.get_blocked()}:
            raise OnuError("La ONU aceptó la petición pero el equipo sigue en la lista de bloqueo.")
