"""Driver ZTE ZXHN con firmware "ThinkLua" (F670L, F680, F6600P, F6201B, F660 recientes…).

Flujo del panel web (el mismo que ejecuta su JavaScript):

  Login     GET  /?_type=loginData&_tag=login_entry       -> {"sess_token": …}
            GET  /?_type=loginData&_tag=login_token       -> reto
            POST /?_type=loginData&_tag=login_entry       Password = sha256(clave + reto)
            GET  /                                        -> clave pública RSA de asyEncode()
  Lectura   GET  /?_type=menuView&_tag=<vista>            -> _sessionTmpToken
            GET  /?_type=menuData&_tag=<tabla>.lua        -> XML <OBJ_…><Instance>…
  Escritura POST /?_type=menuData&_tag=<tabla>.lua        campos en orden + _sessionTOKEN al final
            Header Check = base64(RSA_PKCS1v15(sha256hex(cuerpo)))

  La clave Wi‑Fi viaja cifrada (AES-256-CBC, relleno con ceros) cuando el
  equipo la marca en <encode>; la llave e IV temporales van en el campo
  `encode`, cifrados con la RSA del equipo.

  Bloqueo   wlan_macfilterrule_lua.lua (reglas por punto de acceso) +
            wlan_macfilteraclpolicy_lua.lua (Disabled / Ban / Allow por punto de acceso)
            La regla Ban hace que el punto de acceso rechace al equipo.
"""
from __future__ import annotations

import base64
import hashlib
import random
import re
import string
import time
import xml.etree.ElementTree as ET
from urllib.parse import quote

from ..base import (AuthError, Band, Device, NotSupportedError, OnuDriver, OnuError, WifiNetwork,
                    normalize_mac, validate_ssid, validate_wifi_password)

# Clave que usan muchos firmwares ZTE cuando la página no publica la suya.
FALLBACK_PUBLIC_KEY = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAodPTerkUVCYmv28SOfRV
7UKHVujx/HjCUTAWy9l0L5H0JV0LfDudTdMNPEKloZsNam3YrtEnq6jqMLJV4ASb
1d6axmIgJ636wyTUS99gj4BKs6bQSTUSE8h/QkUYv4gEIt3saMS0pZpd90y6+B/9
hZxZE/RKU8e+zgRqp1/762TB7vcjtjOwXRDEL0w71Jk9i8VUQ59MR1Uj5E8X3WIc
fYSK5RWBkMhfaTRM6ozS9Bqhi40xlSOb3GBxCmliCifOJNLoO9kFoWgAIw5hkSIb
GH+4Csop9Uy8VvmmB+B3ubFLN35qIa5OG5+SDXn4L7FeAA5lRiGxRi8tsWrtew8w
nwIDAQAB
-----END PUBLIC KEY-----"""

SSID_TAG = "wlan_wlansssidconf_lua.lua"
CLIENTS_TAG = "wlan_client_stat_lua.lua"
ACL_RULE_TAG = "wlan_macfilterrule_lua.lua"
ACL_POLICY_TAG = "wlan_macfilteraclpolicy_lua.lua"


def _enc(v) -> str:
    """encodeURIComponent() de JavaScript."""
    return quote("" if v is None else str(v), safe="-_.!~*'()")


def _body(fields: list[tuple[str, str]]) -> str:
    return "&".join(f"{k}={_enc(v)}" for k, v in fields)


# --- criptografía (pycryptodome; empaquetado en el APK) ---------------------

def _aes_key_iv(key_str: str, iv_str: str) -> tuple[bytes, bytes]:
    return hashlib.sha256(key_str.encode()).digest(), hashlib.sha256(iv_str.encode()).digest()[:16]


def aes_encrypt(plaintext: str, key_str: str, iv_str: str) -> str:
    from Crypto.Cipher import AES
    if not plaintext:
        return ""
    key, iv = _aes_key_iv(key_str, iv_str)
    data = plaintext.encode()
    data += b"\x00" * ((16 - len(data) % 16) % 16)
    return base64.b64encode(AES.new(key, AES.MODE_CBC, iv).encrypt(data)).decode()


def aes_decrypt(ciphertext_b64: str, key_str: str, iv_str: str) -> str:
    from Crypto.Cipher import AES
    if not ciphertext_b64:
        return ""
    try:
        key, iv = _aes_key_iv(key_str, iv_str)
        raw = base64.b64decode(ciphertext_b64)
        return AES.new(key, AES.MODE_CBC, iv).decrypt(raw).rstrip(b"\x00").decode()
    except Exception:
        return ""


def rsa_encrypt_b64(text: str, public_key_pem: str) -> str:
    from Crypto.Cipher import PKCS1_v1_5
    from Crypto.PublicKey import RSA
    cipher = PKCS1_v1_5.new(RSA.import_key(public_key_pem))
    return base64.b64encode(cipher.encrypt(text.encode())).decode()


def check_header(body: str, public_key_pem: str) -> str:
    return rsa_encrypt_b64(hashlib.sha256(body.encode()).hexdigest(), public_key_pem)


# --- XML ---------------------------------------------------------------------

def parse_xml(text: str) -> tuple[str, dict[str, list[dict]], set[str]]:
    """(IF_ERRORSTR, {OBJ_x: [instancias]}, campos cifrados)."""
    try:
        root = ET.fromstring(text.strip())
    except ET.ParseError as e:
        raise NotSupportedError("La ONU ZTE respondió en un formato desconocido.") from e
    objs: dict[str, list[dict]] = {}
    for obj in root:
        if not (obj.tag.startswith("OBJ_") or obj.tag.startswith("ID_")):
            continue
        rows = []
        for inst in obj.findall("Instance"):
            kids, row, i = list(inst), {}, 0
            while i < len(kids) - 1:
                if kids[i].tag == "ParaName" and kids[i + 1].tag == "ParaValue":
                    row[kids[i].text or ""] = kids[i + 1].text or ""
                    i += 2
                else:
                    i += 1
            rows.append(row)
        objs[obj.tag] = rows
    encode = {f.strip() for node in root.findall("encode") for f in (node.text or "").split(",") if f.strip()}
    return (root.findtext("IF_ERRORSTR") or "").strip(), objs, encode


def _find_obj(objs: dict, part: str) -> list[dict]:
    for k, v in objs.items():
        if part in k:
            return v
    return []


def _uses_psk(ap: dict) -> bool:
    return any(("PSK" in ap.get(f, "") or "SAE" in ap.get(f, ""))
               for f in ("WPAAuthMode", "11iAuthMode", "WPA3AuthMode"))


ENCRYPTION_TYPES = {  # nombre del formulario -> campos que lo definen
    "No Security": {"BeaconType": "None"},
    "WPA-PSK-AES": {"BeaconType": "WPA", "WPAAuthMode": "PSKAuthentication", "WPAEncryptType": "AESEncryption"},
    "WPA2-PSK-AES": {"BeaconType": "11i", "11iAuthMode": "PSKAuthentication", "11iEncryptType": "AESEncryption"},
    "WPA2-PSK-TKIP/AES": {"BeaconType": "11i", "11iAuthMode": "PSKAuthentication",
                          "11iEncryptType": "TKIPandAESEncryption"},
    "WPA/WPA2-PSK-AES": {"BeaconType": "WPAand11i", "WPAAuthMode": "PSKAuthentication",
                         "11iAuthMode": "PSKAuthentication", "WPAEncryptType": "AESEncryption",
                         "11iEncryptType": "AESEncryption"},
    "WPA/WPA2-PSK-TKIP/AES": {"BeaconType": "WPAand11i", "WPAAuthMode": "PSKAuthentication",
                              "11iAuthMode": "PSKAuthentication", "WPAEncryptType": "TKIPandAESEncryption",
                              "11iEncryptType": "TKIPandAESEncryption"},
    "WPA3-SAE": {"BeaconType": "WPA3", "WPA3AuthMode": "SAEAuthentication", "WPA3EncryptType": "AESEncryption"},
    "WPA2-PSK-AES/WPA3-SAE-AES": {"BeaconType": "11iandWPA3", "11iAuthMode": "PSKAuthentication",
                                  "WPA3AuthMode": "SAEAuthentication", "11iEncryptType": "AESEncryption",
                                  "WPA3EncryptType": "AESEncryption"},
    "WPA2/WPA3-SAE": {"BeaconType": "11iandWPA3", "11iAuthMode": "PSKAuthentication",
                      "WPA3AuthMode": "SAEAuthentication", "11iEncryptType": "TKIPandAESEncryption",
                      "WPA3EncryptType": "AESEncryption"},
}


def _encryption_type(ap: dict) -> str:
    for name, fields in ENCRYPTION_TYPES.items():
        if all(ap.get(k) == v for k, v in fields.items()):
            return name
    return "No Security" if ap.get("BeaconType", "").lower() == "none" else "WPA2-PSK-AES"


def _band(ap: dict) -> str:
    view = ap.get("WLANViewName", "")
    if view.endswith("RD2"):
        return Band.B5
    if view.endswith("RD1"):
        return Band.B24
    n = int(re.sub(r"\D", "", ap.get("_InstID", "")) or 1)
    return Band.B24 if n <= 4 else Band.B5


class ZteDriver(OnuDriver):
    brand = "ZTE"
    default_username = "user"

    def __init__(self, *a, **kw):
        super().__init__(*a, **kw)
        self.sess_token = ""
        self.tmp_token = ""
        self.public_key = ""
        self.session.headers.update({"X-Requested-With": "XMLHttpRequest", "Referer": self.host + "/"})

    @classmethod
    def matches(cls, homepage_html: str, headers: dict) -> bool:
        h = homepage_html.lower()
        return "_type=logindata" in h or "login_entry" in h or "zxhn" in h or (
            "zte" in h and "_type=" in h)

    @classmethod
    def probe(cls, session, host: str, timeout: int = 5) -> bool:
        """Sin credenciales: solo los ZTE responden JSON con sess_token aquí."""
        try:
            r = session.get(f"{host}/?_type=loginData&_tag=login_entry", timeout=timeout)
            return "sess_token" in r.json()
        except Exception:
            return False

    # --- sesión -------------------------------------------------------------
    def login(self) -> None:
        s = self.session
        try:
            info = s.get(self._url("/?_type=loginData&_tag=login_entry"), timeout=self.timeout).json()
        except ValueError as e:
            raise NotSupportedError("Esta ONU ZTE usa un panel antiguo que la app aún no soporta.") from e
        if int(info.get("lockingTime") or 0) > 0:
            raise AuthError(f"La ONU está bloqueada por intentos fallidos. Espera {info['lockingTime']} s.")
        self.sess_token = info.get("sess_token", "")
        r = s.get(self._url(f"/?_type=loginData&_tag=login_token&_={int(time.time() * 1000)}"), timeout=self.timeout)
        m = re.search(r">\s*([^<\s]+)\s*<", r.text) or re.search(r"(\w+)", r.text)
        challenge = m.group(1) if m else ""
        pw_hash = hashlib.sha256((self.password + challenge).encode()).hexdigest()
        body = _body([("action", "login"), ("Username", self.username), ("Password", pw_hash),
                      ("_sessionTOKEN", self.sess_token)])
        r = s.post(self._url("/?_type=loginData&_tag=login_entry"), data=body, timeout=self.timeout,
                   headers={"Content-Type": "application/x-www-form-urlencoded; charset=UTF-8"})
        try:
            res = r.json()
        except ValueError:
            res = {"loginErrMsg": r.text[:200]}
        if res.get("loginErrMsg") or int(res.get("lockingTime") or 0) > 0:
            msg = "La ONU ZTE rechazó el usuario o la contraseña."
            if int(res.get("lockingTime") or 0) > 0:
                msg += f" Bloqueada por {res['lockingTime']} s tras varios intentos."
            raise AuthError(msg)
        self.sess_token = res.get("sess_token") or self.sess_token
        main = s.get(self._url("/"), timeout=self.timeout).text
        self.public_key = self._extract_public_key(main) or ""

    def logout(self) -> None:
        if self.sess_token:
            self.session.post(self._url("/?_type=loginData&_tag=logout_entry"),
                              data=_body([("IF_LogOff", "1"), ("_sessionTOKEN", self.sess_token)]),
                              timeout=5, headers={"Content-Type": "application/x-www-form-urlencoded"})

    @staticmethod
    def _extract_public_key(html: str) -> str | None:
        text = html.replace("\\r", "").replace("\\n", "\n")
        m = re.search(r"-----BEGIN PUBLIC KEY-----(.*?)-----END PUBLIC KEY-----", text, re.S)
        if not m:
            return None
        # Quitar comillas, saltos y concatenaciones JS ("…" + "…"): solo queda base64.
        inner = re.sub(r"[\"']\s*\+\s*[\"']", "", m.group(1))
        inner = re.sub(r"[\"'\s]|\\n|\\r", "", inner)
        inner = re.sub(r"[^A-Za-z0-9+/=]", "", inner)
        body = "\n".join(inner[i:i + 64] for i in range(0, len(inner), 64))
        return f"-----BEGIN PUBLIC KEY-----\n{body}\n-----END PUBLIC KEY-----"

    def _view(self, tag: str) -> None:
        r = self.session.get(self._url(f"/?_type=menuView&_tag={tag}&Menu3Location=0&_={int(time.time() * 1000)}"),
                             timeout=self.timeout)
        if "SessionTimeout" in r.text or r.status_code in (401, 403):
            raise AuthError("La sesión con la ONU expiró. Vuelve a pulsar Conectar.")
        m = re.search(r"_sessionTmpToken\s*=\s*['\"]([^'\"]+)['\"]", r.text)
        if m:
            raw = m.group(1)
            self.tmp_token = (bytes(int(h, 16) for h in re.findall(r"\\x([0-9a-fA-F]{2})", raw)).decode()
                              if raw.startswith("\\x") else raw)
        if not self.public_key:
            self.public_key = self._extract_public_key(r.text) or ""

    def _data(self, tag: str) -> tuple[dict, set]:
        r = self.session.get(self._url(f"/?_type=menuData&_tag={tag}&_={int(time.time() * 1000)}"),
                             timeout=self.timeout)
        if r.status_code == 404:
            raise NotSupportedError(f"Esta ONU ZTE no tiene la tabla {tag}.")
        err, objs, encode = parse_xml(r.text)
        if "SessionTimeout" in err:
            raise AuthError("La sesión con la ONU expiró. Vuelve a pulsar Conectar.")
        if err and err not in ("SUCC", "SUCCESS", "OK"):
            raise OnuError(f"La ONU ZTE devolvió: {err}")
        return objs, encode

    def _post(self, tag: str, fields: list[tuple[str, str]]) -> None:
        if not self.tmp_token:
            raise OnuError("No se obtuvo el token de la página de la ONU.")
        body = _body(fields + [("_sessionTOKEN", self.tmp_token)])
        headers = {"Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
                   "Check": check_header(body, self.public_key or FALLBACK_PUBLIC_KEY)}
        r = self.session.post(self._url(f"/?_type=menuData&_tag={tag}"), data=body, headers=headers,
                              timeout=60)
        if r.status_code >= 400:
            raise OnuError(f"La ONU rechazó el cambio (HTTP {r.status_code}).")
        try:
            err, _, _ = parse_xml(r.text)
        except NotSupportedError:
            return
        if "SessionTimeout" in err:
            raise AuthError("La sesión con la ONU expiró. Vuelve a pulsar Conectar.")
        if err and err not in ("SUCC", "SUCCESS", "OK"):
            raise OnuError(f"La ONU ZTE no aplicó el cambio: {err}")

    # --- Wi-Fi --------------------------------------------------------------
    def _ssid_conf(self) -> tuple[dict, set]:
        self._view("wlanBasic")
        return self._data(SSID_TAG)

    def get_wifi_networks(self) -> list[WifiNetwork]:
        objs, _ = self._ssid_conf()
        nets = []
        for ap in objs.get("OBJ_WLANAP_ID", []):
            if not ap.get("_InstID"):
                continue
            nets.append(WifiNetwork(id=ap["_InstID"], band=_band(ap), ssid=ap.get("ESSID", ""),
                                    enabled=ap.get("Enable") == "1"))
        if not nets:
            raise NotSupportedError("No se encontró la configuración Wi‑Fi en esta ONU ZTE.")
        return [n for n in nets if n.ssid or n.enabled]

    def set_wifi(self, network: WifiNetwork, ssid: str | None = None, password: str | None = None) -> None:
        if ssid is None and password is None:
            return
        if ssid is not None:
            validate_ssid(ssid)
        if password is not None:
            validate_wifi_password(password)

        objs, encode = self._ssid_conf()
        token = self.tmp_token
        ap = next((a for a in objs.get("OBJ_WLANAP_ID", []) if a.get("_InstID") == network.id), None)
        if ap is None:
            raise OnuError("La red ya no existe en la ONU; vuelve a conectar.")
        ap = dict(ap)
        psk = next((p for p in objs.get("OBJ_WLANPSK_ID", [])
                    if p.get("_InstID", "").startswith(network.id + ".PSK")), {})
        weps = sorted((w for w in objs.get("OBJ_WLANWEPKEY_ID", [])
                       if w.get("_InstID", "").startswith(network.id + ".WEP")), key=lambda w: w["_InstID"])

        if ssid is not None:
            ap["ESSID"] = ssid
        current_pw = psk.get("KeyPassphrase", "")
        if current_pw and "KeyPassphrase" in encode:
            current_pw = aes_decrypt(current_pw, token, token[::-1])
        if password is not None and not _uses_psk(ap):
            ap.update(ENCRYPTION_TYPES["WPA2-PSK-AES"])   # red abierta -> WPA2
        new_pw = password if password is not None else current_pw
        is_psk, is_wep = _uses_psk(ap), ap.get("BeaconType") == "Basic"
        if is_psk and not new_pw:
            raise ValueError("Escribe también la clave Wi‑Fi (no se pudo leer la actual).")

        secret_encoded = bool(encode & {"KeyPassphrase", "WEPKey"})
        k = "".join(random.choices(string.digits, k=16))
        iv = "".join(random.choices(string.digits, k=16))

        def secret(value: str, field: str) -> str:
            if not value:
                return ""
            return aes_encrypt(value, k, iv) if field in encode else value

        wep_values = []
        for w in weps[:4]:
            v = w.get("WEPKey", "")
            if v and "WEPKey" in encode:
                v = aes_decrypt(v, token, token[::-1])
            wep_values.append(secret(v, "WEPKey"))
        wep_values += [""] * (4 - len(wep_values))
        wep_ids = [w.get("_InstID") for w in weps[:4]]
        wep_ids += [f"{network.id}.WEP{i + 1}" for i in range(len(wep_ids), 4)]

        fields = [
            ("IF_ACTION", "Apply"), ("_InstID", network.id),
            ("_WEPCONIG", "Y" if is_wep else "N"), ("_PSKCONIG", "Y" if is_psk else "N"),
            ("BeaconType", ap.get("BeaconType", "")), ("WEPAuthMode", ap.get("WEPAuthMode", "")),
            ("WPAAuthMode", ap.get("WPAAuthMode", "")), ("11iAuthMode", ap.get("11iAuthMode", "")),
            ("WPAEncryptType", ap.get("WPAEncryptType", "")), ("11iEncryptType", ap.get("11iEncryptType", "")),
            ("WPA3AuthMode", ap.get("WPA3AuthMode", "")), ("WPA3EncryptType", ap.get("WPA3EncryptType", "")),
            ("_InstID_WEP0", wep_ids[0]), ("_InstID_WEP1", wep_ids[1]),
            ("_InstID_WEP2", wep_ids[2]), ("_InstID_WEP3", wep_ids[3]),
            ("_InstID_PSK", psk.get("_InstID") or f"{network.id}.PSK1"),
            ("MasterAuthServerIp", ap.get("MasterAuthServerIp", "")),
            ("_InstID_GUEST", ap.get("_InstID_GUEST", "")), ("_GUEST", ap.get("_GUEST", "N")),
            ("GuestWifi", ap.get("GuestWifi", "")),
            ("Enable", ap.get("Enable", "1")), ("ESSID", ap.get("ESSID", "")),
            ("ESSIDHideEnable", ap.get("ESSIDHideEnable", "0")), ("PMFEnable", ap.get("PMFEnable", "0")),
            ("EncryptionType", _encryption_type(ap)),
            ("KeyPassphrase", secret(new_pw, "KeyPassphrase") if is_psk else ""),
            ("WEPKeyIndex", ap.get("WEPKeyIndex", "1")), ("ShowWEPKey", ""),
            ("WEPKey00", wep_values[0]), ("WEPKey01", wep_values[1]),
            ("WEPKey02", wep_values[2]), ("WEPKey03", wep_values[3]),
            ("VapIsolationEnable", ap.get("VapIsolationEnable", "0")),
            ("MaxUserNum", ap.get("MaxUserNum", "32")),
            ("Btn_cancel_WLANSSIDConf", ""), ("Btn_apply_WLANSSIDConf", ""),
        ]
        if secret_encoded and (is_psk or any(wep_values)):
            fields.append(("encode", rsa_encrypt_b64(f"{k}+{iv}", self.public_key or FALLBACK_PUBLIC_KEY)))

        self._view("wlanBasic")      # el token del POST debe ser el de la vista recién abierta
        self._post(SSID_TAG, fields)

        if ssid is not None:
            now = {n.id: n for n in self.get_wifi_networks()}
            if network.id in now and now[network.id].ssid != ssid:
                raise OnuError("La ONU aceptó la petición pero el nombre de la red no cambió.")

    # --- dispositivos -------------------------------------------------------
    def get_devices(self) -> list[Device]:
        bands = {n.id: n.band for n in self.get_wifi_networks()}
        blocked = {d.mac for d in self.get_blocked()}
        self._view("localNetStatus")
        objs, _ = self._data(CLIENTS_TAG)
        devices: dict[str, Device] = {}
        for c in objs.get("OBJ_WLAN_AD_ID", []):
            try:
                mac = normalize_mac(c.get("MACAddress", ""))
            except ValueError:
                continue
            devices[mac] = Device(mac=mac, name=c.get("HostName", ""), ip=c.get("IPAddress", ""),
                                  interface=bands.get(c.get("AliasName", ""), "Wi‑Fi"), online=True,
                                  blocked=mac in blocked)
        return sorted(devices.values(), key=lambda d: d.name.lower())

    def _acl(self) -> tuple[list[dict], list[dict]]:
        self._view("wlanAdvanced")
        pol, _ = self._data(ACL_POLICY_TAG)
        rules, _ = self._data(ACL_RULE_TAG)
        return _find_obj(pol, "WLANAP"), _find_obj(rules, "ACLCFG")

    def get_blocked(self) -> list[Device]:
        policies, rules = self._acl()
        banned = {p.get("_InstID") for p in policies if p.get("ACLPolicy") == "Ban"}
        out: dict[str, Device] = {}
        for r in rules:
            if r.get("Interface") in banned:
                try:
                    mac = normalize_mac(r.get("MACAddress", ""))
                except ValueError:
                    continue
                label = re.sub(r"\s+AP\d+$", "", r.get("Name", "")).strip()
                out.setdefault(mac, Device(mac=mac, name="" if label.upper() == mac else label,
                                           online=False, blocked=True))
        return list(out.values())

    @staticmethod
    def _rule_fields(action: str, inst_id: str, mac: str, name: str, interface: str) -> list[tuple[str, str]]:
        octets = mac.upper().split(":")
        f = [("IF_ACTION", action), ("_InstID", inst_id), ("MACAddress", mac.upper()), ("Name", name),
             ("Interface", interface)]
        f += [(f"sub_MACAddress{i}", o) for i, o in enumerate(octets)]
        return f

    def block_device(self, mac: str, name: str = "") -> None:
        mac = normalize_mac(mac)
        targets = [n.id for n in self.get_wifi_networks() if n.enabled]
        if not targets:
            raise OnuError("No hay redes Wi‑Fi encendidas en la ONU.")
        policies, rules = self._acl()
        policy_of = {p.get("_InstID"): p.get("ACLPolicy") or "Disabled" for p in policies}
        if any(policy_of.get(t) == "Allow" for t in targets):
            raise NotSupportedError("El control de acceso Wi‑Fi de esta ONU está en modo lista blanca (solo "
                                    "permite los equipos de la lista). Bloquear desde aquí haría lo contrario; "
                                    "no se cambió nada.")
        have = {r.get("Interface") for r in rules if r.get("MACAddress", "").upper() == mac}
        for ap in targets:
            if ap in have:
                continue
            short = ap.rsplit(".", 1)[-1]
            label = (f"{name[:10]} {short}" if name else f"{mac} {short}")[:32]
            self._view("wlanAdvanced")
            self._post(ACL_RULE_TAG, self._rule_fields("Apply", "-1", mac, label, ap))
        if any(policy_of.get(t) != "Ban" for t in targets):
            new = dict(policy_of)
            for t in targets:
                new[t] = "Ban"
            fields = [("IF_ACTION", "Apply"), ("_InstNum", str(len(policies)))]
            for i, p in enumerate(policies):
                fields += [(f"_InstID_{i}", p.get("_InstID", "")), (f"ACLPolicy_{i}", new[p.get("_InstID")])]
            fields += [("_InstID", "")]
            self._view("wlanAdvanced")
            self._post(ACL_POLICY_TAG, fields)
        if mac not in {d.mac for d in self.get_blocked()}:
            raise OnuError("La ONU aceptó la petición pero el equipo no aparece en la lista de bloqueo.")

    def unblock_device(self, mac: str) -> None:
        mac = normalize_mac(mac)
        # La ONU renumera las reglas tras cada borrado: se relee antes de cada uno.
        for _ in range(16):
            _, rules = self._acl()
            target = next((r for r in rules if r.get("MACAddress", "").upper() == mac), None)
            if target is None:
                return
            self._view("wlanAdvanced")
            self._post(ACL_RULE_TAG, self._rule_fields("Delete", target.get("_InstID", ""), mac,
                                                       target.get("Name", ""), target.get("Interface", "")))
        raise OnuError("No se pudieron borrar todas las reglas de bloqueo de este equipo.")

