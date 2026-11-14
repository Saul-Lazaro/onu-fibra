"""ONUs simuladas para las pruebas: servidores HTTP reales que validan lo mismo
que los equipos (tokens, orden de campos, firma Check, cifrado de la clave)."""
from __future__ import annotations

import base64
import hashlib
import json
import random
import re
import threading
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qsl, unquote, urlsplit


def hexesc(s: str) -> str:
    return "".join(c if c.isalnum() or c == " " else f"\\x{ord(c):02x}" for c in s)


class FakeServer:
    """Arranca `handler_cls` en un puerto libre; `state` es compartido."""

    def __init__(self, handler_cls, state):
        handler = type("H", (handler_cls,), {"state": state})
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        self.state = state
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)

    @property
    def host(self) -> str:
        return f"127.0.0.1:{self.httpd.server_address[1]}"

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *exc):
        self.httpd.shutdown()
        self.httpd.server_close()


class Base(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    state: dict

    def log_message(self, *a):
        pass

    def body(self) -> str:
        n = int(self.headers.get("Content-Length") or 0)
        return self.rfile.read(n).decode() if n else ""

    def send(self, text: str, status=200, ctype="text/html", cookies=None):
        data = text.encode()
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        for k, v in (cookies or {}).items():
            self.send_header("Set-Cookie", f"{k}={v}; path=/")
        self.end_headers()
        self.wfile.write(data)

    def cookie(self, name):
        c = SimpleCookie(self.headers.get("Cookie", ""))
        return c[name].value if name in c else None


# =========================================================================
# Huawei
# =========================================================================

HUAWEI_LOGIN_PAGE = """<html><script src="/resource/common/safelogin.js"></script>
<script>function GetRandCount(){ $.post('/asp/GetRandCount.asp') }</script>
<input id="txt_Username"><input id="txt_Password" type="password"></html>"""


def huawei_state():
    return {
        "user": "Epuser", "password": "clave123",
        "wlans": {1: {"ssid": "Casa-2G", "enable": "1", "psk": "viejaclave1"},
                  5: {"ssid": "Casa-5G", "enable": "1", "psk": "viejaclave1"}},
        "devices": [("192.168.100.10", "AA:BB:CC:00:00:01", "SSID1", "Online", "celular-ana"),
                    ("192.168.100.11", "AA:BB:CC:00:00:02", "SSID5", "Online", "tv-sala"),
                    ("192.168.100.12", "AA:BB:CC:00:00:03", "LAN1", "Offline", "pc-viejo")],
        "filter_enable": "0", "filter_mode": "0", "filter": [],  # [(ssidname, mac)]
        "token_seq": 0, "page_token": None, "login_token": None, "login_conn": None,
        "sid": None, "fail": 0, "log": [],
    }


class HuaweiHandler(Base):
    def authed(self):
        return self.state["sid"] and self.cookie("Cookie") == f"sid={self.state['sid']}"

    def new_token(self):
        self.state["token_seq"] += 1
        self.state["page_token"] = hashlib.md5(str(self.state["token_seq"]).encode()).hexdigest()
        return self.state["page_token"]

    def page(self, js):
        return f'<html><input type="hidden" name="onttoken" id="hwonttoken" value="{self.new_token()}">' \
               f"<script>{js}</script></html>"

    def do_GET(self):
        p = urlsplit(self.path)
        if p.path == "/":
            return self.send(HUAWEI_LOGIN_PAGE)
        if not self.authed():
            return self.send("<script>var pageName = '/'; top.location.replace(pageName);</script>")
        if p.path == "/index.asp":
            return self.send(self.page("var x=1;"))
        if p.path == "/html/amp/wlanbasic/WlanBasic.asp":
            rows = ",".join(
                f'new stWlan("{hexesc(f"InternetGatewayDevice.LANDevice.1.WLANConfiguration.{i}")}",'
                f'"{i}","{w["enable"]}","{hexesc(w["ssid"])}","1","11i")' for i, w in self.state["wlans"].items())
                # La página también trae las claves (como la real) -- no se usan para escribir.
            psk = ",".join(f'new stPreSharedKey("{hexesc(f"InternetGatewayDevice.LANDevice.1.WLANConfiguration.{i}.PreSharedKey.1")}","{hexesc(w["psk"])}","")'
                           for i, w in self.state["wlans"].items())
            return self.send(self.page(f"var WlanArr = new Array({rows},null); var wpaPskKey = new Array({psk},null);"))
        if p.path == "/html/bbsp/wlanmacfilter/wlanmacfilter.asp":
            rows = ",".join(
                f'new stMacFilter("InternetGatewayDevice.X_HW_Security.WLANMacFilter.{i + 1}","{s}","{hexesc(m)}")'
                for i, (s, m) in enumerate(self.state["filter"]))
            return self.send(self.page(f"var enableFilter = '{self.state['filter_enable']}'; "
                                       f"var Mode = '{self.state['filter_mode']}'; "
                                       f"var MacFilterSrc = new Array({rows}, null);"))
        return self.send("not found", 404)

    def do_POST(self):
        p = urlsplit(self.path)
        raw = self.body()
        form = parse_qsl(raw, keep_blank_values=True)
        st = self.state
        if p.path == "/asp/GetRandCount.asp":
            st["login_token"] = "%032x" % random.getrandbits(128)
            st["login_conn"] = id(self.connection)
            return self.send("﻿" + st["login_token"])
        if p.path == "/login.cgi":
            f = dict(form)
            ok = (f.get("UserName") == st["user"] and base64.b64decode(f.get("PassWord", "")).decode() == st["password"]
                  and f.get("x.X_HW_Token") == st["login_token"] and st["login_conn"] == id(self.connection))
            if not ok:
                st["fail"] += 1
                return self.send(HUAWEI_LOGIN_PAGE)
            st["sid"] = "%016x" % random.getrandbits(64)
            return self.send("<script>window.location='/index.asp';</script>", cookies={"Cookie": f"sid={st['sid']}"})
        if not self.authed():
            return self.send("<script>var pageName = '/'; top.location.replace(pageName);</script>")
        if p.path == "/logout.cgi":
            st["sid"] = None
            return self.send("ok")
        if p.path == "/html/bbsp/common/GetLanUserDevInfo.asp":
            rows = ",".join(f'new USERDevice("InternetGatewayDevice.LANDevice.1.X_HW_UserDev.{i}","{hexesc(ip)}",'
                            f'"{hexesc(mac)}","{port}","DHCP","","{status}","x","0:10","{name}","1","1","0")'
                            for i, (ip, mac, port, status, name) in enumerate(st["devices"], 1))
            return self.send(f"var UserDevinfo = new Array({rows},null);")

        # --- escrituras: RequestFile literal, token válido y al final -------------
        assert "%2F" not in p.query, "RequestFile debe ir con '/' literal"
        if not form or form[-1][0] != "x.X_HW_Token" or form[-1][1] != st["page_token"]:
            return self.send("<script>alert('token error')</script>")
        st["page_token"] = None  # un solo uso
        q = dict(parse_qsl(p.query))
        f = dict(form)
        st["log"].append((p.path, q, form))
        if p.path == "/html/amp/wlanbasic/set.cgi":
            inst = int(q["x"].rsplit(".", 1)[1])
            if "x.SSID" in f:
                st["wlans"][inst]["ssid"] = f["x.SSID"]
            if "k.PreSharedKey" in f:
                assert q["k"] == q["x"] + ".PreSharedKey.1"
                st["wlans"][inst]["psk"] = f["k.PreSharedKey"]
            return self.send("<script>top.location.replace('/html/amp/wlanbasic/WlanBasic.asp')</script>")
        if p.path == "/html/bbsp/wlanmacfilter/add.cgi":
            st["filter"].append((f["x.SSIDName"], f["x.SourceMACAddress"]))
            return self.send("ok")
        if p.path == "/html/bbsp/wlanmacfilter/del.cgi":
            names = [k for k, _ in form if k.startswith("InternetGatewayDevice.")]
            idx = {int(n.rsplit(".", 1)[1]) - 1 for n in names}
            st["filter"] = [e for i, e in enumerate(st["filter"]) if i not in idx]
            return self.send("ok")
        if p.path == "/html/bbsp/wlanmacfilter/set.cgi":
            st["filter_enable"], st["filter_mode"] = f["x.WlanMacFilterRight"], f["x.WlanMacFilterPolicy"]
            return self.send("ok")
        return self.send("not found", 404)


# =========================================================================
# ZTE
# =========================================================================

def zte_state():
    from Crypto.PublicKey import RSA
    key = RSA.generate(1024)
    return {
        "user": "user", "password": "Zte#1234", "rsa": key,
        "aps": {
            "DEV.WIFI.AP1": {"ESSID": "Hogar", "Enable": "1", "WLANViewName": "DEV.WIFI.RD1", "psk": "pass2g-old",
                             "BeaconType": "11i", "11iAuthMode": "PSKAuthentication", "11iEncryptType": "AESEncryption"},
            "DEV.WIFI.AP5": {"ESSID": "Hogar-5G", "Enable": "1", "WLANViewName": "DEV.WIFI.RD2", "psk": "pass5g-old",
                             "BeaconType": "11i", "11iAuthMode": "PSKAuthentication", "11iEncryptType": "AESEncryption"},
            "DEV.WIFI.AP2": {"ESSID": "", "Enable": "0", "WLANViewName": "DEV.WIFI.RD1", "psk": "",
                             "BeaconType": "None"},
        },
        "clients": [("AA:BB:CC:11:11:11", "192.168.1.20", "moto-g", "DEV.WIFI.AP1"),
                    ("AA:BB:CC:22:22:22", "192.168.1.21", "laptop", "DEV.WIFI.AP5")],
        "policy": {"DEV.WIFI.AP1": "Disabled", "DEV.WIFI.AP2": "Disabled", "DEV.WIFI.AP5": "Disabled"},
        "rules": [],  # dicts Name/Interface/MACAddress
        "sess": None, "challenge": None, "tmp": None, "logged": False, "log": [],
    }


def _para(k, v):
    return f"<ParaName>{k}</ParaName><ParaValue>{v}</ParaValue>"


class ZteHandler(Base):
    def xml(self, inner, err="SUCC"):
        return self.send(f"<ajax_response_xml_root><IF_ERRORSTR>{err}</IF_ERRORSTR>{inner}</ajax_response_xml_root>",
                         ctype="text/xml")

    def do_GET(self):
        st = self.state
        p = urlsplit(self.path)
        q = dict(parse_qsl(p.query))
        if q.get("_type") == "loginData" and q.get("_tag") == "login_entry":
            st["sess"] = "%08x" % random.getrandbits(32)
            return self.send(json.dumps({"sess_token": st["sess"], "lockingTime": 0}), ctype="application/json")
        if q.get("_type") == "loginData" and q.get("_tag") == "login_token":
            st["challenge"] = str(random.randint(10 ** 7, 10 ** 8))
            return self.send(f"<ajax_response_xml_root>{st['challenge']}</ajax_response_xml_root>", ctype="text/xml")
        if p.path == "/" and not q:
            if not st["logged"]:
                return self.send("<html><script>var url='/?_type=loginData&_tag=login_entry';</script></html>")
            pem = st["rsa"].publickey().export_key().decode().replace("\n", "\\n")
            return self.send(f'<html><script>var IntegCheck = true; function asyEncode(s){{ var pubKey = "{pem}";'
                             f" return rsa(s, pubKey); }}</script></html>")
        if not st["logged"]:
            return self.xml("", "SessionTimeout")
        if q.get("_type") == "menuView":
            st["tmp"] = "%016x" % random.getrandbits(64)
            st["view"] = q["_tag"]
            esc = "".join(f"\\x{ord(c):02x}" for c in st["tmp"])
            return self.send(f'<html><script>_sessionTmpToken = "{esc}";</script></html>')
        if q.get("_type") == "menuData":
            return self.menu_data(q["_tag"])
        return self.send("nf", 404)

    def menu_data(self, tag):
        st = self.state
        from onuchanger.drivers.zte import aes_encrypt
        if tag == "wlan_wlansssidconf_lua.lua":
            if st.get("view") != "wlanBasic":
                return self.xml("", "SessionTimeout")
            aps = "".join("<Instance>" + _para("_InstID", i) + "".join(_para(k, v) for k, v in a.items() if k != "psk")
                          + "</Instance>" for i, a in st["aps"].items())
            psks = "".join("<Instance>" + _para("_InstID", f"{i}.PSK1") +
                           _para("KeyPassphrase", aes_encrypt(a["psk"], st["tmp"], st["tmp"][::-1])) + "</Instance>"
                           for i, a in st["aps"].items())
            return self.xml(f"<OBJ_WLANAP_ID>{aps}</OBJ_WLANAP_ID><OBJ_WLANPSK_ID>{psks}</OBJ_WLANPSK_ID>"
                            "<encode>WEPKey</encode><encode>KeyPassphrase</encode>")
        if tag == "wlan_client_stat_lua.lua":
            rows = "".join("<Instance>" + _para("_InstID", f"DEV.WIFI.AD{i}") + _para("MACAddress", m.lower()) +
                           _para("IPAddress", ip) + _para("HostName", h) + _para("AliasName", ap) + "</Instance>"
                           for i, (m, ip, h, ap) in enumerate(st["clients"], 1))
            return self.xml(f"<OBJ_WLAN_AD_ID>{rows}</OBJ_WLAN_AD_ID>")
        if tag == "wlan_macfilteraclpolicy_lua.lua":
            rows = "".join("<Instance>" + _para("_InstID", i) + _para("ACLPolicy", v) + "</Instance>"
                           for i, v in st["policy"].items())
            return self.xml(f"<OBJ_WLANAP_ID>{rows}</OBJ_WLANAP_ID>")
        if tag == "wlan_macfilterrule_lua.lua":
            rows = "".join("<Instance>" + _para("_InstID", f"DEV.ACL{i}") + _para("Name", r["Name"]) +
                           _para("Interface", r["Interface"]) + _para("MACAddress", r["MACAddress"]) + "</Instance>"
                           for i, r in enumerate(st["rules"], 1))
            return self.xml(f"<OBJ_ACLCFG_ID>{rows}</OBJ_ACLCFG_ID>")
        return self.send("nf", 404)

    def do_POST(self):
        st = self.state
        p = urlsplit(self.path)
        q = dict(parse_qsl(p.query))
        raw = self.body()
        form = parse_qsl(raw, keep_blank_values=True)
        f = dict(form)
        if q.get("_tag") == "login_entry":
            good = hashlib.sha256((st["password"] + st["challenge"]).encode()).hexdigest()
            if f.get("Username") == st["user"] and f.get("Password") == good and f.get("_sessionTOKEN") == st["sess"]:
                st["logged"] = True
                return self.send(json.dumps({"sess_token": "x" + st["sess"], "login_need_refresh": True}))
            return self.send(json.dumps({"loginErrMsg": "Usuario o clave incorrectos", "lockingTime": 0}))
        if q.get("_tag") == "logout_entry":
            st["logged"] = False
            return self.send("{}")
        if not st["logged"]:
            return self.xml("", "SessionTimeout")
        # Firma Check = RSA(sha256hex(body)) y token de la vista al final
        from Crypto.Cipher import PKCS1_v1_5
        check = PKCS1_v1_5.new(st["rsa"]).decrypt(base64.b64decode(self.headers.get("Check", "")), None)
        if check != hashlib.sha256(raw.encode()).hexdigest().encode():
            return self.send("bad check", 400)
        if form[-1] != ("_sessionTOKEN", st["tmp"]):
            return self.xml("", "SessionTimeout")
        st["log"].append((q["_tag"], form))
        tag = q["_tag"]
        if tag == "wlan_wlansssidconf_lua.lua":
            from onuchanger.drivers.zte import aes_decrypt
            ap = st["aps"][f["_InstID"]]
            ap["ESSID"] = f["ESSID"]
            for k in ("BeaconType", "11iAuthMode", "11iEncryptType"):
                if f.get(k):
                    ap[k] = f[k]
            if f.get("KeyPassphrase"):
                kiv = PKCS1_v1_5.new(st["rsa"]).decrypt(base64.b64decode(f["encode"]), None).decode()
                k, iv = kiv.split("+")
                ap["psk"] = aes_decrypt(f["KeyPassphrase"], k, iv)
            return self.xml("")
        if tag == "wlan_macfilterrule_lua.lua":
            assert st.get("view") == "wlanAdvanced"
            if f["IF_ACTION"] == "Apply" and f["_InstID"] == "-1":
                assert ":".join(f[f"sub_MACAddress{i}"] for i in range(6)) == f["MACAddress"]
                if any(r["Name"] == f["Name"] for r in st["rules"]):
                    return self.xml("", "Name already exists")
                st["rules"].append({"Name": f["Name"], "Interface": f["Interface"], "MACAddress": f["MACAddress"]})
            elif f["IF_ACTION"] == "Delete":
                i = int(f["_InstID"].replace("DEV.ACL", "")) - 1
                st["rules"].pop(i)   # renumera, como el equipo
            return self.xml("")
        if tag == "wlan_macfilteraclpolicy_lua.lua":
            for i in range(int(f["_InstNum"])):
                st["policy"][f[f"_InstID_{i}"]] = f[f"ACLPolicy_{i}"]
            return self.xml("")
        return self.send("nf", 404)


# =========================================================================
# FiberHome
# =========================================================================

def fiberhome_state():
    return {
        "user": "user", "password": "Fh2024!", "acs": "abcdef6HTTa1234567bLVLzyxwvu",
        "lan": [{"MACAddress": "AA:BB:CC:33:33:33", "IPAddress": "192_point_168_point_1_point_5",
                 "HostName": "Galaxy-A14", "Active": "1", "AccessType": "2.4G"},
                {"MACAddress": "AA:BB:CC:44:44:44", "IPAddress": "192_point_168_point_1_point_6",
                 "HostName": "unknown", "Active": "1", "AccessType": "Ethernet"}],
        "enable": "0", "mode": "black", "filter": [],
        "sid": None, "logged": False, "next_index": 1, "log": [],
    }


class FiberhomeHandler(Base):
    def j(self, obj):
        return self.send(json.dumps(obj), ctype="application/json")

    def do_GET(self):
        st = self.state
        p = urlsplit(self.path)
        q = dict(parse_qsl(p.query))
        m = q.get("ajaxmethod")
        if p.path == "/":
            return self.send('<html><script src="/js/xhr.js"></script><script>var ajaxcgi="/cgi-bin/ajax";</script></html>')
        if m == "get_acs_random":
            return self.j({"acsRandom": st["acs"]})
        if m == "get_refresh_sessionid":
            st["sid"] = "%08X" % random.getrandbits(32)
            return self.j({"sessionid": st["sid"]})
        if not st["logged"]:
            return self.j({"session_valid": 0})
        if m == "get_lan_status":
            return self.j({"session_valid": 1, "get_lan_status": {"status": "success", "dhcp_user_list": st["lan"]}})
        if m == "get_ipv4_mac_filter_info":
            return self.j({"session_valid": 1, "ipv4_mac_filter_info": {
                "MACFEnable": st["enable"], "MACFMode": st["mode"],
                "mac_filter_data": [{"Enable": "1", "MAC": mac, "ipv4_mac_filter_index": idx}
                                    for idx, mac in st["filter"]]}})
        return self.send("nf", 404)

    def do_POST(self):
        st = self.state
        if urlsplit(self.path).query:
            return self.send("forbidden", 403)    # todo va en el cuerpo
        f = dict(parse_qsl(self.body(), keep_blank_values=True))
        if f.get("sessionid") != st["sid"]:
            return self.send("forbidden", 403)    # cada POST con sessionid recién pedido
        m = f.get("ajaxmethod")
        if m == "do_login":
            from Crypto.Cipher import AES
            key = st["acs"][6:22].encode()
            raw = AES.new(key, AES.MODE_CBC, key).decrypt(bytes.fromhex(f["loginpd"]))
            pw = raw[:-raw[-1]].decode(errors="replace")
            ok = f.get("username") == st["user"] and pw == st["password"]
            st["logged"] = ok
            return self.j({"session_valid": 1, "login_result": 0 if ok else 1})
        if not st["logged"]:
            return self.j({"session_valid": 0})
        st["log"].append(f)
        if m == "do_logout":
            st["logged"] = False
            return self.j({"session_valid": 1})
        if m == "set_ipv4_mac_filter_info":
            if f["action"] == "add":
                st["filter"].append((st["next_index"], f["MAC"]))
                st["next_index"] += 1
            elif f["action"] == "delete":
                st["filter"] = [(i, mac) for i, mac in st["filter"] if str(i) != f["ipv4_mac_filter_index"]]
            elif f["action"] == "enable":
                st["enable"], st["mode"] = f["ipv4_mac_filter_enable"], f["ipv4_mac_filter_mode"]
            return self.j({"session_valid": 1})
        return self.send("nf", 404)


# =========================================================================
# Realtek "boa" (V-SOL / OptiTimes): reproduce el SDK y una página de producción
# =========================================================================

def realtek_state(brand="V-SOL"):
    return {
        "brand": brand, "user": "admin", "password": "stdONU101",
        "logged": False, "csrf": None, "code": None, "idx": 0, "fails": 0,
        # wlan_idx 0 = 5 GHz y 1 = 2.4 GHz, como muchos RTL9607C con radio externa
        "wlan": {
            0: {"band": "2", "ssids": [{"ssid": "Familia-5G", "encrypt": 4, "u": 0, "u2": 2, "psk": "vieja5g123",
                                        "dot11w": 1, "sha": 1, "rekey": "86400"}],
                "ac_mode": 0, "ac": [], "clients": ["a4:c1:38:00:00:05"]},
            1: {"band": "1", "ssids": [{"ssid": "Familia", "encrypt": 6, "u": 3, "u2": 3, "psk": "vieja24g12",
                                        "dot11w": 0, "sha": 0, "rekey": "86400"},
                                       {"ssid": "Invitados", "encrypt": 0, "u": 0, "u2": 0, "psk": "",
                                        "dot11w": 0, "sha": 0, "rekey": "0"}],
                "ac_mode": 0, "ac": [], "clients": ["a4:c1:38:00:00:24", "a4:c1:38:00:00:25"]},
        },
        "log": [],
    }


class RealtekHandler(Base):
    def csrf_input(self):
        self.state["csrf"] = "%08x" % random.getrandbits(32)
        return f'<input type="hidden" name="csrftoken" value="{self.state["csrf"]}">'

    def login_page(self):
        st = self.state
        st["code"] = str(random.randint(1000, 9999))
        return self.send(f"""<html><head><title>{st['brand']} XPON ONU</title><script>
function on_submit(){{ with(document.forms[0]){{ username.value=username1.value; psd.value=psd1.value; submit(); }} }}
</script></head><body><form action=/boaform/admin/formLogin method=POST name="cmlogin">
<input type="text" name="username1" id="username1"><input type="password" name="psd1" id="psd1">
<input type="text" name="verification_code"><input type="hidden" id="check_code" value="{st['code']}">
<input name="button" type="button" onClick="on_submit();" value="Login">
<input type="hidden" name="username" id="username" value=''>
<input type="hidden" name="psd" id="psd" value=''>
<input type="hidden" name="sec_lang" value='0'>
{self.csrf_input()}</form></body></html>""")

    def do_GET(self):
        st = self.state
        p = urlsplit(self.path)
        q = dict(parse_qsl(p.query))
        if p.path in ("/", "/admin/login.asp"):
            if not st["logged"]:
                return self.login_page()
            return self.send("<html><frameset><frame src=/admin/top.asp></frameset></html>")
        if not st["logged"]:
            return self.login_page()
        if p.path == "/boaform/admin/formWlanRedirect":
            idx = int(q["wlan_idx"])
            if idx in st["wlan"]:
                st["idx"] = idx
            self.send_response(302)
            self.send_header("Location", q["redirect-url"])
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        w = st["wlan"][st["idx"]]
        if p.path == "/admin/wlbasic.asp":
            return self.send(f"""<html><form action=/boaform/admin/formWlanSetup method=POST name="wlanSetup">
<input type="checkbox" name="wlanDisabled" value=OFF><select size=1 name=band></select>
<input type=text name=ssid value="{w['ssids'][0]['ssid']}"><input type='checkbox' name='wlHide' value=0>
<input type="hidden" value="/admin/wlbasic.asp" name="submit-url"><input type="hidden" name="basicrates" value=0>
<input type="hidden" name="wlan_idx" value={st['idx']}><input type="hidden" name="Band2G5GSupport" value={w['band']}>
{self.csrf_input()}</form></html>""")
        if p.path == "/admin/wlwpa.asp":
            arrays = "".join(
                f"_wlan_mode[{k}]=0;\n\t_encrypt[{k}]={s['encrypt']};\n\t_enable1X[{k}]=0;\n\t_wpaAuth[{k}]=2;\n"
                f"\t_wpaPSKFormat[{k}]=0;\n\t_wpaPSK[{k}]='{s['psk']}';\n\t_wpaGroupRekeyTime[{k}]='{s['rekey']}';\n"
                f"\t_uCipher[{k}]={s['u']};\n\t_wpa2uCipher[{k}]={s['u2']};\n\t_wlan_isNmode[{k}]=1;\n"
                f"\t_dotIEEE80211W[{k}]={s['dot11w']};\n\t_sha256[{k}]={s['sha']};\n"
                for k, s in enumerate(w["ssids"]))
            opts = "".join(f'<option value="{i}">{s["ssid"]}</option>' for i, s in enumerate(w["ssids"]))
            return self.send(f"""<html><script>var _encrypt=new Array();
{arrays}ssid_num={len(w['ssids'])};</script>
<form action=/boaform/admin/formWlEncrypt method=POST name="formEncrypt">
<input type=hidden name="wlanDisabled" value=OFF><input type=hidden name="isNmode" value=0>
<select name=wpaSSID>{opts}</select><select id="security_method" name="security_method"></select>
<input type="hidden" name="wepEnabled" value="ON" checked>
<input name="wpaAuth" type="radio" value="psk"><input type="checkbox" name="wpa2ciphersuite_a" value=1>
<input type="password" name="pskValue" value=""><input id="radius_ip" name="radiusIP" value="0.0.0.0">
<input type="hidden" value="/admin/wlwpa.asp" name="submit-url">
<input type="hidden" name="wlan_idx" value={st['idx']}>{self.csrf_input()}</form></html>""")
        if p.path == "/boaform/admin/formWirelessTbl":
            idx = int(q.get("wlan_idx", st["idx"]))
            rows = "".join(f"<tr bgcolor=#b7b7b7><td><font size=2>{m}</td><td><font size=2>10</td></tr>"
                           for m in st["wlan"][idx]["clients"]) or \
                "<tr bgcolor=#b7b7b7><td><font size=2>None</td><td><font size=2>---</td></tr>"
            return self.send(f"<html><form action=/boaform/admin/formWirelessTbl><table>{rows}</table></form></html>")
        if p.path == "/admin/wlactrl.asp":
            rows = "".join(f'<tr><td align=center width="45%" bgcolor="#C0C0C0"><font size="2">{m}</td>\n'
                           f'<td align=center width="20%" bgcolor="#C0C0C0"><input type="checkbox" name="select{n}" '
                           f'value="ON"></td></tr>\n' for n, m in w["ac"])
            return self.send(f"""<html><form action=/boaform/admin/formWlAc method=POST name="formWlAcAdd">
<select size="1" name="wlanAcEnabled"><option value=0 >Disabled</option><option value=1 selected >Allow</option>
<option value=2 >Deny</option></select><input type="submit" value="Apply" name="setFilterMode">
<input type="text" name="mac" size="15" maxlength="12"><input type="submit" value="Add" name="addFilterMac">
<input type="hidden" value="/admin/wlactrl.asp" name="submit-url"><input type="hidden" name="wlan_idx" value={st['idx']}>
{self.csrf_input()}</form>
<form action=/boaform/admin/formWlAc method=POST name="formWlAcDel"><table>{rows}</table>
<input type="submit" value="Delete Selected" name="deleteSelFilterMac">
<input type="submit" value="Delete All" name="deleteAllFilterMac">
<input type="hidden" value="/admin/wlactrl.asp" name="submit-url"><input type="hidden" name="wlan_idx" value={st['idx']}>
<input type="hidden" name="csrftoken" value="{st['csrf']}"></form>
<script>document.formWlAcAdd.wlanAcEnabled.selectedIndex={w['ac_mode']}
</script></html>""")
        if p.path == "/admin/top.asp":
            return self.send(f"<html><form action=/boaform/admin/formLogout method=POST>{self.csrf_input()}</form></html>")
        return self.send("nf", 404)

    def err(self, msg):
        return self.send(f"<html><body><h4>ERROR: {msg}</h4><form><input type=button value=OK></form></body></html>")

    def ok(self, url):
        return self.send("<html><head><script>/* change setting successfully */</script></head><body>"
                         + "Change setting successfully!" + " " * 5000
                         + f"<form action={url}><input type=submit value=OK></form></body></html>")

    def do_POST(self):
        st = self.state
        p = urlsplit(self.path)
        form = parse_qsl(self.body(), keep_blank_values=True)
        f = dict(form)
        if p.path == "/boaform/admin/formLogin":
            ok = (f.get("username") == st["user"] and f.get("psd") == st["password"]
                  and f.get("verification_code") == st["code"] and f.get("csrftoken") == st["csrf"])
            if not ok:
                st["fails"] += 1
                return self.login_page()
            st["logged"] = True
            return self.send("<html><script>top.location='/';</script></html>")
        if not st["logged"]:
            return self.login_page()
        if f.get("csrftoken") != st["csrf"]:
            return self.err("csrf token invalid")
        if p.path == "/boaform/admin/formLogout":
            st["logged"] = False
            return self.send("bye")
        st["log"].append((p.path, form))
        idx = int(f.get("wlan_idx", st["idx"]))
        w = st["wlan"][idx]
        if p.path == "/boaform/admin/formWlEncrypt":
            # Lógica de fmwlan.c (SDK Realtek)
            if not f.get("wpaSSID"):
                return self.err("No SSID type")
            s = w["ssids"][int(f["wpaSSID"])]
            if not f.get("security_method"):
                return self.err("No encryption")
            enc = int(f["security_method"])
            s["encrypt"] = enc
            if enc in (2, 6):
                v = 0
                if f.get("ciphersuite_t"):
                    v |= 1 if f["ciphersuite_t"] == "1" else 0
                    v |= 2 if f.get("ciphersuite_a") == "1" else 0
                    v = v or 1
                elif enc == 6:
                    v = 3
                s["u"] = v
            else:
                s["u"] = 0
            if enc in (4, 6):
                v = 0
                if f.get("wpa2ciphersuite_t"):
                    v |= 1 if f["wpa2ciphersuite_t"] == "1" else 0
                    v |= 2 if f.get("wpa2ciphersuite_a") == "1" else 0
                    v = v or 2
                elif enc == 6:
                    v = 3
                elif enc == 4:
                    v = 2
                s["u2"] = v
            else:
                s["u2"] = 0
            if enc == 4:
                if not f.get("dotIEEE80211W"):
                    return self.err("80211w")
                s["dot11w"] = int(f["dotIEEE80211W"])
                if s["dot11w"] == 1:
                    if not f.get("sha256"):
                        return self.err("sha256")
                    s["sha"] = int(f["sha256"])
            if f.get("wpaAuth") == "psk":
                if not f.get("pskFormat"):
                    return self.err("No PSK format")
                if not 0 < len(f.get("pskValue", "")) < 64:
                    return self.err("Invalid PSK value")
                s["psk"] = f["pskValue"]
            if f.get("gk_rekey"):
                s["rekey"] = f["gk_rekey"]
            return self.ok(f.get("submit-url", "/"))
        if p.path == "/boaform/admin/formWlAc":
            if f.get("setFilterMode"):
                w["ac_mode"] = int(f["wlanAcEnabled"][0])
                return self.ok("/admin/wlactrl.asp")
            if f.get("addFilterMac"):
                mac = f.get("mac", "")
                if len(mac) != 12:
                    return self.err("Invalid MAC address")
                mac = ":".join(mac[i:i + 2] for i in range(0, 12, 2)).lower()
                if any(m == mac for _, m in w["ac"]):
                    return self.err("Entry already exists")
                nxt = max([n for _, wl in st["wlan"].items() for n, _ in wl["ac"]] or [-1]) + 1
                w["ac"].append((nxt, mac))
            if f.get("deleteSelFilterMac"):
                before = len(w["ac"])
                w["ac"] = [(n, m) for n, m in w["ac"] if f.get(f"select{n}") != "ON"]
                if len(w["ac"]) == before:
                    return self.err("There is no item selected to delete!")
            return self.ok("/admin/wlactrl.asp")
        return self.send("nf", 404)
