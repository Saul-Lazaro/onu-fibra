import pytest

from onuchanger import AuthError, NotSupportedError
from onuchanger.base import js_constructors, normalize_mac, validate_ssid, validate_wifi_password
from onuchanger.detect import detect_brand
from onuchanger.drivers.fiberhome import FiberhomeDriver
from onuchanger.drivers.huawei import HuaweiDriver
from onuchanger.drivers.zte import ZteDriver
from onuchanger.service import Connection, block, change_wifi, change_wifi_each, connect, list_devices, unblock

from fakes import (FakeServer, FiberhomeHandler, HuaweiHandler, RealtekHandler, ZteHandler, fiberhome_state,
                   huawei_state, realtek_state, zte_state)
from onuchanger.drivers.realtek import RealtekDriver


@pytest.fixture
def huawei():
    with FakeServer(HuaweiHandler, huawei_state()) as s:
        yield s


@pytest.fixture
def zte():
    with FakeServer(ZteHandler, zte_state()) as s:
        yield s


@pytest.fixture
def realtek():
    with FakeServer(RealtekHandler, realtek_state()) as s:
        yield s


@pytest.fixture
def fiberhome():
    with FakeServer(FiberhomeHandler, fiberhome_state()) as s:
        yield s


# --- utilidades ---------------------------------------------------------------

def test_validations():
    validate_wifi_password("12345678")
    for bad in ("1234567", "x" * 64, "contraseña1"):
        with pytest.raises(ValueError):
            validate_wifi_password(bad)
    validate_ssid("Mi Red-5G")
    for bad in ("", "x" * 33, " espacio", "Señal"):
        with pytest.raises(ValueError):
            validate_ssid(bad)
    assert normalize_mac("aa-bb-cc-dd-ee-ff") == "AA:BB:CC:DD:EE:FF"
    assert normalize_mac("aabbccddeeff") == "AA:BB:CC:DD:EE:FF"


def test_js_constructors_decodes_and_handles_parens():
    js = r'var a = new Array(new stX("a\x2eb","x(y)","q\"z"), new stX("2","3"), null);'
    assert js_constructors(js, "stX") == [["a.b", "x(y)", 'q\\"z'], ["2", "3"]]


# --- detección ---------------------------------------------------------------

def test_detect_brand(huawei, zte, fiberhome, realtek):
    assert detect_brand(huawei.host) == "huawei"
    assert detect_brand(zte.host) == "zte"
    assert detect_brand(fiberhome.host) == "fiberhome"
    assert detect_brand(realtek.host) == "realtek"


# --- Huawei --------------------------------------------------------------------

def test_huawei_wrong_password(huawei):
    with pytest.raises(AuthError):
        HuaweiDriver(huawei.host, "Epuser", "mala").login()


def test_huawei_wifi_and_devices(huawei):
    with HuaweiDriver(huawei.host, "Epuser", "clave123") as d:
        nets = d.get_wifi_networks()
        assert [(n.ssid, n.band) for n in nets] == [("Casa-2G", "2.4GHz"), ("Casa-5G", "5GHz")]
        d.set_wifi(nets[0], ssid="NuevaCasa", password="ClaveNueva2026")
        d.set_wifi(nets[1], password="ClaveNueva2026")
        devs = d.get_devices()
    st = huawei.state
    assert st["wlans"][1] == {"ssid": "NuevaCasa", "enable": "1", "psk": "ClaveNueva2026"}
    assert st["wlans"][5]["ssid"] == "Casa-5G" and st["wlans"][5]["psk"] == "ClaveNueva2026"
    # el envío de solo-clave no incluye SSID
    assert [k for k, _ in st["log"][1][2]] == ["k.PreSharedKey", "x.X_HW_Token"]
    assert [(x.name, x.interface) for x in devs] == [("celular-ana", "2.4GHz"), ("tv-sala", "5GHz")]
    assert st["sid"] is None  # cerró sesión


def test_huawei_block_unblock(huawei):
    with HuaweiDriver(huawei.host, "Epuser", "clave123") as d:
        d.block_device("aa:bb:cc:00:00:02", "tv-sala")
        st = huawei.state
        assert sorted(st["filter"]) == [("SSID-1", "AA:BB:CC:00:00:02"), ("SSID-5", "AA:BB:CC:00:00:02")]
        assert (st["filter_enable"], st["filter_mode"]) == ("1", "0")
        assert [x.blocked for x in d.get_devices()] == [False, True]
        d.unblock_device("AA:BB:CC:00:00:02")
        assert st["filter"] == []


def test_huawei_refuses_whitelist(huawei):
    huawei.state.update(filter_enable="1", filter_mode="1", filter=[("SSID-1", "AA:BB:CC:00:00:01")])
    with HuaweiDriver(huawei.host, "Epuser", "clave123") as d:
        with pytest.raises(NotSupportedError):
            d.block_device("AA:BB:CC:00:00:02")
        assert d.get_blocked() == []
    assert huawei.state["filter"] == [("SSID-1", "AA:BB:CC:00:00:01")]


# --- ZTE -----------------------------------------------------------------------

def test_zte_wrong_password(zte):
    with pytest.raises(AuthError):
        ZteDriver(zte.host, "user", "mala").login()


def test_zte_wifi_change_encrypted(zte):
    with ZteDriver(zte.host, "user", "Zte#1234") as d:
        nets = d.get_wifi_networks()
        assert [(n.id, n.ssid, n.band) for n in nets] == [("DEV.WIFI.AP1", "Hogar", "2.4GHz"),
                                                          ("DEV.WIFI.AP5", "Hogar-5G", "5GHz")]
        d.set_wifi(nets[0], ssid="Hogar Perez", password="SuperClave99")
        d.set_wifi(nets[1], ssid="Hogar Perez 5G")   # solo nombre: conserva la clave actual
    aps = zte.state["aps"]
    assert (aps["DEV.WIFI.AP1"]["ESSID"], aps["DEV.WIFI.AP1"]["psk"]) == ("Hogar Perez", "SuperClave99")
    assert (aps["DEV.WIFI.AP5"]["ESSID"], aps["DEV.WIFI.AP5"]["psk"]) == ("Hogar Perez 5G", "pass5g-old")
    # la clave nunca viaja en claro
    sent = dict(zte.state["log"][0][1])
    assert sent["KeyPassphrase"] != "SuperClave99" and sent["encode"]


def test_zte_open_network_gets_wpa2(zte):
    zte.state["aps"]["DEV.WIFI.AP2"].update(ESSID="Invitados", Enable="1")
    with ZteDriver(zte.host, "user", "Zte#1234") as d:
        guest = next(n for n in d.get_wifi_networks() if n.id == "DEV.WIFI.AP2")
        d.set_wifi(guest, password="invitados123")
    ap = zte.state["aps"]["DEV.WIFI.AP2"]
    assert (ap["BeaconType"], ap["psk"]) == ("11i", "invitados123")


def test_zte_block_unblock(zte):
    with ZteDriver(zte.host, "user", "Zte#1234") as d:
        devs = d.get_devices()
        assert [(x.name, x.interface) for x in devs] == [("laptop", "5GHz"), ("moto-g", "2.4GHz")]
        d.block_device("aa:bb:cc:11:11:11", "moto-g")
        st = zte.state
        assert {r["Interface"] for r in st["rules"]} == {"DEV.WIFI.AP1", "DEV.WIFI.AP5"}
        assert st["policy"] == {"DEV.WIFI.AP1": "Ban", "DEV.WIFI.AP2": "Disabled", "DEV.WIFI.AP5": "Ban"}
        assert [(b.mac, b.name) for b in d.get_blocked()] == [("AA:BB:CC:11:11:11", "moto-g")]
        d.unblock_device("AA:BB:CC:11:11:11")
        assert st["rules"] == []


def test_zte_refuses_allowlist(zte):
    zte.state["policy"]["DEV.WIFI.AP1"] = "Allow"
    with ZteDriver(zte.host, "user", "Zte#1234") as d:
        with pytest.raises(NotSupportedError):
            d.block_device("AA:BB:CC:11:11:11")
    assert zte.state["rules"] == []


# --- FiberHome -----------------------------------------------------------------

def test_fiberhome_wrong_password(fiberhome):
    with pytest.raises(AuthError):
        FiberhomeDriver(fiberhome.host, "user", "mala").login()


def test_fiberhome_devices_and_block(fiberhome):
    with FiberhomeDriver(fiberhome.host, "user", "Fh2024!") as d:
        devs = d.get_devices()
        assert [(x.name, x.ip, x.interface) for x in devs] == [("", "192.168.1.6", "Cable"),
                                                              ("Galaxy-A14", "192.168.1.5", "2.4GHz")]
        d.block_device("AA:BB:CC:33:33:33")
        st = fiberhome.state
        assert (st["enable"], st["mode"], [m for _, m in st["filter"]]) == ("1", "black", ["AA:BB:CC:33:33:33"])
        d.unblock_device("aa:bb:cc:33:33:33")
        assert st["filter"] == []
        with pytest.raises(NotSupportedError):
            d.get_wifi_networks()


def test_fiberhome_legacy_key(fiberhome):
    fiberhome.state["acs"] = "x"          # firmware sin acs_random -> llave fija
    from onuchanger.drivers import fiberhome as fh
    fiberhome.state["acs"] = "000000" + fh.LEGACY_KEY.decode() + "0000000"
    with FiberhomeDriver(fiberhome.host, "user", "Fh2024!") as d:
        assert d.get_blocked() == []


# --- servicio (lo que usa la app) ---------------------------------------------

def test_service_flow_autodetect(huawei):
    conn = Connection(huawei.host, None, "", "clave123")
    ov = connect(conn)
    assert conn.brand_name == "Huawei" and conn.username == "Epuser"
    assert len(ov.networks) == 2 and len(ov.devices) == 2
    res = change_wifi(conn, [(ov.networks[0], "Casa Nueva"), (ov.networks[1], None)], "OtraClave55", "OtraClave55")
    msg = res.message
    assert res.creds == [("Casa Nueva", "OtraClave55"), ("Casa-5G", "OtraClave55")] and not res.cut
    assert "Casa Nueva (2.4GHz: nombre y clave)" in msg and "Casa-5G (5GHz: clave)" in msg
    devs = block(conn, ov.devices[0])
    assert next(x for x in devs if x.mac == ov.devices[0].mac).blocked
    devs = unblock(conn, ov.devices[0])
    assert not any(x.blocked for x in devs)


def test_service_validates_before_touching_onu(huawei):
    conn = Connection(huawei.host, "huawei", "Epuser", "clave123")
    ov = connect(conn)
    with pytest.raises(ValueError):
        change_wifi(conn, [(ov.networks[0], None)], "corta", "corta")
    with pytest.raises(ValueError):
        change_wifi(conn, [(ov.networks[0], None)], "ClaveLarga1", "ClaveLarga2")
    with pytest.raises(ValueError):
        change_wifi(conn, [(ov.networks[0], "Casa-2G")], "", "")
    assert huawei.state["log"] == []


def test_service_password_per_network(huawei):
    conn = Connection(huawei.host, "huawei", "Epuser", "clave123")
    ov = connect(conn)
    n24, n5 = ov.networks
    with pytest.raises(ValueError, match="5GHz"):
        change_wifi_each(conn, [(n24, "Casa-2G", "Clave24aaa", "Clave24aaa"), (n5, "Casa-5G", "Clave5Gaaa", "otra")])
    assert huawei.state["log"] == []
    res = change_wifi_each(conn, [(n24, "Casa-2G", "Clave24aaa", "Clave24aaa"), (n5, "Casa-5G", "Clave5Gaaa", "Clave5Gaaa")])
    assert res.creds == [("Casa-2G", "Clave24aaa"), ("Casa-5G", "Clave5Gaaa")]
    assert "Casa-2G (2.4GHz: clave)" in res.message and "Casa-5G (5GHz: clave)" in res.message
    # Sin clave en una red: esa red no se toca.
    res = change_wifi_each(conn, [(n24, "Casa-2G", "", ""), (n5, "Casa-5G", "Otra5Gclave", "Otra5Gclave")])
    assert "2.4GHz" not in res.message and res.creds == [("Casa-5G", "Otra5Gclave")]


def test_service_reports_wifi_cut(huawei, monkeypatch):
    import requests
    conn = Connection(huawei.host, "huawei", "Epuser", "clave123")
    ov = connect(conn)

    def cut(*a, **kw):
        raise requests.ConnectionError("el router apagó el Wi‑Fi")
    monkeypatch.setattr(HuaweiDriver, "set_wifi", cut)
    res = change_wifi(conn, [(ov.networks[0], None)], "OtraClave55", "OtraClave55")
    assert res.cut and "reinició el Wi‑Fi" in res.message
    assert res.creds == [("Casa-2G", "OtraClave55")]   # igual se ofrece reconectar


def test_service_fiberhome_overview(fiberhome):
    ov = connect(Connection(fiberhome.host, None, "", "Fh2024!"))
    assert ov.networks == [] and "FiberHome" in ov.wifi_note and len(ov.devices) == 2


# --- V-SOL / OptiTimes (Realtek boa) ---------------------------------------------

def test_realtek_wrong_password(realtek):
    with pytest.raises(AuthError):
        RealtekDriver(realtek.host, "admin", "mala").login()


def test_realtek_login_brand_and_networks(realtek):
    with RealtekDriver(realtek.host, "admin", "stdONU101") as d:
        assert d.brand == "V‑SOL"
        nets = d.get_wifi_networks()
    # wlan_idx 0 es 5 GHz en este equipo: la banda sale del equipo, no del índice
    assert [(n.ssid, n.band) for n in nets] == [("Familia-5G", "5GHz"), ("Familia", "2.4GHz"),
                                               ("Invitados", "2.4GHz")]
    assert realtek.state["logged"] is False   # cerró sesión


def test_realtek_password_keeps_security_settings(realtek):
    w = realtek.state["wlan"]
    with RealtekDriver(realtek.host, "admin", "stdONU101") as d:
        nets = {n.ssid: n for n in d.get_wifi_networks()}
        d.set_wifi(nets["Familia-5G"], password="NuevaClave2026")
        d.set_wifi(nets["Familia"], password="NuevaClave2026")
        with pytest.raises(NotSupportedError):
            d.set_wifi(nets["Familia"], ssid="OtroNombre", password="NuevaClave2026")
    s5, s24 = w[0]["ssids"][0], w[1]["ssids"][0]
    # Clave cambiada; WPA2 + PMF opcional + SHA256 intactos en 5 GHz
    assert (s5["psk"], s5["encrypt"], s5["u2"], s5["dot11w"], s5["sha"]) == ("NuevaClave2026", 4, 2, 1, 1)
    # Mixto WPA/WPA2 con TKIP+AES intacto en 2.4 GHz
    assert (s24["psk"], s24["encrypt"], s24["u"], s24["u2"]) == ("NuevaClave2026", 6, 3, 3)
    assert s24["ssid"] == "Familia"


def test_realtek_open_network_gets_wpa2(realtek):
    with RealtekDriver(realtek.host, "admin", "stdONU101") as d:
        guest = next(n for n in d.get_wifi_networks() if n.ssid == "Invitados")
        d.set_wifi(guest, password="invitados99")
    g = realtek.state["wlan"][1]["ssids"][1]
    assert (g["encrypt"], g["u2"], g["psk"]) == (4, 2, "invitados99")


def test_realtek_clients_block_unblock(realtek):
    w = realtek.state["wlan"]
    with RealtekDriver(realtek.host, "admin", "stdONU101") as d:
        devs = d.get_devices()
        assert [(x.mac, x.interface, x.ip) for x in devs] == [("A4:C1:38:00:00:05", "5GHz", "192.168.1.30"),
                                                             ("A4:C1:38:00:00:24", "2.4GHz", "192.168.1.31"),
                                                             ("A4:C1:38:00:00:25", "2.4GHz", "192.168.1.32")]
        d.block_device("a4:c1:38:00:00:24")
        assert (w[0]["ac_mode"], w[1]["ac_mode"]) == (2, 2)      # lista negra en ambas bandas
        assert [m for _, m in w[0]["ac"]] == [m for _, m in w[1]["ac"]] == ["a4:c1:38:00:00:24"]
        assert [x.blocked for x in d.get_devices()] == [False, True, False]
        d.unblock_device("A4:C1:38:00:00:24")
        assert w[0]["ac"] == w[1]["ac"] == []


def test_realtek_refuses_allowlist(realtek):
    realtek.state["wlan"][1].update(ac_mode=1, ac=[(0, "a4:c1:38:00:00:25")])
    with RealtekDriver(realtek.host, "admin", "stdONU101") as d:
        with pytest.raises(NotSupportedError):
            d.block_device("A4:C1:38:00:00:24")
        assert d.get_blocked() == []
    assert realtek.state["wlan"][0]["ac"] == [] and realtek.state["wlan"][0]["ac_mode"] == 0


def test_realtek_service_overview_optitimes():
    with FakeServer(RealtekHandler, realtek_state("OPTICTIMES")) as srv:
        conn = Connection(srv.host, None, "", "stdONU101")
        ov = connect(conn)
        assert conn.brand_name == "OptiTimes" and not ov.can_rename
        assert "solo cambia la clave" in ov.wifi_note and len(ov.networks) == 3
        msg = change_wifi(conn, [(ov.networks[1], None)], "ClaveCasa77", "ClaveCasa77").message
        assert "Familia (2.4GHz: clave)" in msg


# --- verificación del proveedor (igual que mi-router) ----------------------------

from onuchanger import isp


def test_isp_unlock_password(monkeypatch):
    # La contraseña real de técnico no se escribe en el repositorio: se prueba el mecanismo
    # con una de ejemplo y se fija que el hash sea el mismo de mi-router.
    import hashlib
    assert isp._UNLOCK_HASH == "d9e6ace1e6df09c877c513e26eff81734d4f430c69a48450a58c9d8e797e418c"
    assert not isp.check_unlock_password("")
    assert not isp.check_unlock_password("adivinanza")
    monkeypatch.setattr(isp, "_UNLOCK_HASH", hashlib.sha256(isp._UNLOCK_SALT + b"clave-de-prueba").hexdigest())
    assert isp.check_unlock_password("clave-de-prueba")


def test_isp_unreachable_when_ping_fails(monkeypatch):
    monkeypatch.setattr(isp, "_ping", lambda host, timeout: False)
    assert not isp.isp_reachable("10.99.0.1", timeout=1)


def test_isp_ok_when_ping_answers(monkeypatch):
    monkeypatch.setattr(isp, "_ping", lambda host, timeout: True)
    assert isp.isp_reachable("10.99.0.1", timeout=1)


def test_isp_tcp_fallback_only_without_ping(monkeypatch):
    monkeypatch.setattr(isp, "_ping", lambda host, timeout: None)
    monkeypatch.setattr(isp, "_tcp_probe", lambda host, timeout: False)
    assert not isp.isp_reachable("10.99.0.1", timeout=1)
    monkeypatch.setattr(isp, "_tcp_probe", lambda host, timeout: True)
    assert isp.isp_reachable("10.99.0.1", timeout=1)


def test_isp_settings_match_mi_router():
    assert isp.ISP_HOST == "10.99.0.1"
    assert isp.ISP_PHONES == ("996770477", "982877033")
    assert "MaxSolution" in isp.ISP_MESSAGE


# --- solo redes encendidas y reconexión del celular -----------------------------

from onuchanger import android_wifi


def test_only_enabled_networks_are_listed(huawei, zte, realtek):
    huawei.state["wlans"][5]["enable"] = "0"
    ov = connect(Connection(huawei.host, "huawei", "Epuser", "clave123"))
    assert [n.ssid for n in ov.networks] == ["Casa-2G"]
    zte.state["aps"]["DEV.WIFI.AP2"].update(ESSID="Apagada", Enable="0")
    ov = connect(Connection(zte.host, "zte", "user", "Zte#1234"))
    assert [n.ssid for n in ov.networks] == ["Hogar", "Hogar-5G"]
    realtek.state["wlan"][1]["disabled"] = True
    ov = connect(Connection(realtek.host, "realtek", "admin", "stdONU101"))
    assert [n.ssid for n in ov.networks] == ["Familia-5G"]


def test_only_disabled_networks_shows_note(huawei):
    for w in huawei.state["wlans"].values():
        w["enable"] = "0"
    ov = connect(Connection(huawei.host, "huawei", "Epuser", "clave123"))
    assert ov.networks == [] and "encendidas" in ov.wifi_note


@pytest.mark.parametrize("fixture,brand,user,pw,current", [
    ("huawei", "huawei", "Epuser", "clave123", "viejaclave1"),
    ("zte", "zte", "user", "Zte#1234", "pass2g-old"),
])
def test_rename_only_reconnects_with_current_password(request, fixture, brand, user, pw, current):
    srv = request.getfixturevalue(fixture)
    conn = Connection(srv.host, brand, user, pw)
    ov = connect(conn)
    res = change_wifi(conn, [(ov.networks[0], "Nombre Nuevo")], "", "")
    assert res.creds == [("Nombre Nuevo", current)]


def test_realtek_exposes_current_password(realtek):
    ov = connect(Connection(realtek.host, "realtek", "admin", "stdONU101"))
    assert {n.ssid: n.extra.get("psk") for n in ov.networks} == {
        "Familia-5G": "vieja5g123", "Familia": "vieja24g12", "Invitados": None}


class FakeJava:
    """Imitación mínima de las clases Android que usa android_wifi."""

    def __init__(self, sdk):
        self.sdk, self.calls = sdk, []
        fj = self

        class Obj:
            def __init__(self, name, *a):
                self._n = name
                fj.calls.append((name, "new") + a)

            def __getattr__(self, attr):
                if attr.startswith("_"):
                    raise AttributeError(attr)
                def call(*a):
                    fj.calls.append((self._n, attr) + a)
                    if attr == "build":
                        return ("suggestion",) + fj.calls[-2][2:] + fj.calls[-1][2:]
                    if attr == "addNetwork":
                        return 7
                    if attr == "addNetworkSuggestions":
                        return 0
                    return None
                return call

        self.Obj = Obj
        self.wm = Obj("WifiManager")

    def __call__(self, name):
        fj = self
        if name == "android.os.Build$VERSION":
            return type("V", (), {"SDK_INT": self.sdk})
        if name == "org.kivy.android.PythonActivity":
            act = self.Obj("Activity")
            act.getApplicationContext = lambda: type("C", (), {"getSystemService": lambda _s, n: fj.wm})()
            return type("PA", (), {"mActivity": act})
        if name == "android.provider.Settings":
            return type("S", (), {"ACTION_WIFI_ADD_NETWORKS": "ADD_NETS", "EXTRA_WIFI_NETWORK_LIST": "LIST"})
        if name == "android.content.Context":
            return type("Ctx", (), {"WIFI_SERVICE": "wifi"})
        if name == "java.util.ArrayList":
            return lambda: _JList(fj)
        short = name.rsplit(".", 1)[-1]
        return lambda *a: self.Obj(short, *a)


class _JList(list):
    def __init__(self, fj):
        super().__init__()

    def add(self, x):
        self.append(x)


def test_android_11_opens_system_save_dialog():
    j = FakeJava(33)
    msg = android_wifi.save_and_connect([("Casa Nueva", "Clave2026"), ("Casa-5G", "Clave2026")], autoclass=j)
    assert ("WifiNetworkSuggestion$Builder", "setSsid", "Casa Nueva") in j.calls
    assert ("WifiNetworkSuggestion$Builder", "setWpa2Passphrase", "Clave2026") in j.calls
    put = next(c for c in j.calls if c[1] == "putParcelableArrayListExtra")
    assert put[2] == "LIST" and len(put[3]) == 2
    assert any(c[:2] == ("Activity", "startActivity") for c in j.calls)
    assert "Guardar" in msg and "Casa Nueva" in msg


def test_android_10_uses_network_suggestions():
    j = FakeJava(29)
    msg = android_wifi.save_and_connect([("Casa", "Clave2026")], autoclass=j)
    assert any(c[:2] == ("WifiManager", "addNetworkSuggestions") for c in j.calls)
    assert not any(c[1] == "startActivity" for c in j.calls)
    assert "Permitir" in msg


def test_android_9_connects_directly():
    j = FakeJava(28)
    msg = android_wifi.save_and_connect([("Casa", "Clave2026")], autoclass=j)
    names = [c[1] for c in j.calls if c[0] == "WifiManager" and c[1] != "new"]
    assert names == ["addNetwork", "saveConfiguration", "disconnect", "enableNetwork", "reconnect"]
    assert ("WifiManager", "enableNetwork", 7, True) in j.calls
    assert "Conectando" in msg


def test_android_wifi_noop_without_creds_or_android():
    assert android_wifi.save_and_connect([("Casa", "")]) == ""
    assert "Conecta este equipo" in android_wifi.save_and_connect([("Casa", "Clave2026")])


# --- no se puede bloquear el celular donde corre la app ---------------------------

def test_cannot_block_own_phone(huawei):
    conn = Connection(huawei.host, "huawei", "Epuser", "clave123")
    ov = connect(conn)
    phone = next(d for d in ov.devices if d.ip == "192.168.100.10")
    with pytest.raises(ValueError, match="este celular"):
        block(conn, phone, own_ip="192.168.100.10")
    assert huawei.state["filter"] == []
    # con la IP antigua en pantalla pero la ONU ya le asignó la del celular: también se rechaza
    stale = type(phone)(mac=phone.mac, name=phone.name, ip="192.168.100.99")
    with pytest.raises(ValueError, match="este celular"):
        block(conn, stale, own_ip="192.168.100.10")
    assert huawei.state["filter"] == []
    # otro equipo sí se puede bloquear
    other = next(d for d in ov.devices if d.ip != "192.168.100.10")
    devs = block(conn, other, own_ip="192.168.100.10")
    assert next(x for x in devs if x.mac == other.mac).blocked


# --- V‑SOL con código de verificación en imagen ---------------------------------------
from onuchanger.base import CaptchaRequired
from onuchanger.service import disconnect


def _code(img: bytes) -> str:
    return img.split(b"tEXtcode\x00", 1)[1][:4].decode()


def test_realtek_text_code_needs_no_input(realtek):
    conn = Connection(realtek.host, "realtek", "admin", "stdONU101")
    ov = connect(conn)                       # el código viene en la página: no se pide
    assert ov.networks and conn.live is None and conn.pending is None


def test_realtek_image_captcha_flow(realtek):
    realtek.state["captcha_img"] = True
    conn = Connection(realtek.host, "realtek", "admin", "stdONU101")
    with pytest.raises(CaptchaRequired) as e:
        connect(conn)
    assert not e.value.wrong and e.value.ext == "png" and conn.pending is not None
    # Código equivocado: se pide otro con una imagen nueva
    conn.captcha = "0000"
    with pytest.raises(CaptchaRequired) as e2:
        connect(conn)
    assert e2.value.wrong
    conn.captcha = _code(e2.value.image)
    ov = connect(conn)
    assert ov.networks and conn.live is not None
    images = realtek.state["images"]
    # Las acciones siguientes reutilizan la sesión: no vuelven a pedir el código
    devs = list_devices(conn)
    assert devs and realtek.state["images"] == images
    target = next(d for d in devs if not d.blocked)
    after = block(conn, target)
    assert any(d.mac == target.mac and d.blocked for d in after)
    n = ov.networks[0]
    res = change_wifi_each(conn, [(n, None, "NuevaClave99", "NuevaClave99")])
    assert "clave" in res.message and realtek.state["images"] == images
    # Si la sesión vence, se vuelve a pedir el código
    realtek.state["logged"] = False
    with pytest.raises(CaptchaRequired):
        list_devices(conn)
    disconnect(conn)
    assert conn.live is None and conn.pending is None


# --- ZTE con panel antiguo (F670L firmware viejo) -----------------------------------
from fakes import ZteLegacyHandler, zte_legacy_state
from onuchanger.detect import detect_brand


@pytest.fixture
def ztel():
    with FakeServer(ZteLegacyHandler, zte_legacy_state()) as srv:
        yield srv


def test_zte_legacy_detect_and_connect(ztel):
    assert detect_brand(ztel.host) == "zte_legacy"
    conn = Connection(ztel.host, "zte", "admin", "ClaveZTE1")     # elegido «ZTE» a mano
    ov = connect(conn)
    assert conn.brand_key == "zte_legacy" and conn.brand_name == "ZTE"
    assert [(n.ssid, n.band) for n in ov.networks] == [("ZTE-Casa", "2.4GHz"), ("ZTE-Casa-5G", "5GHz")]
    assert {d.name: d.interface for d in ov.devices} == {"celular": "2.4GHz", "tv": "5GHz", "pc": "Cable"}
    assert not ov.can_block if hasattr(ov, "can_block") else True


def test_zte_legacy_change_wifi(ztel):
    conn = Connection(ztel.host, None, "admin", "ClaveZTE1")
    ov = connect(conn)
    n24, n5 = ov.networks
    res = change_wifi_each(conn, [(n24, "Casa-Nueva", "NuevaClave24", "NuevaClave24"),
                                  (n5, None, "NuevaClave5G", "NuevaClave5G")])
    aps = ztel.state["aps"]
    assert aps[0]["ESSID"] == "Casa-Nueva" and aps[0]["KeyPassphrase"] == "NuevaClave24"
    assert aps[4]["KeyPassphrase"] == "NuevaClave5G" and aps[4]["ESSID"] == "ZTE-Casa-5G"
    assert aps[1]["ESSID"] == "ZTE-Invitado"                # las demás redes no se tocan
    assert "Casa-Nueva" in res.message
    name, sent = ztel.state["applies"][0]
    assert sent["IF_ACTION"] == "apply" and sent["_InstID"] == "DEV.WIFI.AP5" and "Frm_ESSID" not in sent


def test_zte_legacy_wrong_password_single_attempt(ztel):
    conn = Connection(ztel.host, "zte", "admin", "mala")
    with pytest.raises(AuthError, match="rechazó"):
        connect(conn)
    assert ztel.state["fails"] == 1                            # un solo intento: no se bloquea


def test_zte_legacy_with_validate_code(ztel):
    ztel.state["captcha"] = True
    conn = Connection(ztel.host, "zte", "admin", "ClaveZTE1")
    with pytest.raises(CaptchaRequired) as e:
        connect(conn)
    assert e.value.image and not e.value.wrong
    conn.captcha = "xxxx"
    with pytest.raises(CaptchaRequired) as e2:
        connect(conn)
    assert e2.value.wrong
    conn.captcha = ztel.state["vcode"]
    ov = connect(conn)
    assert ov.networks and conn.live is not None
    imgs = ztel.state["images"]
    list_devices(conn)
    assert ztel.state["images"] == imgs          # no vuelve a pedir el código
