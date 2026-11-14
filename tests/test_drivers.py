import pytest

from onuchanger import AuthError, NotSupportedError
from onuchanger.base import js_constructors, normalize_mac, validate_ssid, validate_wifi_password
from onuchanger.detect import detect_brand
from onuchanger.drivers.fiberhome import FiberhomeDriver
from onuchanger.drivers.huawei import HuaweiDriver
from onuchanger.drivers.zte import ZteDriver
from onuchanger.service import Connection, block, change_wifi, connect, unblock

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
    msg = change_wifi(conn, [(ov.networks[0], "Casa Nueva"), (ov.networks[1], None)], "OtraClave55", "OtraClave55")
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


def test_service_reports_wifi_cut(huawei, monkeypatch):
    import requests
    conn = Connection(huawei.host, "huawei", "Epuser", "clave123")
    ov = connect(conn)

    def cut(*a, **kw):
        raise requests.ConnectionError("el router apagó el Wi‑Fi")
    monkeypatch.setattr(HuaweiDriver, "set_wifi", cut)
    assert "Reconéctate" in change_wifi(conn, [(ov.networks[0], None)], "OtraClave55", "OtraClave55")


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
        assert [(x.mac, x.interface) for x in devs] == [("A4:C1:38:00:00:05", "5GHz"),
                                                       ("A4:C1:38:00:00:24", "2.4GHz"),
                                                       ("A4:C1:38:00:00:25", "2.4GHz")]
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
        msg = change_wifi(conn, [(ov.networks[1], None)], "ClaveCasa77", "ClaveCasa77")
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
