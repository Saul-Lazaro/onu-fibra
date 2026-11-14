import pytest

from onuchanger import AuthError, NotSupportedError
from onuchanger.base import js_constructors, normalize_mac, validate_ssid, validate_wifi_password
from onuchanger.detect import detect_brand
from onuchanger.drivers.fiberhome import FiberhomeDriver
from onuchanger.drivers.huawei import HuaweiDriver
from onuchanger.drivers.zte import ZteDriver
from onuchanger.service import Connection, block, change_wifi, connect, unblock

from fakes import (FakeServer, FiberhomeHandler, HuaweiHandler, ZteHandler, fiberhome_state, huawei_state,
                   zte_state)


@pytest.fixture
def huawei():
    with FakeServer(HuaweiHandler, huawei_state()) as s:
        yield s


@pytest.fixture
def zte():
    with FakeServer(ZteHandler, zte_state()) as s:
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

def test_detect_brand(huawei, zte, fiberhome):
    assert detect_brand(huawei.host) == "huawei"
    assert detect_brand(zte.host) == "zte"
    assert detect_brand(fiberhome.host) == "fiberhome"


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
