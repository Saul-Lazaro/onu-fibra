from onuchanger import update
import hashlib

import pytest
import requests

from onuchanger.update import (AndroidInstaller, DownloadError, UpdateInfo, check_update, download_apk, is_newer,
                              parse_response, parse_version)


def test_versions():
    assert parse_version("0.3.14") == (0, 3, 14) and parse_version("v1.2.0") == (1, 2)
    assert is_newer("0.3.15", "0.3.14") and is_newer("0.4", "0.3.99") and is_newer("0.3.100", "0.3.99")
    assert not is_newer("0.3.14", "0.3.14") and not is_newer("0.3.9", "0.3.14") and not is_newer("x", "0.3.1")


def test_panel_without_versions():
    # Respuesta real del panel mientras no se sube ninguna versión.
    assert parse_response({"disponible": False, "hay_nueva": False}, "0.3.14") is None


def test_panel_with_version_flat_and_nested():
    info = parse_response({"disponible": True, "hay_nueva": True, "version": "0.3.20",
                           "notas": "Arreglos", "obligatoria": 1,
                           "url": "/api/v1/app-fibra/descargar"}, "0.3.14")
    assert info.version == "0.3.20" and info.notes == "Arreglos" and info.mandatory
    assert info.url == "https://redmax.maxsolution.pe/api/v1/app-fibra/descargar"
    info = parse_response({"disponible": True, "version": {"numero": "1.0.0", "cambios": "x"}}, "0.3.14")
    assert info.version == "1.0.0" and not info.mandatory and info.url == update.DOWNLOAD_URL


def test_same_or_older_version_is_ignored_even_if_panel_says_new():
    assert parse_response({"disponible": True, "hay_nueva": True, "version": "0.3.14"}, "0.3.14") is None
    assert parse_response({"disponible": True, "hay_nueva": True, "version": "0.3.2"}, "0.3.14") is None


def test_without_version_number_trusts_hay_nueva_and_only_https():
    info = parse_response({"disponible": True, "hay_nueva": True, "url": "http://otro.sitio/x.apk"}, "0.3.14")
    assert info is not None and info.url == update.DOWNLOAD_URL
    assert parse_response({"disponible": True, "hay_nueva": False}, "0.3.14") is None


def test_check_update_handles_errors_and_dev():
    class S:
        def __init__(self, resp):
            self.resp = resp

        def get(self, url, **kw):
            assert url == update.CHECK_URL and kw["params"]["version"] == "0.3.14"
            if isinstance(self.resp, Exception):
                raise self.resp
            return self.resp

    class R:
        status_code = 200

        def json(self):
            return {"disponible": True, "version": "0.3.15"}

    import requests
    assert check_update("0.3.14", session=S(R())).version == "0.3.15"
    assert check_update("0.3.14", session=S(requests.ConnectionError())) is None
    assert check_update("dev", session=S(R())) is None


def test_panel_real_response_with_size_and_hash():
    data = {"disponible": True, "version": "0.3.16", "hay_nueva": True, "obligatoria": False, "notas": None,
            "tamano": 49579028, "sha256": "3e409412d7c61b4588a801aefededb047e85187a8444062b4ae2fc1710689646",
            "fecha": "2026-11-15T03:40:19-05:00", "url": "https://redmax.maxsolution.pe/api/v1/app-fibra/descargar"}
    info = parse_response(data, "0.3.15")
    assert info.version == "0.3.16" and info.size == 49579028 and info.sha256.startswith("3e4094")
    assert info.notes == "" and not info.mandatory and info.url == update.DOWNLOAD_URL
    assert parse_response(data, "0.3.16") is None


class _Resp:
    def __init__(self, status, body, headers=None, cut_after=None):
        self.status_code, self.body, self.headers, self.cut_after = status, body, headers or {}, cut_after

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def iter_content(self, n):
        sent = 0
        for i in range(0, len(self.body), n):
            if self.cut_after is not None and sent >= self.cut_after:
                raise requests.ConnectionError("se cortó")
            block = self.body[i:i + n]
            sent += len(block)
            yield block


class _Server:
    """Sirve `data` con soporte de Range; la primera respuesta se corta a la mitad."""

    def __init__(self, data, cut_first=True, accept_range=True):
        self.data, self.cut, self.accept_range, self.calls = data, cut_first, accept_range, []

    def get(self, url, headers=None, stream=False, timeout=None):
        rng = (headers or {}).get("Range")
        self.calls.append(rng)
        start = int(rng.split("=")[1].rstrip("-")) if rng and self.accept_range else 0
        body = self.data[start:]
        cut = len(body) // 2 if self.cut else None
        self.cut = False
        return _Resp(206 if start else 200, body, {"Content-Length": str(len(body))}, cut_after=cut)


def test_download_resumes_after_cut_and_checks_hash(tmp_path, monkeypatch):
    monkeypatch.setattr("time.sleep", lambda s: None)
    data = bytes(range(256)) * 4000                     # ~1 MB
    info = UpdateInfo("0.3.17", size=len(data), sha256=hashlib.sha256(data).hexdigest(), url=update.DOWNLOAD_URL)
    seen = []
    srv = _Server(data)
    out = download_apk(info, str(tmp_path / "a.apk"), progress=lambda d, t: seen.append((d, t)), session=srv,
                       chunk=64 * 1024)
    assert open(out, "rb").read() == data
    assert srv.calls[0] is None and srv.calls[1].startswith("bytes=") and srv.calls[1] != "bytes=0-"
    assert seen[-1] == (len(data), len(data))


def test_download_without_range_support_restarts(tmp_path, monkeypatch):
    monkeypatch.setattr("time.sleep", lambda s: None)
    data = b"PK" + b"x" * 300000
    info = UpdateInfo("1", size=len(data), sha256=hashlib.sha256(data).hexdigest())
    out = download_apk(info, str(tmp_path / "b.apk"), session=_Server(data, accept_range=False), chunk=50000)
    assert open(out, "rb").read() == data


def test_download_rejects_wrong_hash(tmp_path, monkeypatch):
    monkeypatch.setattr("time.sleep", lambda s: None)
    data = b"PK" + b"y" * 1000
    info = UpdateInfo("1", size=len(data), sha256="0" * 64)
    with pytest.raises(DownloadError, match="no coincide"):
        download_apk(info, str(tmp_path / "c.apk"), session=_Server(data, cut_first=False))
    assert not (tmp_path / "c.apk").exists()


def test_installer_writes_session_and_opens_confirmation(tmp_path):
    calls = []
    apk = tmp_path / "x.apk"
    apk.write_bytes(b"PK" + b"z" * 600000)

    class Obj:
        def __init__(self, name):
            self.name = name

        def __getattr__(self, attr):
            def f(*a):
                calls.append((self.name, attr, a))
                return {"getPackageManager": Obj("pm"), "getPackageInstaller": Obj("installer"),
                        "createSession": 5, "openSession": Obj("session"), "openWrite": Obj("out"),
                        "getClass": "cls", "getIntentSender": "sender", "canRequestPackageInstalls": True,
                        "getAction": "com.onuchanger.INSTALL_STATUS", "getIntExtra": -1,
                        "getParcelableExtra": Obj("confirm")}.get(attr)
            return f

    consts = {"SDK_INT": 34, "MODE_FULL_INSTALL": 1, "FLAG_ACTIVITY_SINGLE_TOP": 1, "FLAG_UPDATE_CURRENT": 2,
              "FLAG_MUTABLE": 4, "EXTRA_STATUS": "st", "STATUS_PENDING_USER_ACTION": -1, "EXTRA_INTENT": "ei",
              "FLAG_ACTIVITY_NEW_TASK": 8}

    class Cls:
        def __init__(self, name):
            self.name = name
            if name.endswith("PythonActivity"):
                self.mActivity = Obj("activity")

        def __getattr__(self, attr):
            if attr in consts:
                return consts[attr]
            return lambda *a: (calls.append((self.name, attr, a)), Obj(self.name + "." + attr))[1]

        def __call__(self, *a):
            return Obj(self.name)

    bound = []
    inst = AndroidInstaller(autoclass=Cls, bind=bound.append)
    assert inst.can_install() and bound
    inst.install(str(apk))
    written = sum(a[2] for n, m, a in calls if n == "out" and m == "write")
    assert written == apk.stat().st_size
    assert ("session", "commit", ("sender",)) in calls
    assert any(m == "getActivity" and a[3] == 2 | 4 for n, m, a in calls)
    bound[0](Obj("intent"))                       # Android pide confirmación al usuario
    assert ("activity", "startActivity", ) in [(n, m) for n, m, a in calls if m == "startActivity"]
