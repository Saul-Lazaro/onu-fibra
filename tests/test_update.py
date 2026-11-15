from onuchanger import update
from onuchanger.update import AndroidUpdater, check_update, is_newer, parse_response, parse_version


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


def test_android_download_and_install_flow():
    calls = []

    class Obj:
        def __init__(self, name, *a):
            self.name, self.a = name, a

        def __getattr__(self, attr):
            def f(*a):
                calls.append((self.name, attr, a))
                if attr == "getSystemService":
                    return Obj("dm")
                if attr == "enqueue":
                    return 42
                if attr == "query":
                    return Obj("cursor")
                if attr == "moveToFirst":
                    return True
                if attr == "getInt":
                    return 8          # STATUS_SUCCESSFUL
                if attr == "getLong":
                    return 1000
                if attr == "getColumnIndex":
                    return 0
                if attr == "getUriForDownloadedFile":
                    return "content://downloads/42"
                if attr == "getPackageManager":
                    return Obj("pm")
                if attr == "canRequestPackageInstalls":
                    return True
                return None
            return f

    consts = {"DOWNLOAD_SERVICE": "download", "VISIBILITY_VISIBLE_NOTIFY_COMPLETED": 1, "DIRECTORY_DOWNLOADS": "Download",
              "STATUS_SUCCESSFUL": 8, "STATUS_FAILED": 16, "COLUMN_STATUS": "status",
              "COLUMN_BYTES_DOWNLOADED_SO_FAR": "b", "COLUMN_TOTAL_SIZE_BYTES": "t", "ACTION_VIEW": "view",
              "FLAG_GRANT_READ_URI_PERMISSION": 1, "FLAG_ACTIVITY_NEW_TASK": 2, "SDK_INT": 34}

    class Cls:
        def __init__(self, name):
            self.name = name
            if name == "org.kivy.android.PythonActivity":
                self.mActivity = Obj("activity")

        def __getattr__(self, attr):
            if attr in consts:
                return consts[attr]
            return lambda *a: Obj(self.name + "." + attr, *a)

        def __call__(self, *a):
            return Obj(self.name, *a)

    up = AndroidUpdater(autoclass=Cls)
    assert up.can_install()
    up.start(update.UpdateInfo("0.3.15"))
    assert up.download_id == 42
    assert ("android.app.DownloadManager$Request", "setDestinationInExternalFilesDir",
            (up.activity, "Download", "MaxsOnu-v0.3.15.apk")) in [(c[0], c[1], c[2]) for c in calls]
    assert up.progress() == ("done", 100)
    up.install()
    started = [c for c in calls if c[1] == "startActivity"]
    assert started and any(c[1] == "setDataAndType" and c[2] == ("content://downloads/42", update.APK_MIME)
                           for c in calls)
