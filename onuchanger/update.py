"""Actualizaciones de Maxs Onu desde el panel Red Maxs Solution (opción «APP Max Fibra»).

El panel publica la última versión subida en una dirección pública:

  GET  {PANEL}/api/v1/app-fibra/version      -> {"disponible": bool, "hay_nueva": bool, ...}
  GET  {PANEL}/api/v1/app-fibra/descargar    -> el APK

Con una versión subida, el JSON trae además el número de versión, las notas y si la
actualización es obligatoria. Los nombres de esos campos se leen de forma tolerante
(version / ultima / ...), y la app compara la versión ella misma: no depende de
`hay_nueva`, salvo que el panel no diga qué versión es.

En Android la descarga la hace el DownloadManager del sistema (sin permisos de
almacenamiento) y luego se abre el instalador; como todas las versiones se firman con
la misma llave, se instala encima de la anterior.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

import requests

PANEL = "https://redmax.maxsolution.pe"
CHECK_URL = PANEL + "/api/v1/app-fibra/version"
DOWNLOAD_URL = PANEL + "/api/v1/app-fibra/descargar"
APK_MIME = "application/vnd.android.package-archive"


@dataclass
class UpdateInfo:
    version: str
    notes: str = ""
    mandatory: bool = False
    url: str = DOWNLOAD_URL
    size: int = 0          # bytes, si el panel lo informa ("tamano")
    sha256: str = ""       # huella del APK, si el panel la informa


def parse_version(text: str) -> tuple[int, ...]:
    """'0.3.14' -> (0, 3, 14); 'v1.2' -> (1, 2). Sin números -> ()."""
    nums = re.findall(r"\d+", str(text or ""))
    t = tuple(int(n) for n in nums[:4])
    while t and t[-1] == 0:      # 1.2.0 == 1.2
        t = t[:-1]
    return t


def is_newer(remote: str, current: str) -> bool:
    r, c = parse_version(remote), parse_version(current)
    return bool(r) and bool(c) and r > c


def _pick(d: dict, *keys, default=None):
    for k in keys:
        if k in d and d[k] not in (None, ""):
            return d[k]
    return default


def _truthy(v) -> bool:
    if isinstance(v, str):
        return v.strip().lower() in ("1", "true", "si", "sí", "yes", "on")
    return bool(v)


def parse_response(data: dict, current: str) -> UpdateInfo | None:
    """Interpreta la respuesta del panel. Devuelve None si no hay nada nuevo que instalar."""
    if not isinstance(data, dict):
        return None
    inner = data.get("version") if isinstance(data.get("version"), dict) else data.get("data")
    d = {**{k: v for k, v in data.items() if not isinstance(v, dict)}, **inner} if isinstance(inner, dict) else data
    if "disponible" in d and not _truthy(d["disponible"]):
        return None
    remote = _pick(d, "version", "ultima_version", "version_nueva", "ultima", "numero", "version_name",
                   "latest", "nombre_version")
    remote = remote if isinstance(remote, (str, int, float)) else None
    if remote is not None:
        if not is_newer(str(remote), current):
            return None
    elif not _truthy(d.get("hay_nueva")):
        return None
    url = _pick(d, "url", "descarga", "url_descarga", "download_url", "apk_url", "apk", "enlace",
                default=DOWNLOAD_URL)
    if not isinstance(url, str) or not url.strip():
        url = DOWNLOAD_URL
    elif url.startswith("/"):
        url = PANEL + url
    if not url.lower().startswith("https://"):
        url = DOWNLOAD_URL       # solo descargas cifradas
    notes = _pick(d, "notas", "cambios", "novedades", "notes", "descripcion", default="")
    try:
        size = int(_pick(d, "tamano", "tamaño", "size", "bytes", default=0) or 0)
    except (TypeError, ValueError):
        size = 0
    sha = str(_pick(d, "sha256", "hash", default="") or "").strip().lower()
    if not re.fullmatch(r"[0-9a-f]{64}", sha):
        sha = ""
    return UpdateInfo(version=str(remote or "nueva"), notes=str(notes or "").strip(),
                      mandatory=_truthy(_pick(d, "obligatoria", "forzar", "mandatory", "required",
                                              default=False)),
                      url=url, size=size, sha256=sha)


def check_update(current: str, timeout: float = 8.0, session=None) -> UpdateInfo | None:
    """Pregunta al panel si hay una versión más nueva que `current`. Sin internet -> None."""
    if not parse_version(current):      # versión "dev" (pruebas en PC): no buscar
        return None
    s = session or requests
    try:
        r = s.get(CHECK_URL, params={"version": current, "app": "maxsonu"}, timeout=timeout,
                  headers={"Accept": "application/json"})
        if r.status_code != 200:
            return None
        return parse_response(r.json(), current)
    except (requests.RequestException, ValueError):
        return None


# --- Descarga (Python puro: funciona igual en el celular y en las pruebas) ---------------
class DownloadError(Exception):
    pass


def download_apk(info: UpdateInfo, dest: str, progress=None, session=None, retries: int = 6,
                 chunk: int = 256 * 1024, timeout: float = 30.0) -> str:
    """Descarga el APK a `dest`. Si la conexión se corta, reanuda desde donde quedó (Range).
    Comprueba tamaño y SHA‑256 cuando el panel los informa. `progress(hechos, total)`."""
    import hashlib
    import os

    s = session or requests
    part = dest + ".part"
    total = info.size or 0
    have = os.path.getsize(part) if os.path.exists(part) else 0
    if total and have > total:
        os.remove(part)
        have = 0
    last_error = None
    for _ in range(retries):
        headers = {"Range": f"bytes={have}-"} if have else {}
        try:
            with s.get(info.url, headers=headers, stream=True, timeout=timeout) as r:
                if r.status_code == 416 and total and have == total:
                    break                                     # ya estaba completo
                if r.status_code not in (200, 206):
                    raise DownloadError(f"El panel respondió {r.status_code}.")
                if r.status_code == 200 and have:             # no aceptó reanudar: desde cero
                    have = 0
                if not total:
                    cl = r.headers.get("Content-Length")
                    if cl and cl.isdigit():
                        total = int(cl) + (have if r.status_code == 206 else 0)
                with open(part, "ab" if have else "wb") as f:
                    for block in r.iter_content(chunk):
                        if not block:
                            continue
                        f.write(block)
                        have += len(block)
                        if progress:
                            progress(have, total)
            if not total or have >= total:
                break
        except (requests.RequestException, OSError) as e:      # corte: reintentar desde `have`
            last_error = e
            import time
            time.sleep(2)
    else:
        raise DownloadError("La descarga se cortó varias veces. Revisa tu internet e inténtalo de nuevo."
                            + (f" ({last_error.__class__.__name__})" if last_error else ""))
    if total and have != total:
        raise DownloadError("La descarga quedó incompleta. Inténtalo de nuevo.")
    if info.sha256:
        h = hashlib.sha256()
        with open(part, "rb") as f:
            for block in iter(lambda: f.read(1024 * 1024), b""):
                h.update(block)
        if h.hexdigest() != info.sha256:
            os.remove(part)
            raise DownloadError("El archivo descargado no coincide con el publicado. Inténtalo de nuevo.")
    os.replace(part, dest)
    return dest


# --- Android: instalar con PackageInstaller -----------------------------------------------
class AndroidInstaller:
    """Instala el APK con PackageInstaller (no hace falta compartir el archivo con otra app).

    Android muestra su ventana «¿Quieres actualizar esta app?»: llega como un intent a
    PythonActivity (onNewIntent) con STATUS_PENDING_USER_ACTION y se abre desde ahí.
    """

    def __init__(self, autoclass=None, bind=None):
        if autoclass is None:
            from jnius import autoclass
        self.ac = autoclass
        self.activity = autoclass("org.kivy.android.PythonActivity").mActivity
        self.sdk = autoclass("android.os.Build$VERSION").SDK_INT
        if bind is None:
            try:
                from android import activity as _act     # módulo "android" de python-for-android
                bind = lambda cb: _act.bind(on_new_intent=cb)
            except Exception:
                bind = None
        if bind is not None:
            bind(self._on_new_intent)
        self.last_status = None
        try:
            from jnius import cast as _cast
            self._cast = _cast
        except Exception:
            self._cast = lambda _name, obj: obj

    def can_install(self) -> bool:
        if self.sdk < 26:
            return True
        return bool(self.activity.getPackageManager().canRequestPackageInstalls())

    def ask_install_permission(self) -> None:
        Intent = self.ac("android.content.Intent")
        Uri = self.ac("android.net.Uri")
        Settings = self.ac("android.provider.Settings")
        self.activity.startActivity(Intent(Settings.ACTION_MANAGE_UNKNOWN_APP_SOURCES,
                                           Uri.parse("package:" + self.activity.getPackageName())))

    def install(self, path: str) -> None:
        import os

        PI = self.ac("android.content.pm.PackageInstaller")
        Params = self.ac("android.content.pm.PackageInstaller$SessionParams")
        Intent = self.ac("android.content.Intent")
        PendingIntent = self.ac("android.app.PendingIntent")
        installer = self.activity.getPackageManager().getPackageInstaller()
        params = Params(Params.MODE_FULL_INSTALL)
        session_id = installer.createSession(params)
        session = installer.openSession(session_id)
        try:
            size = os.path.getsize(path)
            out = session.openWrite("maxsonu.apk", 0, size)
            with open(path, "rb") as f:
                for block in iter(lambda: f.read(256 * 1024), b""):
                    out.write(block, 0, len(block))
            session.fsync(out)
            out.close()
            # El resultado vuelve a esta misma actividad (onNewIntent).
            it = Intent(self.activity, self.activity.getClass())
            it.setAction("com.onuchanger.INSTALL_STATUS")
            it.addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP)
            flags = PendingIntent.FLAG_UPDATE_CURRENT
            if self.sdk >= 31:
                flags |= PendingIntent.FLAG_MUTABLE           # el sistema agrega el estado
            pi = PendingIntent.getActivity(self.activity, 7, it, flags)
            session.commit(pi.getIntentSender())
        except Exception:
            session.abandon()
            raise
        finally:
            session.close()

    def _on_new_intent(self, intent) -> None:
        try:
            if intent is None or intent.getAction() != "com.onuchanger.INSTALL_STATUS":
                return
            PI = self.ac("android.content.pm.PackageInstaller")
            Intent = self.ac("android.content.Intent")
            status = intent.getIntExtra(PI.EXTRA_STATUS, -999)
            self.last_status = status
            if status == PI.STATUS_PENDING_USER_ACTION:
                confirm = intent.getParcelableExtra(Intent.EXTRA_INTENT)
                if confirm is not None:
                    confirm = self._cast("android.content.Intent", confirm)
                    confirm.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                    self.activity.startActivity(confirm)
        except Exception:
            pass
