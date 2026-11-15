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
    return UpdateInfo(version=str(remote or "nueva"), notes=str(notes or "").strip(),
                      mandatory=_truthy(_pick(d, "obligatoria", "forzar", "mandatory", "required",
                                              default=False)),
                      url=url)


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


# --- Android: descargar e instalar --------------------------------------------------------
class AndroidUpdater:
    """Descarga el APK con el DownloadManager y abre el instalador del sistema."""

    def __init__(self, autoclass=None):
        if autoclass is None:
            from jnius import autoclass
        self.ac = autoclass
        self.activity = autoclass("org.kivy.android.PythonActivity").mActivity
        self.dm = self.activity.getSystemService(autoclass("android.content.Context").DOWNLOAD_SERVICE)
        self.download_id = None

    def can_install(self) -> bool:
        """Android 8+: ¿el usuario permitió a Maxs Onu instalar apps?"""
        if self.ac("android.os.Build$VERSION").SDK_INT < 26:
            return True
        return bool(self.activity.getPackageManager().canRequestPackageInstalls())

    def ask_install_permission(self) -> None:
        """Abre Ajustes > «Instalar apps desconocidas» para esta app."""
        Intent = self.ac("android.content.Intent")
        Uri = self.ac("android.net.Uri")
        Settings = self.ac("android.provider.Settings")
        it = Intent(Settings.ACTION_MANAGE_UNKNOWN_APP_SOURCES,
                    Uri.parse("package:" + self.activity.getPackageName()))
        self.activity.startActivity(it)

    def start(self, info: UpdateInfo) -> None:
        Request = self.ac("android.app.DownloadManager$Request")
        Uri = self.ac("android.net.Uri")
        Environment = self.ac("android.os.Environment")
        name = "MaxsOnu-v%s.apk" % re.sub(r"[^0-9A-Za-z._-]", "", info.version or "nueva")
        req = Request(Uri.parse(info.url))
        req.setTitle("Maxs Onu " + (info.version or ""))
        req.setDescription("Descargando la actualización")
        req.setMimeType(APK_MIME)
        req.setNotificationVisibility(Request.VISIBILITY_VISIBLE_NOTIFY_COMPLETED)
        req.setDestinationInExternalFilesDir(self.activity, Environment.DIRECTORY_DOWNLOADS, name)
        self.download_id = self.dm.enqueue(req)

    def progress(self) -> tuple[str, int]:
        """('running'|'done'|'failed', porcentaje)."""
        DM = self.ac("android.app.DownloadManager")
        Query = self.ac("android.app.DownloadManager$Query")
        q = Query()
        q.setFilterById([self.download_id])
        c = self.dm.query(q)
        try:
            if not c.moveToFirst():
                return "failed", 0
            status = c.getInt(c.getColumnIndex(DM.COLUMN_STATUS))
            done = c.getLong(c.getColumnIndex(DM.COLUMN_BYTES_DOWNLOADED_SO_FAR))
            total = c.getLong(c.getColumnIndex(DM.COLUMN_TOTAL_SIZE_BYTES))
        finally:
            c.close()
        pct = int(done * 100 / total) if total > 0 else 0
        if status == DM.STATUS_SUCCESSFUL:
            return "done", 100
        if status == DM.STATUS_FAILED:
            return "failed", pct
        return "running", pct

    def install(self) -> None:
        """Abre el instalador con el APK descargado (URI content:// del DownloadManager)."""
        Intent = self.ac("android.content.Intent")
        uri = self.dm.getUriForDownloadedFile(self.download_id)
        if uri is None:
            raise RuntimeError("No se encontró el archivo descargado.")
        it = Intent(Intent.ACTION_VIEW)
        it.setDataAndType(uri, APK_MIME)
        it.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION | Intent.FLAG_ACTIVITY_NEW_TASK)
        self.activity.startActivity(it)
