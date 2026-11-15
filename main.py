"""Maxs Onu (Kivy): Wi‑Fi y equipos conectados de ONUs de fibra Huawei, ZTE, FiberHome, V‑SOL y OptiTimes."""
import json
import os
import socket
import threading
from urllib.parse import quote

from kivy.app import App
from kivy.clock import Clock, mainthread
from kivy.uix.scrollview import ScrollView
from kivy.core.window import Window
from kivy.factory import Factory
from kivy.lang import Builder
from kivy.metrics import dp
from kivy.properties import BooleanProperty, ListProperty, NumericProperty, StringProperty
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.button import Button
from kivy.uix.checkbox import CheckBox
from kivy.uix.label import Label
from kivy.uix.popup import Popup
from kivy.uix.textinput import TextInput

from onuchanger.android_wifi import save_and_connect
from onuchanger.base import OnuError
from onuchanger.version import VERSION
from onuchanger.isp import ISP_MESSAGE, ISP_PHONES, WHATSAPP_TEXT, check_unlock_password, isp_reachable
from onuchanger.service import (BRAND_KEYS, USER_HINTS, Connection, block, change_wifi_each, connect, list_devices,
                                suggest_host, unblock)

Window.softinput_mode = "below_target"  # el teclado no tapa el campo activo

# Paleta tomada del logo de Group S & M / Max's Solution (verdes), igual que mi-router
BG = (0.945, 0.969, 0.933, 1)       # verde muy claro de fondo
DARK = (0.106, 0.420, 0.208, 1)     # verde oscuro del logo
GREEN = (0.180, 0.620, 0.310, 1)    # verde principal
LIME = (0.553, 0.776, 0.247, 1)     # verde lima del logo
BLUE = GREEN                        # botones principales
RED = (0.839, 0.271, 0.271, 1)
GREY = (0.62, 0.67, 0.63, 1)
SOFT = (0.86, 0.93, 0.83, 1)
TEXT = (0.122, 0.176, 0.141, 1)
MUTED = (0.42, 0.48, 0.44, 1)

KV = """
#:import dp kivy.metrics.dp

#:set BG (0.945, 0.969, 0.933, 1)
#:set DARK (0.106, 0.420, 0.208, 1)
#:set GREEN (0.180, 0.620, 0.310, 1)
#:set LIME (0.553, 0.776, 0.247, 1)
#:set TEXT (0.122, 0.176, 0.141, 1)
#:set MUTED (0.42, 0.48, 0.44, 1)
#:set GRAY (0.70, 0.74, 0.71, 1)

<Popup>:
    background: ""
    background_color: 1, 1, 1, 1
    title_color: 0.106, 0.420, 0.208, 1
    title_size: "19sp"
    separator_color: 0.553, 0.776, 0.247, 1
    separator_height: dp(3)
    overlay_color: 0, 0.12, 0.05, 0.55

<Field@TextInput>:
    multiline: False
    write_tab: False
    size_hint_y: None
    height: dp(48)
    font_size: "16sp"
    padding: [dp(12), dp(13)]
    background_normal: ""
    background_active: ""
    background_disabled_normal: ""
    background_color: (0.93, 0.95, 0.92, 1) if self.disabled else (1, 1, 1, 1)
    foreground_color: TEXT
    disabled_foreground_color: MUTED
    hint_text_color: MUTED
    cursor_color: GREEN
    canvas.after:
        Color:
            rgba: GREEN if self.focus else (0.80, 0.88, 0.78, 1)
        Line:
            width: dp(1.4) if self.focus else dp(1)
            rounded_rectangle: (self.x, self.y, self.width, self.height, dp(12))

<Section@Label>:
    size_hint_y: None
    height: dp(30)
    text_size: self.width, None
    halign: "left"
    bold: True
    font_size: "17sp"
    color: DARK

<Hint@Label>:
    size_hint_y: None
    height: self.texture_size[1] + dp(4)
    text_size: self.width, None
    halign: "left"
    font_size: "13sp"
    color: MUTED

<RoundButton>:
    background_normal: ""
    background_down: ""
    background_disabled_normal: ""
    background_color: 0, 0, 0, 0
    color: 1, 1, 1, 1
    bold: True
    canvas.before:
        Color:
            rgba: GRAY if self.disabled else ((self.bg[0] * 0.85, self.bg[1] * 0.85, self.bg[2] * 0.85, 1) if self.state == "down" else self.bg)
        RoundedRectangle:
            pos: self.pos
            size: self.size
            radius: [self.radius]

<BigButton@RoundButton>:
    size_hint_y: None
    height: dp(50)
    font_size: "17sp"

<SoftButton@RoundButton>:
    bg: 0.86, 0.93, 0.83, 1
    color: DARK
    size_hint_y: None
    height: dp(46)
    font_size: "15sp"

<LinkButton@Button>:
    size_hint_y: None
    height: dp(30)
    font_size: "14sp"
    background_normal: ""
    background_down: ""
    background_color: 0, 0, 0, 0
    color: DARK

<Card>:
    orientation: "vertical"
    size_hint_y: None
    height: self.minimum_height
    padding: dp(16), dp(14)
    spacing: dp(10)
    canvas.before:
        Color:
            rgba: 0, 0.25, 0.1, 0.06
        RoundedRectangle:
            pos: self.x, self.y - dp(2)
            size: self.size
            radius: [dp(18)]
        Color:
            rgba: 1, 1, 1, 1
        RoundedRectangle:
            pos: self.pos
            size: self.size
            radius: [dp(18)]

<Spinner>:
    background_normal: ""
    background_down: ""
    background_color: 0.86, 0.93, 0.83, 1
    color: 0.106, 0.420, 0.208, 1
    bold: True

<SpinnerOption>:
    background_normal: ""
    background_color: 1, 1, 1, 1
    color: 0.122, 0.176, 0.141, 1
    height: dp(46)

<Root>:
    canvas.before:
        Color:
            rgba: BG
        Rectangle:
            pos: self.pos
            size: self.size
    ScrollView:
        do_scroll_x: False
        BoxLayout:
            orientation: "vertical"
            padding: dp(14), dp(14), dp(14), dp(24)
            spacing: dp(12)
            size_hint_y: None
            height: self.minimum_height

            # ---------- encabezado con el logo ----------
            Card:
                padding: dp(12), dp(10), dp(12), dp(12)
                spacing: dp(2)
                Image:
                    source: app.directory + "/logo.png"
                    size_hint_y: None
                    height: dp(120) if not root.connected else dp(72)
                    fit_mode: "contain"
                Label:
                    text: "Maxs Onu"
                    font_size: "24sp"
                    bold: True
                    color: DARK
                    size_hint_y: None
                    height: dp(34)
                Label:
                    text: "Versión " + app.version_text
                    color: GREEN
                    bold: True
                    font_size: "13sp"
                    size_hint_y: None
                    height: dp(18)
                Label:
                    text: "Huawei · ZTE · FiberHome · V‑SOL · OptiTimes"
                    color: MUTED
                    font_size: "13sp"
                    size_hint_y: None
                    height: dp(20)
                Widget:
                    size_hint_y: None
                    height: dp(4)
                    canvas:
                        Color:
                            rgba: LIME
                        RoundedRectangle:
                            pos: self.center_x - dp(40), self.y
                            size: dp(80), dp(4)
                            radius: [dp(2)]

            # ---------- sesión abierta (reemplaza a la tarjeta 1) ----------
            Card:
                opacity: 1 if root.connected else 0
                disabled: not root.connected
                height: self.minimum_height if root.connected else 0
                padding: (dp(16), dp(12)) if root.connected else (0, 0)
                Label:
                    text: root.session_text
                    color: DARK
                    bold: True
                    font_size: "15sp"
                    text_size: self.width, None
                    halign: "center"
                    size_hint_y: None
                    height: self.texture_size[1] + dp(4)
                BoxLayout:
                    size_hint_y: None
                    height: dp(54)
                    spacing: dp(10)
                    RoundButton:
                        text: "Ocultar equipos" if root.devices_open else "Bloquear equipos en la red"
                        bg: 0.839, 0.271, 0.271, 1
                        font_size: "14sp"
                        halign: "center"
                        text_size: self.width - dp(8), None
                        on_release: root.toggle_devices()
                    SoftButton:
                        text: "Cerrar sesión"
                        height: dp(54)
                        font_size: "14sp"
                        on_release: root.logout()

            # ---------- 1. acceso (se oculta una vez iniciada la sesión) ----------
            Card:
                opacity: 0 if root.connected else 1
                disabled: root.connected
                height: 0 if root.connected else self.minimum_height
                padding: (0, 0) if root.connected else (dp(16), dp(14))
                Section:
                    text: "1. Datos de la etiqueta de tu ONU"
                Field:
                    id: host
                    hint_text: "IP de la ONU (ej. 192.168.1.1)"
                    input_filter: lambda t, undo: t if t in "0123456789.:" else ""
                Spinner:
                    id: brand
                    text: "Detectar marca"
                    values: ["Detectar marca", "Huawei", "ZTE", "FiberHome", "V‑SOL", "OptiTimes"]
                    size_hint_y: None
                    height: dp(48)
                    on_text: root.on_brand(self.text)
                Field:
                    id: user
                    hint_text: "Usuario de la etiqueta (déjalo vacío si no sabes)"
                Field:
                    id: admin
                    password: True
                    hint_text: "Contraseña de la etiqueta"
                BigButton:
                    text: "Conectando…" if root.busy and not root.connected else "Conectar"
                    disabled: root.busy
                    on_release: root.do_connect()
                BoxLayout:
                    size_hint_y: None
                    height: dp(44)
                    spacing: dp(10)
                    SoftButton:
                        text: "Abrir panel de la ONU"
                        height: dp(44)
                        font_size: "14sp"
                        on_release: root.open_panel()
                    SoftButton:
                        text: "Modo técnico activo" if root.unlocked else "Desbloquear"
                        height: dp(44)
                        font_size: "14sp"
                        on_release: root.ask_unlock()
                SoftButton:
                    text: "Salir de la aplicación"
                    on_release: root.exit_app()
                LinkButton:
                    text: "Olvidar usuario y contraseña guardados" if root.has_saved else ""
                    height: dp(28) if root.has_saved else 0
                    disabled: not root.has_saved
                    color: MUTED
                    font_size: "13sp"
                    on_release: root.forget_login()

            # ---------- estado ----------
            Label:
                text: root.status
                color: root.status_color
                bold: True
                font_size: "14sp"
                text_size: self.width, None
                size_hint_y: None
                height: self.texture_size[1] + dp(6)
                halign: "center"

            # ---------- 2. Wi-Fi ----------
            Card:
                opacity: 1 if root.connected else 0
                disabled: not root.connected
                height: self.minimum_height if root.connected else 0
                padding: (dp(16), dp(14)) if root.connected else (0, 0)
                Section:
                    text: "2. Nombre y clave del Wi‑Fi"
                Hint:
                    text: root.wifi_note
                    height: (self.texture_size[1] + dp(4)) if root.wifi_note else 0
                BoxLayout:
                    id: nets
                    orientation: "vertical"
                    size_hint_y: None
                    height: self.minimum_height
                    spacing: dp(6)
                Hideable:
                    # Controles de Wi‑Fi: se pliegan por completo si la marca no lo permite.
                    orientation: "vertical"
                    spacing: dp(10)
                    size_hint_y: None
                    height: self.minimum_height if root.can_wifi else 0
                    opacity: 1 if root.can_wifi else 0
                    disabled: not root.can_wifi
                    BoxLayout:
                        size_hint_y: None
                        height: dp(36)
                        CheckBox:
                            size_hint_x: None
                            width: dp(40)
                            color: DARK
                            on_active: root.show_passwords(self.active)
                        Label:
                            text: "Mostrar claves"
                            color: TEXT
                            text_size: self.size
                            valign: "middle"
                    Hint:
                        text: ("Deja la clave vacía para cambiar solo el nombre. " if root.can_rename else "Deja vacía la clave de la red que no quieras cambiar. ") + "Al guardar, el celular se reconecta solo con los datos nuevos; los demás equipos deben volver a entrar."
                    BigButton:
                        text: "Aplicando…" if root.busy else "Guardar cambios de Wi‑Fi"
                        disabled: root.busy or not root.can_wifi
                        on_release: root.do_change()

            # ---------- 3. equipos (se abre con "Bloquear equipos en la red") ----------
            Card:
                id: devcard
                opacity: 1 if (root.connected and root.devices_open) else 0
                disabled: not (root.connected and root.devices_open)
                height: self.minimum_height if (root.connected and root.devices_open) else 0
                padding: (dp(16), dp(14)) if (root.connected and root.devices_open) else (0, 0)
                Section:
                    text: "Equipos en la red"
                Hideable:
                    orientation: "vertical"
                    spacing: dp(8)
                    size_hint_y: None
                    height: self.minimum_height
                    Hint:
                        text: root.devices_note or "Toca Bloquear para que un equipo deje de usar tu Wi‑Fi."
                    BoxLayout:
                        id: devs
                        orientation: "vertical"
                        size_hint_y: None
                        height: self.minimum_height
                        spacing: dp(6)
                    SoftButton:
                        text: "Actualizar lista"
                        disabled: root.busy or not root.devices_open
                        on_release: root.do_refresh()
                    SoftButton:
                        text: "Ocultar equipos"
                        on_release: root.toggle_devices()

            Label:
                text: "Group S & M · Max's Solution E.I.R.L. · Maxs Onu v" + app.version_text
                color: MUTED
                font_size: "12sp"
                size_hint_y: None
                height: dp(20)
"""


class Hideable(BoxLayout):
    """Contenedor que se oculta con opacity 0 / altura 0. Mientras está oculto NO recibe
    toques: en Kivy un widget desactivado se queda con los toques que caen encima, y el
    contenido de una tarjeta plegada sigue ocupando sitio sobre los botones visibles."""

    def _hidden(self):
        return self.opacity == 0 or self.height <= 0

    def on_touch_down(self, touch):
        return False if self._hidden() else super().on_touch_down(touch)

    def on_touch_move(self, touch):
        return False if self._hidden() else super().on_touch_move(touch)

    def on_touch_up(self, touch):
        return False if self._hidden() else super().on_touch_up(touch)


class Card(Hideable):
    """Tarjeta blanca (estilo en el KV)."""


class RoundButton(Button):
    """Botón redondeado (estilo mi-router): `bg` y `radius` se usan en el canvas del KV."""
    bg = ListProperty([0.180, 0.620, 0.310, 1])
    radius = NumericProperty(dp(14))


def _unlock_file():
    """Almacenamiento privado de la app: Android lo borra al desinstalarla (y la copia de
    seguridad está desactivada en buildozer.spec, así que no vuelve al reinstalar)."""
    app = App.get_running_app()
    return os.path.join(app.user_data_dir if app else ".", "desbloqueo_tecnico")


def _load_unlock() -> bool:
    try:
        with open(_unlock_file()) as fh:
            return fh.read().strip() == "1"
    except OSError:
        return False


def _save_unlock() -> None:
    try:
        with open(_unlock_file(), "w") as fh:
            fh.write("1")
    except OSError:
        pass


def _login_file():
    app = App.get_running_app()
    return os.path.join(app.user_data_dir if app else ".", "inicio_sesion.json")


def _load_login() -> dict:
    """Datos de la última sesión correcta (IP, marca, usuario y contraseña de la etiqueta).
    Están en el almacenamiento privado de la app: otras apps no pueden leerlo y se
    borra al desinstalar (la copia de seguridad está desactivada)."""
    try:
        with open(_login_file(), encoding="utf-8") as fh:
            data = json.load(fh)
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def _save_login(data: dict) -> None:
    try:
        with open(_login_file(), "w", encoding="utf-8") as fh:
            json.dump(data, fh)
    except OSError:
        pass


def _clear_login() -> None:
    try:
        os.remove(_login_file())
    except OSError:
        pass


def _clear_unlock() -> None:
    try:
        os.remove(_unlock_file())
    except OSError:
        pass


def open_in_browser(url: str) -> None:
    """Navegador del sistema (Android: Intent ACTION_VIEW; escritorio: webbrowser)."""
    if "ANDROID_ARGUMENT" in os.environ or "ANDROID_PRIVATE" in os.environ:
        from jnius import autoclass
        Intent = autoclass("android.content.Intent")
        Uri = autoclass("android.net.Uri")
        activity = autoclass("org.kivy.android.PythonActivity").mActivity
        activity.startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(url)))
    else:
        import webbrowser
        webbrowser.open(url)


def _wrap_label(text, color=TEXT, font_size="15sp", halign="left"):
    lbl = Label(text=text, color=color, font_size=font_size, halign=halign, valign="middle", size_hint_y=None)
    lbl.bind(width=lambda w, v: setattr(w, "text_size", (v, None)),
             texture_size=lambda w, v: setattr(w, "height", v[1] + dp(2)))
    return lbl


def own_ip(host: str) -> str:
    """IP de este teléfono en la red de la ONU (sin enviar nada)."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect((host.split(":")[0], 80))
            return s.getsockname()[0]
    except OSError:
        return ""


class Root(BoxLayout):
    busy = BooleanProperty(False)
    connected = BooleanProperty(False)
    can_wifi = BooleanProperty(False)
    can_rename = BooleanProperty(True)
    unlocked = BooleanProperty(False)   # modo técnico: no verifica el proveedor (hasta desinstalar)
    has_saved = BooleanProperty(False)  # hay usuario/contraseña guardados
    session_text = StringProperty("")
    devices_open = BooleanProperty(False)
    wifi_note = StringProperty("")
    devices_note = StringProperty("")
    status = StringProperty("Conéctate al Wi‑Fi de tu ONU y escribe el usuario y la contraseña de la etiqueta.")
    status_color = ListProperty(list(MUTED))

    def __init__(self, **kw):
        super().__init__(**kw)
        self.conn = None
        self.net_rows = []   # (nombre, clave, repetir, WifiNetwork)
        self.my_ip = ""
        self.ids.host.text = suggest_host()
        self.unlocked = _load_unlock()
        saved = _load_login()
        if saved.get("password"):
            self.ids.host.text = saved.get("host") or self.ids.host.text
            if saved.get("brand") in self.ids.brand.values:
                self.ids.brand.text = saved["brand"]
            self.ids.user.text = saved.get("user", "")
            self.ids.admin.text = saved["password"]
            self.has_saved = True
            self.status = "Tus datos están guardados: pulsa Conectar."

    # --- utilidades --------------------------------------------------------
    def _run(self, work, on_ok, busy_text="Trabajando…"):
        """Ejecuta `work` fuera del hilo de la interfaz para no congelar la app."""
        self.busy = True
        self._msg(busy_text, ok=None)

        def target():
            try:
                result = work()
            except (OnuError, ValueError) as e:
                self._done(None, str(e))
            except Exception as e:  # red caída, tiempo agotado, respuesta inesperada
                self._done(None, f"No se pudo comunicar con la ONU: {e.__class__.__name__}. "
                                 "Revisa que sigas conectado a su Wi‑Fi.")
            else:
                self._done(lambda: on_ok(result), None)

        threading.Thread(target=target, daemon=True).start()

    @mainthread
    def _done(self, callback, error):
        self.busy = False
        if error:
            self._msg(error, ok=False)
            if error == ISP_MESSAGE:
                self._alert("Sin conexión con el proveedor", error, phones=ISP_PHONES, center=True)
            else:
                self._alert("No se pudo completar", error, panel=not self.connected)
        else:
            callback()

    def _alert(self, title, text, panel=False, phones=(), center=False):
        """Ventana de mensaje. `phones`: botones de WhatsApp; `panel`: abrir el panel web."""
        box = BoxLayout(orientation="vertical", padding=dp(12), spacing=dp(12), size_hint_y=None)
        box.bind(minimum_height=box.setter("height"))
        box.add_widget(_wrap_label(text, halign="center" if center else "left"))
        popup = Popup(title=title, content=box, size_hint=(0.9, None))
        for number in phones:                     # WhatsApp a cada número (Perú: +51)
            pretty = f"{number[:3]} {number[3:6]} {number[6:]}"
            chat = RoundButton(text=f"WhatsApp {pretty}", size_hint_y=None, height=dp(48),
                               bg=(0.145, 0.827, 0.400, 1))
            url = f"https://wa.me/51{number}?text={quote(WHATSAPP_TEXT)}"
            chat.bind(on_release=lambda *_, u=url: open_in_browser(u))
            box.add_widget(chat)
        if panel:
            web = RoundButton(text="Abrir panel de la ONU", size_hint_y=None, height=dp(48),
                              bg=SOFT, color=DARK)
            web.bind(on_release=lambda *_: (popup.dismiss(), self.open_panel()))
            box.add_widget(web)
        ok = RoundButton(text="Entendido", size_hint_y=None, height=dp(48), bg=BLUE)
        ok.bind(on_release=lambda *_: popup.dismiss())
        box.add_widget(ok)
        box.bind(height=lambda *_: setattr(popup, "height", box.height + dp(92)))
        popup.height = box.height + dp(92)
        self._last_alert = popup
        popup.open()

    def open_panel(self):
        """Abre el panel web de la ONU (la IP escrita) en el navegador del celular."""
        host = (self.conn.host if self.connected and self.conn else self.ids.host.text).strip()
        if not host:
            self._alert("Abrir panel", "Escribe primero la IP de la ONU.")
            return
        url = host if host.startswith("http") else f"http://{host}"
        try:
            open_in_browser(url)
            self._msg(f"Abriendo {url} en el navegador…", ok=None)
        except Exception as e:
            self._alert("Abrir panel", f"No se pudo abrir el navegador: {e}")

    def ask_unlock(self):
        """Contraseña de técnico: permite usar la app sin verificar el proveedor."""
        if self.unlocked:
            self._ask_lock()
            return
        box = BoxLayout(orientation="vertical", padding=dp(12), spacing=dp(10))
        box.add_widget(_wrap_label("Escribe la contraseña de desbloqueo.", color=MUTED,
                                   font_size="14sp"))
        field = TextInput(password=True, multiline=False, hint_text="contraseña de desbloqueo",
                          size_hint_y=None, height=dp(48), font_size="16sp", padding=[dp(12), dp(13)])
        box.add_widget(field)
        error = _wrap_label("", color=(1, 0.45, 0.4, 1), font_size="13sp")
        box.add_widget(error)
        row = BoxLayout(size_hint_y=None, height=dp(48), spacing=dp(10))
        popup = Popup(title="Desbloquear", content=box, size_hint=(0.88, None), height=dp(290),
                      auto_dismiss=True)
        cancel = RoundButton(text="Cancelar", bg=GREY)
        ok = RoundButton(text="Desbloquear", bg=BLUE)

        def try_unlock(*_):
            if check_unlock_password(field.text):
                self.unlocked = True
                _save_unlock()
                popup.dismiss()
                self._msg("Modo técnico activo: la app no verificará el proveedor.", ok=True)
            else:
                field.text = ""
                error.text = "Contraseña incorrecta."

        cancel.bind(on_release=lambda *_: popup.dismiss())
        ok.bind(on_release=try_unlock)
        field.bind(on_text_validate=try_unlock)
        row.add_widget(cancel)
        row.add_widget(ok)
        box.add_widget(row)
        self._unlock_popup, self._unlock_field, self._unlock_ok = popup, field, ok
        popup.open()

    def _ask_lock(self):
        """Modo técnico activo: ofrecer salir de él."""
        box = BoxLayout(orientation="vertical", padding=dp(12), spacing=dp(12), size_hint_y=None)
        box.bind(minimum_height=box.setter("height"))
        box.add_widget(_wrap_label("El modo técnico está activo en este celular: la app no verifica la "
                                   "conexión con el proveedor. ¿Quieres salir del modo técnico?"))
        popup = Popup(title="Modo técnico", content=box, size_hint=(0.9, None))
        out = RoundButton(text="Salir del modo técnico", size_hint_y=None, height=dp(48), bg=RED)
        keep = RoundButton(text="Seguir en modo técnico", size_hint_y=None, height=dp(48), bg=SOFT, color=DARK)

        def lock(*_):
            popup.dismiss()
            self.exit_tech_mode()

        out.bind(on_release=lock)
        keep.bind(on_release=lambda *_: popup.dismiss())
        box.add_widget(out)
        box.add_widget(keep)
        box.bind(height=lambda *_: setattr(popup, "height", box.height + dp(92)))
        popup.height = box.height + dp(92)
        self._lock_popup, self._lock_out = popup, out
        popup.open()

    def exit_tech_mode(self):
        _clear_unlock()
        self.unlocked = False
        self._msg("Saliste del modo técnico: la app vuelve a verificar el proveedor.", ok=None)

    def exit_app(self):
        """Cierra la app (en Android termina la actividad)."""
        if self.busy:
            self._msg("Espera a que termine la operación en curso para salir.", ok=False)
            return
        App.get_running_app().stop()

    def _msg(self, text, ok=True):
        self.status_color = {True: list(DARK), False: list(RED), None: list(MUTED)}[ok]
        self.status = text

    def on_brand(self, text):
        key = BRAND_KEYS.get(text)
        self.ids.user.hint_text = USER_HINTS.get(key, "Usuario de la etiqueta (déjalo vacío si no sabes)")

    # --- conectar ----------------------------------------------------------
    def do_connect(self):
        self.connected = self.can_wifi = self.devices_open = False
        self.ids.nets.clear_widgets()
        self.ids.devs.clear_widgets()
        self.net_rows = []
        conn = Connection(self.ids.host.text, BRAND_KEYS[self.ids.brand.text], self.ids.user.text,
                          self.ids.admin.text)
        self.my_ip = own_ip(conn.host)
        skip_isp = self.unlocked

        def work():
            if not skip_isp:
                self._progress("Verificando conexión con el proveedor…")
                if not isp_reachable():
                    raise OnuError(ISP_MESSAGE)
            self._progress("Conectando con la ONU…")
            return connect(conn)

        self._run(work, lambda ov: self._show(conn, ov), "Verificando conexión con el proveedor…")

    @mainthread
    def _progress(self, text):
        self._msg(text, ok=None)

    def _show(self, conn, ov):
        self.conn = conn
        self.ids.user.text = conn.username
        self.wifi_note = ov.wifi_note
        self.devices_note = ov.devices_note
        for n in ov.networks:
            # Cada red con su nombre y sus propios casilleros de clave (sin casilla para
            # apagar la red: la app nunca desactiva el Wi‑Fi).
            box = BoxLayout(orientation="vertical", size_hint_y=None, spacing=dp(6),
                            padding=(0, dp(4), 0, dp(6)))
            box.bind(minimum_height=box.setter("height"))
            title = Label(text=f"Red {n.band}", size_hint_y=None, height=dp(26), font_size="15sp",
                          bold=True, color=DARK, halign="left", valign="middle")
            title.bind(size=title.setter("text_size"))
            box.add_widget(title)
            ti = Factory.Field(text=n.ssid, hint_text="Nombre de la red", readonly=not ov.can_rename)
            if not ov.can_rename:
                ti.background_color = (0.93, 0.95, 0.92, 1)
            pw = Factory.Field(password=True, hint_text=f"Nueva clave {n.band} (8 a 63 caracteres)")
            cf = Factory.Field(password=True, hint_text=f"Repite la nueva clave {n.band}")
            for w in (ti, pw, cf):
                box.add_widget(w)
            self.ids.nets.add_widget(box)
            self.net_rows.append((ti, pw, cf, n))
        self.can_wifi = bool(ov.networks)
        self.can_rename = ov.can_rename
        self._show_devices(ov.devices)
        self.connected = True
        self.session_text = f"Conectado a tu ONU {conn.brand_name} · {conn.host}"
        self._msg(f"Conectado a tu ONU {conn.brand_name}.")
        # Guardar los datos que funcionaron para no tener que escribirlos otra vez.
        _save_login({"host": self.ids.host.text.strip(), "brand": self.ids.brand.text,
                     "user": conn.username, "password": conn.password})
        self.has_saved = True

    def toggle_devices(self):
        self.devices_open = not self.devices_open
        if self.devices_open:
            # Llevar la vista a la lista recién abierta.
            def go(*_):
                sv = next(w for w in self.walk() if isinstance(w, ScrollView))
                sv.scroll_to(self.ids.devcard, padding=dp(10), animate=True)
            Clock.schedule_once(go, 0.15)

    def logout(self):
        """Vuelve a la tarjeta 1 (los datos guardados se conservan)."""
        if self.busy:
            return
        self.connected = self.can_wifi = self.devices_open = False
        self.conn = None
        self.ids.nets.clear_widgets()
        self.ids.devs.clear_widgets()
        self.net_rows = []
        self._msg("Sesión cerrada. Revisa los datos y pulsa Conectar.", ok=None)

    def forget_login(self):
        _clear_login()
        self.has_saved = False
        self.ids.user.text = self.ids.admin.text = ""
        self._msg("Se borraron el usuario y la contraseña guardados.", ok=None)

    # --- Wi-Fi -------------------------------------------------------------
    def show_passwords(self, show):
        for _, pw, cf, _ in self.net_rows:
            pw.password = cf.password = not show

    def do_change(self):
        items = [(n, ti.text.strip(), pw.text, cf.text) for ti, pw, cf, n in self.net_rows]
        if not items:
            return
        conn = self.conn
        self._run(lambda: change_wifi_each(conn, items), self._changed, "Guardando en la ONU…")

    def _changed(self, result):
        for ti, pw, cf, n in self.net_rows:
            pw.text = cf.text = ""
            if ti.text.strip():
                n.ssid = ti.text.strip()
        # Reconectar este celular con los datos nuevos para no perder la conexión.
        try:
            hint = save_and_connect(result.creds)
        except Exception as e:   # sin permiso, API no disponible…
            hint = f"No se pudo reconectar automáticamente ({e.__class__.__name__})."
        if not hint:
            hint = "Conéctate a la red con los datos nuevos desde Ajustes > Wi‑Fi."
        self._msg(result.message + " " + hint, ok=True)

    # --- equipos -----------------------------------------------------------
    def _show_devices(self, devices):
        box = self.ids.devs
        box.clear_widgets()
        if not devices:
            box.add_widget(Label(text="No hay equipos conectados.", size_hint_y=None, height=dp(36),
                                 color=MUTED))
            return
        for d in devices:
            mine = bool(self.my_ip) and d.ip == self.my_ip
            title = d.name or "Equipo sin nombre"
            if mine:
                title += "  (este celular)"
            net = _net_label(d.interface)
            detail = " · ".join(x for x in (d.ip, d.mac) if x)
            if d.blocked:
                detail = "BLOQUEADO · " + detail
            row = BoxLayout(size_hint_y=None, height=dp(80), spacing=dp(8), padding=[0, dp(4)])
            lbl = Label(text=f"[b]{_esc(title)}[/b]\n[size=14sp][b][color=3f9142]{_esc(net)}[/color][/b][/size]"
                             f"\n[size=12sp][color=6b7a70]{_esc(detail)}[/color][/size]",
                        markup=True, halign="left", valign="middle", color=TEXT)
            lbl.bind(size=lambda w, s: setattr(w, "text_size", s))
            row.add_widget(lbl)
            if mine and not d.blocked:
                # El celular donde está la app no se puede bloquear: perdería la conexión.
                row.add_widget(Label(text="Este celular", size_hint_x=None, width=dp(118), bold=True,
                                     font_size="14sp", color=DARK))
            else:
                btn = RoundButton(text="Desbloquear" if d.blocked else "Bloquear", size_hint_x=None,
                                  width=dp(118), bg=GREEN if d.blocked else RED, font_size="15sp",
                                  size_hint_y=None, height=dp(50), pos_hint={"center_y": 0.5})
                btn.bind(on_release=lambda _b, dev=d, m=mine: self._ask(dev, m))
                row.add_widget(btn)
            box.add_widget(row)

    def _ask(self, dev, mine):
        if self.busy:
            return
        name = dev.name or dev.mac
        if dev.blocked:
            text = f"¿Permitir de nuevo el acceso a {name}?"
        elif mine:
            self._alert("No permitido", "Ese equipo es este celular: no se puede bloquear desde la app.")
            return
        else:
            text = f"¿Bloquear a {name}? No podrá usar tu Wi‑Fi hasta que lo desbloquees."
        content = BoxLayout(orientation="vertical", padding=dp(12), spacing=dp(12))
        msg = Label(text=text, halign="left", valign="top", color=TEXT)
        msg.bind(size=lambda w, s: setattr(w, "text_size", (s[0], None)))
        buttons = BoxLayout(size_hint_y=None, height=dp(50), spacing=dp(10))
        popup = Popup(title="Confirmar", content=content, size_hint=(0.9, None), height=dp(260),
                      auto_dismiss=True)
        no = RoundButton(text="Cancelar", bg=GREY)
        yes = RoundButton(text="Desbloquear" if dev.blocked else "Bloquear", bg=GREEN if dev.blocked else RED)
        no.bind(on_release=lambda *_: popup.dismiss())
        yes.bind(on_release=lambda *_: (popup.dismiss(), self._toggle(dev)))
        buttons.add_widget(no)
        buttons.add_widget(yes)
        content.add_widget(msg)
        content.add_widget(buttons)
        popup.open()

    def _toggle(self, dev):
        conn = self.conn
        action = unblock if dev.blocked else block
        verb = "desbloqueado" if dev.blocked else "bloqueado"
        name = dev.name or dev.mac

        def ok(devices):
            self._show_devices(devices)
            self._msg(f"{name} {verb}.")

        my_ip = self.my_ip
        self._run(lambda: action(conn, dev, own_ip=my_ip) if action is block else action(conn, dev), ok,
                  "Aplicando en la ONU…")

    def do_refresh(self):
        conn = self.conn

        def ok(devices):
            self._show_devices(devices)
            self._msg("Lista actualizada.")

        self._run(lambda: list_devices(conn), ok, "Leyendo equipos…")


def _net_label(interface: str) -> str:
    """Por qué red está conectado el equipo, en palabras del cliente."""
    i = (interface or "").replace(" ", "").lower()
    if i.startswith("2.4"):
        return "Conectado a la red 2.4 GHz"
    if i.startswith("5"):
        return "Conectado a la red 5 GHz"
    if i in ("cable", "lan") or i.startswith("lan") or i.startswith("eth"):
        return "Conectado por cable"
    if interface:
        return f"Conectado por {interface}"
    return "Red desconocida (equipo bloqueado)"


def _esc(text: str) -> str:
    return text.replace("&", "&amp;").replace("[", "&bl;").replace("]", "&br;")


class OnuApp(App):
    title = "Maxs Onu"
    version_text = VERSION
    icon = os.path.join(os.path.dirname(os.path.abspath(__file__)), "icon.png")

    def build(self):
        Builder.load_string(KV)
        return Root()


if __name__ == "__main__":
    OnuApp().run()
