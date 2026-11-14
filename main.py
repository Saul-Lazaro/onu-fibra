"""App Android (Kivy): Wi‑Fi y equipos conectados de ONUs de fibra Huawei, ZTE y FiberHome."""
import os
import socket
import threading
from urllib.parse import quote

from kivy.app import App
from kivy.clock import mainthread
from kivy.core.window import Window
from kivy.lang import Builder
from kivy.metrics import dp
from kivy.properties import BooleanProperty, ListProperty, StringProperty
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.button import Button
from kivy.uix.checkbox import CheckBox
from kivy.uix.label import Label
from kivy.uix.popup import Popup
from kivy.uix.textinput import TextInput

from onuchanger.base import OnuError
from onuchanger.isp import ISP_MESSAGE, ISP_PHONES, WHATSAPP_TEXT, check_unlock_password, isp_reachable
from onuchanger.service import (BRAND_KEYS, USER_HINTS, Connection, block, change_wifi, connect, list_devices,
                                suggest_host, unblock)

Window.softinput_mode = "below_target"  # el teclado no tapa el campo activo

BLUE = (0.13, 0.45, 0.85, 1)
RED = (0.78, 0.22, 0.22, 1)
GREEN = (0.2, 0.6, 0.35, 1)
GREY = (0.3, 0.3, 0.35, 1)

KV = """
#:import dp kivy.metrics.dp

<Field@TextInput>:
    multiline: False
    write_tab: False
    size_hint_y: None
    height: dp(50)
    font_size: "16sp"
    padding: [dp(12), dp(14)]

<Section@Label>:
    size_hint_y: None
    height: dp(34)
    text_size: self.width, None
    halign: "left"
    bold: True
    font_size: "17sp"
    color: 0.65, 0.8, 1, 1

<Hint@Label>:
    size_hint_y: None
    height: self.texture_size[1] + dp(6)
    text_size: self.width, None
    halign: "left"
    font_size: "13sp"
    color: 0.62, 0.62, 0.68, 1

<BigButton@Button>:
    size_hint_y: None
    height: dp(54)
    font_size: "17sp"
    background_normal: ""
    background_color: (0.13, 0.45, 0.85, 1) if not self.disabled else (0.3, 0.3, 0.35, 1)

<LinkButton@Button>:
    size_hint_y: None
    height: dp(32)
    font_size: "14sp"
    background_normal: ""
    background_down: ""
    background_color: 0, 0, 0, 0

<Root>:
    canvas.before:
        Color:
            rgba: 0.08, 0.09, 0.12, 1
        Rectangle:
            pos: self.pos
            size: self.size
    ScrollView:
        do_scroll_x: False
        BoxLayout:
            orientation: "vertical"
            padding: dp(18), dp(24)
            spacing: dp(10)
            size_hint_y: None
            height: self.minimum_height

            Label:
                text: "Mi ONU de fibra"
                font_size: "24sp"
                bold: True
                size_hint_y: None
                height: dp(44)
            Label:
                text: "Huawei · ZTE · FiberHome · V‑SOL · OptiTimes"
                color: 0.6, 0.6, 0.65, 1
                size_hint_y: None
                height: dp(22)

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
                height: dp(50)
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
            LinkButton:
                text: "Abrir panel de la ONU"
                color: 0.65, 0.8, 1, 1
                on_release: root.open_panel()
            LinkButton:
                text: "Modo técnico activo" if root.unlocked else "Desbloquear"
                bold: True
                color: (0.45, 0.85, 0.5, 1) if root.unlocked else (0.62, 0.62, 0.68, 1)
                on_release: root.ask_unlock()

            Label:
                text: root.status
                color: root.status_color
                text_size: self.width, None
                size_hint_y: None
                height: self.texture_size[1] + dp(12)
                halign: "left"

            # ------------------------------------------------ Wi-Fi
            Section:
                text: "2. Nombre y clave del Wi‑Fi" if root.connected else ""
                height: dp(34) if root.connected else 0
            Hint:
                text: root.wifi_note if root.connected else ""
                height: (self.texture_size[1] + dp(6)) if (root.connected and root.wifi_note) else 0
            BoxLayout:
                id: nets
                orientation: "vertical"
                size_hint_y: None
                height: self.minimum_height
                spacing: dp(6)
            BoxLayout:
                # Controles de Wi‑Fi: se pliegan por completo si la marca no lo permite.
                orientation: "vertical"
                spacing: dp(10)
                size_hint_y: None
                height: self.minimum_height if root.can_wifi else 0
                opacity: 1 if root.can_wifi else 0
                disabled: not root.can_wifi
                Field:
                    id: new_pw
                    password: True
                    hint_text: "Nueva clave (8 a 63 caracteres)"
                Field:
                    id: confirm
                    password: True
                    hint_text: "Repite la nueva clave"
                BoxLayout:
                    size_hint_y: None
                    height: dp(40)
                    CheckBox:
                        size_hint_x: None
                        width: dp(44)
                        on_active: new_pw.password = confirm.password = not self.active
                    Label:
                        text: "Mostrar clave"
                        text_size: self.size
                        valign: "middle"
                Hint:
                    text: ("Deja la clave vacía para cambiar solo el nombre. " if root.can_rename else "") + "Al guardar, los equipos conectados se desconectan y deben volver a entrar."
                BigButton:
                    text: "Aplicando…" if root.busy else "Guardar cambios de Wi‑Fi"
                    disabled: root.busy or not root.can_wifi
                    on_release: root.do_change()

            # ------------------------------------------------ Equipos
            Section:
                text: "3. Equipos conectados" if root.connected else ""
                height: dp(34) if root.connected else 0
            Hint:
                text: root.devices_note if root.connected else ""
                height: (self.texture_size[1] + dp(6)) if (root.connected and root.devices_note) else 0
            BoxLayout:
                id: devs
                orientation: "vertical"
                size_hint_y: None
                height: self.minimum_height
                spacing: dp(4)
            BigButton:
                text: "Actualizar lista"
                disabled: root.busy or not root.connected
                opacity: 1 if root.connected else 0
                height: dp(48) if root.connected else 0
                background_color: (0.22, 0.24, 0.3, 1)
                on_release: root.do_refresh()
            Widget:
                size_hint_y: None
                height: dp(30)
"""


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


def _wrap_label(text, color=(0.92, 0.92, 0.95, 1), font_size="15sp", halign="left"):
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
    wifi_note = StringProperty("")
    devices_note = StringProperty("")
    status = StringProperty("Conéctate al Wi‑Fi de tu ONU y escribe el usuario y la contraseña de la etiqueta.")
    status_color = ListProperty([0.8, 0.8, 0.85, 1])

    def __init__(self, **kw):
        super().__init__(**kw)
        self.conn = None
        self.net_rows = []   # (CheckBox, TextInput, WifiNetwork)
        self.my_ip = ""
        self.ids.host.text = suggest_host()
        self.unlocked = _load_unlock()

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
            chat = Button(text=f"WhatsApp {pretty}", size_hint_y=None, height=dp(48),
                          background_normal="", background_color=(0.145, 0.827, 0.400, 1))
            url = f"https://wa.me/51{number}?text={quote(WHATSAPP_TEXT)}"
            chat.bind(on_release=lambda *_, u=url: open_in_browser(u))
            box.add_widget(chat)
        if panel:
            web = Button(text="Abrir panel de la ONU", size_hint_y=None, height=dp(48),
                         background_normal="", background_color=GREY)
            web.bind(on_release=lambda *_: (popup.dismiss(), self.open_panel()))
            box.add_widget(web)
        ok = Button(text="Entendido", size_hint_y=None, height=dp(48), background_normal="", background_color=BLUE)
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
            self._alert("Modo técnico", "La app ya está desbloqueada en este celular: no verifica el "
                        "proveedor hasta que se desinstale.")
            return
        box = BoxLayout(orientation="vertical", padding=dp(12), spacing=dp(10))
        box.add_widget(_wrap_label("Escribe la contraseña de desbloqueo.", color=(0.62, 0.62, 0.68, 1),
                                   font_size="14sp"))
        field = TextInput(password=True, multiline=False, hint_text="contraseña de desbloqueo",
                          size_hint_y=None, height=dp(48), font_size="16sp", padding=[dp(12), dp(13)])
        box.add_widget(field)
        error = _wrap_label("", color=(1, 0.45, 0.4, 1), font_size="13sp")
        box.add_widget(error)
        row = BoxLayout(size_hint_y=None, height=dp(48), spacing=dp(10))
        popup = Popup(title="Desbloquear", content=box, size_hint=(0.88, None), height=dp(290),
                      auto_dismiss=True)
        cancel = Button(text="Cancelar", background_normal="", background_color=GREY)
        ok = Button(text="Desbloquear", background_normal="", background_color=BLUE)

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

    def _msg(self, text, ok=True):
        self.status_color = {True: [0.45, 0.85, 0.5, 1], False: [1, 0.45, 0.4, 1], None: [0.8, 0.8, 0.85, 1]}[ok]
        self.status = text

    def on_brand(self, text):
        key = BRAND_KEYS.get(text)
        self.ids.user.hint_text = USER_HINTS.get(key, "Usuario de la etiqueta (déjalo vacío si no sabes)")

    # --- conectar ----------------------------------------------------------
    def do_connect(self):
        self.connected = self.can_wifi = False
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
            row = BoxLayout(size_hint_y=None, height=dp(50), spacing=dp(6))
            cb = CheckBox(size_hint_x=None, width=dp(40), active=n.enabled)
            band = Label(text=n.band + ("" if n.enabled else "\n(apagada)"), size_hint_x=None, width=dp(74),
                         font_size="14sp", halign="center")
            ti = TextInput(text=n.ssid, multiline=False, write_tab=False, font_size="16sp",
                           padding=[dp(10), dp(14)], hint_text="Nombre de la red",
                           readonly=not ov.can_rename)
            if not ov.can_rename:
                ti.background_color = (0.75, 0.75, 0.78, 1)
            row.add_widget(cb)
            row.add_widget(band)
            row.add_widget(ti)
            self.ids.nets.add_widget(row)
            self.net_rows.append((cb, ti, n))
        self.can_wifi = bool(ov.networks)
        self.can_rename = ov.can_rename
        self._show_devices(ov.devices)
        self.connected = True
        self._msg(f"Conectado a tu ONU {conn.brand_name}.")

    # --- Wi-Fi -------------------------------------------------------------
    def do_change(self):
        changes = [(n, ti.text.strip()) for cb, ti, n in self.net_rows if cb.active]
        if not changes:
            self._msg("Marca al menos una red.", ok=False)
            return
        pw, confirm, conn = self.ids.new_pw.text, self.ids.confirm.text, self.conn
        self._run(lambda: change_wifi(conn, changes, pw, confirm), self._changed, "Guardando en la ONU…")

    def _changed(self, message):
        self.ids.new_pw.text = self.ids.confirm.text = ""
        for cb, ti, n in self.net_rows:
            if cb.active and ti.text.strip():
                n.ssid = ti.text.strip()
        self._msg(message, ok=True)

    # --- equipos -----------------------------------------------------------
    def _show_devices(self, devices):
        box = self.ids.devs
        box.clear_widgets()
        if not devices:
            box.add_widget(Label(text="No hay equipos conectados.", size_hint_y=None, height=dp(36),
                                 color=(0.62, 0.62, 0.68, 1)))
            return
        for d in devices:
            mine = bool(self.my_ip) and d.ip == self.my_ip
            title = d.name or "Equipo sin nombre"
            if mine:
                title += "  (este teléfono)"
            detail = " · ".join(x for x in (d.interface, d.ip, d.mac) if x)
            if d.blocked:
                detail = "BLOQUEADO · " + detail
            row = BoxLayout(size_hint_y=None, height=dp(62), spacing=dp(8), padding=[0, dp(4)])
            lbl = Label(text=f"[b]{_esc(title)}[/b]\n[size=13sp][color=9a9aa8]{_esc(detail)}[/color][/size]",
                        markup=True, halign="left", valign="middle")
            lbl.bind(size=lambda w, s: setattr(w, "text_size", s))
            btn = Button(text="Desbloquear" if d.blocked else "Bloquear", size_hint_x=None, width=dp(118),
                         background_normal="", background_color=GREEN if d.blocked else RED, font_size="15sp")
            btn.bind(on_release=lambda _b, dev=d, m=mine: self._ask(dev, m))
            row.add_widget(lbl)
            row.add_widget(btn)
            box.add_widget(row)

    def _ask(self, dev, mine):
        if self.busy:
            return
        name = dev.name or dev.mac
        if dev.blocked:
            text = f"¿Permitir de nuevo el acceso a {name}?"
        elif mine:
            text = (f"{name} es ESTE teléfono. Si lo bloqueas perderás la conexión y tendrás que "
                    "desbloquearlo desde otro equipo. ¿Bloquear de todas formas?")
        else:
            text = f"¿Bloquear a {name}? No podrá usar tu Wi‑Fi hasta que lo desbloquees."
        content = BoxLayout(orientation="vertical", padding=dp(12), spacing=dp(12))
        msg = Label(text=text, halign="left", valign="top")
        msg.bind(size=lambda w, s: setattr(w, "text_size", (s[0], None)))
        buttons = BoxLayout(size_hint_y=None, height=dp(50), spacing=dp(10))
        popup = Popup(title="Confirmar", content=content, size_hint=(0.9, None), height=dp(260),
                      auto_dismiss=True)
        no = Button(text="Cancelar", background_normal="", background_color=GREY)
        yes = Button(text="Desbloquear" if dev.blocked else "Bloquear", background_normal="",
                     background_color=GREEN if dev.blocked else RED)
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

        self._run(lambda: action(conn, dev), ok, "Aplicando en la ONU…")

    def do_refresh(self):
        conn = self.conn

        def ok(devices):
            self._show_devices(devices)
            self._msg("Lista actualizada.")

        self._run(lambda: list_devices(conn), ok, "Leyendo equipos…")


def _esc(text: str) -> str:
    return text.replace("&", "&amp;").replace("[", "&bl;").replace("]", "&br;")


class OnuApp(App):
    title = "Mi ONU de fibra"

    def build(self):
        Builder.load_string(KV)
        return Root()


if __name__ == "__main__":
    OnuApp().run()
