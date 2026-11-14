# Mi ONU de fibra — app Android para Huawei, ZTE, FiberHome, V‑SOL y OptiTimes

App para que el cliente, conectado al Wi‑Fi de su ONU y con el **usuario y la
contraseña de la etiqueta**, pueda:

| | Huawei | ZTE | FiberHome | V‑SOL / OptiTimes |
|---|:---:|:---:|:---:|:---:|
| Cambiar nombre de la red (SSID) | ✅ | ✅ | ⏳ pendiente | ⏳ pendiente |
| Cambiar clave Wi‑Fi | ✅ | ✅ | ⏳ pendiente | ✅ |
| Ver equipos conectados | ✅ | ✅ (Wi‑Fi) | ✅ | ✅ (Wi‑Fi, solo MAC) |
| Bloquear / desbloquear equipos | ✅ filtro MAC Wi‑Fi | ✅ control de acceso Wi‑Fi | ✅ filtro MAC (corta Internet) | ✅ control de acceso Wi‑Fi |

Misma arquitectura que `wifi-changer` (Kivy + Buildozer + GitHub Actions).

## Compilar el APK (sin SDK en tu PC)

1. Crea un repositorio en GitHub y sube **el contenido** de esta carpeta (incluida
   la carpeta oculta `.github`).
2. Pestaña **Actions** → *Compilar APK* arranca solo con cada push (o *Run workflow*).
   Primero corren las pruebas; la primera compilación tarda ~30–40 min, luego usa caché.
3. Descarga el artefacto **onu-fibra-apk** (zip con el .apk) e instálalo en el
   teléfono (activa "Instalar apps de origen desconocido").

En Linux/WSL: `pip install buildozer cython==0.29.34` y `buildozer android debug`.

## Uso en el teléfono

1. Conéctate al Wi‑Fi de la ONU y abre la app: la IP se rellena sola.
2. Escribe usuario y contraseña de la etiqueta (si dejas el usuario vacío se usa
   el típico de la marca: Huawei `Epuser`, ZTE `user`, FiberHome `user`). **Conectar**.
3. **Wi‑Fi**: marca las redes, edita el nombre y/o escribe la clave nueva → *Guardar*.
   Si el teléfono estaba en esa red se desconecta: reconéctate con los datos nuevos.
4. **Equipos**: *Bloquear* / *Desbloquear*. La app marca "(este teléfono)" para
   que el cliente no se bloquee a sí mismo.

## Verificación del proveedor (igual que mi-router)

Al pulsar **Conectar**, la app hace ping a **10.99.0.1** (equipo de la Red
MaxSolution). Si no responde, no entra a la ONU y muestra *Sin conexión con el
proveedor* con los teléfonos 996 770 477 · 982 877 033, un botón de **WhatsApp**
para cada uno y el aviso de que solo es para clientes. Si el teléfono no permite
ping, se usa una prueba TCP como alternativa (`onuchanger/isp.py`, copiado de
mi-router).

**Modo técnico:** el botón *Desbloquear* pide la misma contraseña de técnico que
mi-router (en el código solo está su hash) y deja la app sin verificación en ese
celular hasta desinstalarla. Ante cualquier otro error, el aviso ofrece
**Abrir panel de la ONU** en el navegador.

## Seguridad: qué hace y qué no

- Solo usa la interfaz web local de la ONU con las credenciales del cliente.
  No usa cuentas de superadministrador ni vulnerabilidades.
- Cada cambio relee la configuración y confirma que se aplicó; si no, avisa.
- Si el filtro de la ONU está en **lista blanca**, la app **no toca nada**: añadir
  un equipo ahí lo permitiría en vez de bloquearlo.
- Bloquear en Huawei y ZTE añade una regla en cada red encendida (2.4 y 5 GHz),
  para que el equipo no salte de banda.
- Intentos fallidos: Huawei bloquea ~1 min tras 3 intentos; FiberHome igual. La
  app muestra el mensaje y no reintenta sola.

## Estructura

| Archivo | Rol |
|---|---|
| `onuchanger/base.py` | `OnuDriver` (interfaz), modelos, validaciones, lector de constructores JS |
| `onuchanger/detect.py` | gateway (Android/PC) + detección de marca sin credenciales |
| `onuchanger/drivers/huawei.py` | Huawei: `login.cgi`, `WlanBasic.asp`, `set.cgi`, filtro MAC Wi‑Fi |
| `onuchanger/drivers/zte.py` | ZTE "ThinkLua": `menuView/menuData`, firma `Check` RSA, clave AES, ACL Wi‑Fi |
| `onuchanger/drivers/fiberhome.py` | FiberHome: `/cgi-bin/ajax`, `loginpd` AES, filtro MAC IPv4 |
| `onuchanger/drivers/realtek.py` | V‑SOL / OptiTimes (Realtek "boa"): `formLogin`, `formWlEncrypt`, `formWlAc` |
| `onuchanger/service.py` | operaciones de la interfaz (sin Kivy, testeable) |
| `onuchanger/cli.py` | línea de comandos para probar con equipos reales |
| `main.py` | interfaz Android (Kivy) |
| `tests/` | ONUs simuladas (servidores HTTP reales) + pruebas |

## Probar con una ONU real desde el PC

```bash
pip install -r requirements.txt
python -m onuchanger listar                               # autodetecta IP y marca
python -m onuchanger --marca zte --usuario user wifi --red 1 --nombre "MiRed" --clave
python -m onuchanger bloquear AA:BB:CC:DD:EE:FF
python -m onuchanger desbloquear AA:BB:CC:DD:EE:FF
python -m pytest -q                                       # pruebas con ONUs simuladas
```

**Antes de repartir la app, prueba cada modelo real** (al menos uno por marca y
firmware que tengas en la red): `listar`, cambiar el nombre de una red de prueba
y bloquear/desbloquear un equipo propio.

## Cobertura y límites conocidos

**Huawei.** EchoLife/OptiXstar con `/asp/GetRandCount.asp` (HG8145V5, EG8145V5,
HG8145X6, HG8546M, HG8245H…). Lee `WlanBasic.asp` (rama `amp`) y, si no existe,
`wlanbasic.asp` (rama `bbsp`). Algunos firmwares de operador ocultan el menú
Wi‑Fi a la cuenta de usuario; ahí la app lo indica. Si una red Huawei está
**abierta** (sin seguridad), poner clave desde la app no activa WPA2: hay que
hacerlo una vez en el panel web. ZTE sí la pasa a WPA2 automáticamente.

**ZTE.** Firmwares con `/?_type=loginData` (F670L, F680, F6600P, F6201B,
F660 v6+…). Los paneles antiguos (`getpage.gch`) no están soportados aún.

**V‑SOL / OptiTimes (Realtek "boa").** Un solo driver para las ONUs con SoC
Realtek (RTL9601D/9602C/9607C) y panel `/boaform/admin/…`, que es lo que usan
V‑SOL y OptiTimes. Como cada fabricante personaliza el HTML, el driver lee el
formulario real del equipo (login con `username`/`psd` o `username1`/`psd1`,
`csrftoken`, código de verificación) y lo reenvía cambiando solo lo necesario.
La banda (2.4/5 GHz) se lee del propio equipo. Al cambiar la clave reenvía el
tipo de seguridad, cifrados y PMF actuales (de `_encrypt[k]`, `_wpa2uCipher[k]`…)
y comprueba después que la clave quedó guardada. Una red abierta pasa a WPA2‑AES.
- **Nombre de la red pendiente:** el formulario `formWlanSetup` lleva banda,
  canal, WMM, SSID oculto, etc. que arma el JavaScript de la página; reenviarlo
  mal cambiaría la radio del cliente. Para activarlo hace falta una captura (abajo).
- La lista de equipos de esta página solo trae la MAC (sin nombre ni IP).
- Hecho a partir del SDK Realtek de ONTs y del webroot de un firmware RTL9607C de
  producción; **no probado aún en una V‑SOL ni una OptiTimes reales.**

**Capturas que faltan** (mismo procedimiento para FiberHome y V‑SOL/OptiTimes):

**FiberHome — Wi‑Fi pendiente.** El login, la lista de equipos y el filtro MAC
están documentados públicamente; los métodos `ajaxmethod` de la página Wi‑Fi
no. Para no enviar peticiones adivinadas a equipos de clientes, esa función está
desactivada. Para activarla hace falta **una captura de un equipo real**:

1. En un PC conectado a una FiberHome, entra a `http://192.168.1.1`, inicia sesión.
2. F12 → pestaña **Red** (Network) → marca *Conservar registro*.
3. Ve a la página Wi‑Fi, cambia el nombre de la red a uno de prueba y guarda.
4. Clic derecho en la lista → **Guardar todo como HAR** (o copia la petición
   `POST /cgi-bin/ajax` del guardado y la `GET` que carga la página).
5. Cambia la clave Wi‑Fi del HAR por una falsa antes de compartirlo.

Con eso se completa `drivers/fiberhome.py` (`get_wifi_networks` / `set_wifi`).
Para V‑SOL / OptiTimes: lo mismo, pero en **Wireless → Basic Settings**
(`wlbasic.asp`): cambia el nombre de la red y pulsa *Apply Changes*. Así se
completa el cambio de nombre en `drivers/realtek.py`.

## Fuentes del protocolo

Flujos tomados de proyectos abiertos que los verificaron en equipos reales:
onlypfachi/hg-router-script y MichaelCommitsAt3AM/home_wifi_manager (Huawei:
login, equipos, filtro MAC), tariqahmed78/newage2 y TheIcelandicguy/huawei_ont
(Huawei Wi‑Fi), zxlawdx/acess_manager y juacas/zte_tracker (ZTE login, SSID,
cifrado), Cheikh-Nakamoto/Kergui-Fibre-Manager (ZTE ACL Wi‑Fi),
mcbyte-it/fiberhome_exporter y julesssssssswrld/PLDC (FiberHome),
cubieb/2PORTONT (SDK Realtek de ONTs: `fmwlan.c`, páginas `wl*.asp`),
bhvym-sudo/sharp-wifi (webroot RTL9607C de producción) y nkitsaini/wifi_util
(login Realtek con código de verificación).
