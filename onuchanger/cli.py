"""CLI para probar en equipos reales desde el PC:

    python -m onuchanger [--host IP] [--marca huawei|zte|fiberhome] [--usuario U] listar
    python -m onuchanger ... wifi --red 1 [--nombre NUEVO] [--clave]
    python -m onuchanger ... bloquear AA:BB:CC:DD:EE:FF
    python -m onuchanger ... desbloquear AA:BB:CC:DD:EE:FF
"""
from __future__ import annotations

import argparse
import getpass
import sys

from .base import OnuError
from .detect import DRIVERS, get_driver


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="onuchanger", description="Wi‑Fi y equipos de ONUs Huawei / ZTE / FiberHome.")
    p.add_argument("--host", help="IP de la ONU (por defecto, el gateway)")
    p.add_argument("--marca", choices=list(DRIVERS), help="Fuerza el driver en vez de autodetectar")
    p.add_argument("--usuario", default="", help="Usuario de la etiqueta")
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("listar", help="Redes Wi‑Fi y equipos conectados")
    w = sub.add_parser("wifi", help="Cambia nombre y/o clave de una red")
    w.add_argument("--red", type=int, required=True, help="Número de la red según 'listar'")
    w.add_argument("--nombre", help="Nuevo nombre (SSID)")
    w.add_argument("--clave", action="store_true", help="Pedir una clave nueva")
    for name in ("bloquear", "desbloquear"):
        sub.add_parser(name).add_argument("mac")
    args = p.parse_args(argv)

    password = getpass.getpass("Contraseña de la etiqueta de la ONU: ")
    try:
        d = get_driver(args.host, args.usuario, password, args.marca)
        print(f"ONU {d.brand} en {d.host} (usuario {d.username})")
        with d:
            if args.cmd == "listar":
                if d.can_change_wifi:
                    for i, n in enumerate(d.get_wifi_networks(), 1):
                        print(f"  [{i}] {n.band:7} {n.ssid!r:34} {'ON ' if n.enabled else 'OFF'} ({n.id})")
                for dev in d.get_devices() + [b for b in d.get_blocked()]:
                    flag = "BLOQUEADO" if dev.blocked else ("en línea" if dev.online else "")
                    print(f"  {dev.mac}  {dev.ip:15} {dev.interface:8} {dev.name[:24]:24} {flag}")
            elif args.cmd == "wifi":
                net = d.get_wifi_networks()[args.red - 1]
                clave = None
                if args.clave:
                    clave = getpass.getpass("Nueva clave Wi‑Fi: ")
                    if clave != getpass.getpass("Repite la clave: "):
                        print("Las claves no coinciden.", file=sys.stderr)
                        return 1
                d.set_wifi(net, ssid=args.nombre, password=clave)
                print("  ✔ Cambio aplicado.")
            elif args.cmd == "bloquear":
                d.block_device(args.mac)
                print("  ✔ Equipo bloqueado.")
            else:
                d.unblock_device(args.mac)
                print("  ✔ Equipo desbloqueado.")
        return 0
    except (OnuError, ValueError) as e:
        print(f"Error: {e}", file=sys.stderr)
        return 2
