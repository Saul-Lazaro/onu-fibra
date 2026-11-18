"""Diagnóstico para ONUs que la app aún no reconoce.

Guarda la página de inicio de sesión de la ONU y los trozos relevantes de su JavaScript
(cómo cifra la contraseña, tokens, código de verificación) para enviarlos al soporte y
ajustar el driver. NO incluye la contraseña y NO intenta iniciar sesión (así no suma
intentos fallidos ni bloquea la ONU).
"""
from __future__ import annotations

import re
from urllib.parse import urljoin, urlparse

import requests

PAGES = ("/", "/admin/login.asp", "/login.asp", "/login.html", "/index.html", "/admin/login_en.asp")
KEYWORDS = re.compile(r"psd|passw|pwd|encrypt|sha|md5|base64|b64|challenge|token|csrf|captcha|"
                      r"check_?code|verif|validat|random|rsa|aes|login|submit|form\.action|\.action\s*=", re.I)
MAX_HTML = 25000
MAX_TOTAL = 60000


def _snippets(js: str, ctx: int = 2, limit: int = 6000) -> str:
    lines = js.splitlines()
    if len(lines) <= 3 and len(js) > 2000:          # JS minificado en una línea: cortar por ';'
        lines = js.replace(";", ";\n").splitlines()
    keep = set()
    for i, ln in enumerate(lines):
        if KEYWORDS.search(ln):
            keep.update(range(max(0, i - ctx), min(len(lines), i + ctx + 1)))
    out, prev = [], -2
    for i in sorted(keep):
        if i != prev + 1:
            out.append("  …")
        out.append(lines[i][:300])
        prev = i
    text = "\n".join(out)
    return text[:limit] + ("\n  …(recortado)" if len(text) > limit else "")


def collect(host: str, brand: str = "", username: str = "", error: str = "", version: str = "",
            timeout: float = 6.0, session=None) -> str:
    base = host if "://" in host else "http://" + host
    base = base.rstrip("/")
    s = session or requests.Session()
    s.verify = False
    out = [f"MaxsFibra {version} · diagnóstico de ONU",
           f"Dirección: {base} · Marca elegida: {brand or 'automática'} · Usuario: {username or '-'}",
           f"Error: {error or '-'}", ""]
    seen_pages, scripts = set(), []
    for p in PAGES:
        try:
            r = s.get(base + p, timeout=timeout, allow_redirects=True)
        except requests.RequestException as e:
            out.append(f"== GET {p}: {e.__class__.__name__}")
            if p == "/":
                break
            continue
        key = (r.url, len(r.text))
        if key in seen_pages or (r.status_code == 404 and p != "/"):
            continue
        seen_pages.add(key)
        hdr = {k: v for k, v in r.headers.items() if k.lower() in ("server", "content-type", "set-cookie",
                                                                      "location", "www-authenticate")}
        out.append(f"== GET {p} -> {r.status_code} {r.url}")
        out.append(f"   cabeceras: {hdr}")
        out.append(f"   cookies: {list(s.cookies.keys())}")
        html = r.text
        out.append(html[:MAX_HTML] + ("\n…(página recortada)" if len(html) > MAX_HTML else ""))
        out.append("")
        for src in re.findall(r"<script[^>]+src=[\"']([^\"']+)", html, re.I):
            url = urljoin(r.url, src)
            if urlparse(url).netloc == urlparse(base).netloc and url not in scripts:
                scripts.append(url)
        for fr in re.findall(r"<i?frame[^>]+src=[\"']([^\"']+)", html, re.I):
            out.append(f"   (frame: {fr})")
        if sum(len(x) for x in out) > MAX_TOTAL:
            break
    for url in scripts[:8]:
        if sum(len(x) for x in out) > MAX_TOTAL:
            out.append("…(más scripts omitidos)")
            break
        try:
            r = s.get(url, timeout=timeout)
            out.append(f"== JS {urlparse(url).path} ({len(r.text)} bytes, líneas relevantes):")
            out.append(_snippets(r.text))
        except requests.RequestException as e:
            out.append(f"== JS {url}: {e.__class__.__name__}")
    text = "\n".join(out)
    return text[:MAX_TOTAL + 5000]


def share_text(text: str, title: str = "Diagnóstico MaxsFibra") -> None:
    """Android: abre «Compartir» (WhatsApp, correo…). Escritorio: copia al portapapeles."""
    import os
    if "ANDROID_ARGUMENT" in os.environ or "ANDROID_PRIVATE" in os.environ:
        from jnius import autoclass
        Intent = autoclass("android.content.Intent")
        activity = autoclass("org.kivy.android.PythonActivity").mActivity
        it = Intent(Intent.ACTION_SEND)
        it.setType("text/plain")
        it.putExtra(Intent.EXTRA_SUBJECT, title)
        it.putExtra(Intent.EXTRA_TEXT, text)
        String = autoclass("java.lang.String")
        activity.startActivity(Intent.createChooser(it, String(title)))
    else:
        from kivy.core.clipboard import Clipboard
        Clipboard.copy(text)
