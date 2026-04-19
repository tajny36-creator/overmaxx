#!/usr/bin/env python3
"""
Discover Tuya/SmartLife camera device IDs using QR login flow from ipc-*.ismartlife.me.

Flow:
1) GET /login to fetch CSRF token
2) POST /api/qrcode/token
3) POST /api/qrcode to get PNG QR code
4) Poll /api/qrcode/valid/v2 until app confirms login
5) Query device list endpoints and print name=device_id lines

This helper is intended to simplify populating `device_map` for the
`overmax_go2rtc_bridge` integration.
"""

from __future__ import annotations

import argparse
import base64
import http.cookiejar
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import webbrowser
from dataclasses import dataclass
from pathlib import Path
from typing import Any


DEFAULT_HOST = "ipc-eu.ismartlife.me"


@dataclass
class SessionContext:
    opener: urllib.request.OpenerDirector
    cookiejar: http.cookiejar.CookieJar
    csrf: str
    host: str


def _build_opener() -> tuple[urllib.request.OpenerDirector, http.cookiejar.CookieJar]:
    jar = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
    opener.addheaders = [
        ("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"),
    ]
    return opener, jar


def _parse_json(raw: bytes) -> dict[str, Any]:
    try:
        return json.loads(raw.decode("utf-8", errors="ignore"))
    except json.JSONDecodeError:
        return {}


def _request(
    opener: urllib.request.OpenerDirector,
    method: str,
    url: str,
    headers: dict[str, str] | None = None,
    body: dict[str, Any] | None = None,
    timeout: float = 20.0,
) -> tuple[int, bytes]:
    data = None
    req_headers = dict(headers or {})

    if body is not None:
        data = json.dumps(body).encode("utf-8")
        req_headers.setdefault("Content-Type", "application/json; charset=utf-8")

    req = urllib.request.Request(url=url, data=data, headers=req_headers, method=method.upper())

    try:
        with opener.open(req, timeout=timeout) as resp:
            return resp.getcode(), resp.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read() or b""


def _extract_csrf(html: str) -> str:
    match = re.search(r'window\.csrf="([^"]+)"', html)
    return match.group(1) if match else ""


def _new_session(host: str) -> SessionContext:
    opener, jar = _build_opener()
    login_url = f"https://{host}/login"
    code, raw = _request(opener, "GET", login_url, timeout=20.0)
    if code != 200:
        raise RuntimeError(f"Cannot open {login_url} (HTTP {code})")

    html = raw.decode("utf-8", errors="ignore")
    csrf = _extract_csrf(html)
    if not csrf:
        raise RuntimeError("Cannot extract CSRF token from login page.")

    return SessionContext(opener=opener, cookiejar=jar, csrf=csrf, host=host)


def _api_headers(ctx: SessionContext, app_id: str | None = None) -> dict[str, str]:
    headers = {
        "Content-Type": "application/json; charset=utf-8",
        "X-Requested-With": "XMLHttpRequest",
        "Cache-Control": "no-cache",
        "Pragma": "no-cache",
        "csrf-token": ctx.csrf,
        "Origin": f"https://{ctx.host}",
        "Referer": f"https://{ctx.host}/login",
    }
    if app_id:
        headers["x-ty-appid"] = str(app_id)
    return headers


def _api_post(
    ctx: SessionContext,
    path: str,
    body: dict[str, Any],
    app_id: str | None = None,
    timeout: float = 20.0,
) -> tuple[int, dict[str, Any]]:
    url = f"https://{ctx.host}{path}"
    code, raw = _request(
        ctx.opener,
        "POST",
        url=url,
        headers=_api_headers(ctx, app_id=app_id),
        body=body,
        timeout=timeout,
    )
    return code, _parse_json(raw)


def _set_token_cookie(ctx: SessionContext, token_id: str) -> None:
    cookie = http.cookiejar.Cookie(
        version=0,
        name="tokenId",
        value=token_id,
        port=None,
        port_specified=False,
        domain=ctx.host,
        domain_specified=True,
        domain_initial_dot=False,
        path="/",
        path_specified=True,
        secure=True,
        expires=None,
        discard=True,
        comment=None,
        comment_url=None,
        rest={},
        rfc2109=False,
    )
    ctx.cookiejar.set_cookie(cookie)


def _extract_qr_data_url(result: Any) -> str:
    if isinstance(result, str) and result.startswith("data:image/"):
        return result
    return ""


def _save_data_uri_png(data_uri: str, output_path: Path) -> None:
    prefix = "data:image/png;base64,"
    if not data_uri.startswith(prefix):
        raise ValueError("Unexpected QR payload (not PNG data URI).")
    raw = base64.b64decode(data_uri[len(prefix) :])
    output_path.write_bytes(raw)


def _walk_collect_devices(value: Any, out: list[dict[str, str]]) -> None:
    if isinstance(value, dict):
        device_id = value.get("deviceId") or value.get("devId")
        device_name = value.get("deviceName") or value.get("name")
        if isinstance(device_id, str) and device_id:
            out.append({"device_id": device_id, "device_name": str(device_name or device_id)})
        for v in value.values():
            _walk_collect_devices(v, out)
    elif isinstance(value, list):
        for item in value:
            _walk_collect_devices(item, out)


def _dedupe_devices(items: list[dict[str, str]]) -> list[dict[str, str]]:
    out: list[dict[str, str]] = []
    seen: set[str] = set()
    for item in items:
        did = item["device_id"]
        if did in seen:
            continue
        seen.add(did)
        out.append(item)
    return out


def _fetch_devices(ctx: SessionContext, app_id: str) -> list[dict[str, str]]:
    endpoints = [
        "/api/v3/device/list/nvr",
        "/api/device/list/nvr",
        "/api/v3/device/list",
        "/api/device/list",
        "/api/v2/device/list",
        "/api/v2/device/shared/list",
        "/api/device/shared/list",
    ]

    found: list[dict[str, str]] = []
    for ep in endpoints:
        code, payload = _api_post(ctx, ep, body={}, app_id=app_id, timeout=20.0)
        if code == 401:
            continue
        if code >= 400:
            continue
        if not payload.get("success", True):
            continue
        _walk_collect_devices(payload.get("result"), found)

    return _dedupe_devices(found)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Discover Tuya camera IDs via QR login from ipc-*.ismartlife.me"
    )
    parser.add_argument(
        "--host",
        default=DEFAULT_HOST,
        help=f"Portal host (default: {DEFAULT_HOST})",
    )
    parser.add_argument(
        "--qr-out",
        default="tuya_qr_login.png",
        help="Where to save QR PNG image (default: ./tuya_qr_login.png)",
    )
    parser.add_argument(
        "--open-qr",
        action="store_true",
        help="Open generated QR image in default viewer/browser",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=300,
        help="Max wait time for QR scan in seconds (default: 300)",
    )
    parser.add_argument(
        "--interval",
        type=float,
        default=4.0,
        help="Polling interval for QR validation in seconds (default: 4.0)",
    )
    parser.add_argument(
        "--device-map-out",
        help="Optional output file for name=device_id lines",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    host = args.host.strip()
    if not host:
        print("Host cannot be empty.", file=sys.stderr)
        return 2

    try:
        ctx = _new_session(host)
    except Exception as exc:
        print(f"[!] Cannot initialize session: {exc}", file=sys.stderr)
        return 1

    code, token_payload = _api_post(
        ctx,
        "/api/qrcode/token",
        body={"crossRegionSupport": "redirect"},
        timeout=20.0,
    )
    if code >= 400 or not token_payload.get("success"):
        print(f"[!] QR token request failed (HTTP {code}): {token_payload}", file=sys.stderr)
        return 1

    token = str(token_payload.get("result") or "")
    if not token:
        print("[!] Empty token in QR token response.", file=sys.stderr)
        return 1

    code, qr_payload = _api_post(
        ctx,
        "/api/qrcode",
        body={"url": f"tuyaSmart--qrLogin?token={token}"},
        timeout=20.0,
    )
    if code >= 400 or not qr_payload.get("success"):
        print(f"[!] QR image request failed (HTTP {code}): {qr_payload}", file=sys.stderr)
        return 1

    qr_data_uri = _extract_qr_data_url(qr_payload.get("result"))
    if not qr_data_uri:
        print(f"[!] Unexpected QR payload: {qr_payload}", file=sys.stderr)
        return 1

    qr_out = Path(args.qr_out).resolve()
    qr_out.parent.mkdir(parents=True, exist_ok=True)
    _save_data_uri_png(qr_data_uri, qr_out)
    print(f"[+] QR saved: {qr_out}")
    print("[+] Scan the QR with Tuya Smart / Smart Life app.")
    if args.open_qr:
        webbrowser.open(qr_out.as_uri())

    deadline = time.time() + max(15, int(args.timeout))
    app_id = ""
    while time.time() < deadline:
        code, valid_payload = _api_post(
            ctx,
            "/api/qrcode/valid/v2",
            body={"token": token},
            timeout=20.0,
        )
        if code >= 400:
            print(f"[!] QR status check failed (HTTP {code}): {valid_payload}", file=sys.stderr)
            return 1

        result = valid_payload.get("result") or {}
        user_session = result.get("userSessionVO") or {}
        sid = str(user_session.get("sid") or "")
        app_id = str(result.get("appId") or "")
        redirect_region = result.get("redirectRegion")

        if redirect_region:
            print(f"[!] Region redirect required: {redirect_region}", file=sys.stderr)
            return 1

        if sid and app_id:
            token_id = f"{token}_{app_id}"
            _set_token_cookie(ctx, token_id)
            print("[+] QR login confirmed.")
            break

        print("[.] Waiting for QR scan confirmation...")
        time.sleep(max(1.0, float(args.interval)))
    else:
        print("[!] QR login timed out.", file=sys.stderr)
        return 1

    devices = _fetch_devices(ctx, app_id=app_id)
    if not devices:
        print("[!] Logged in, but no devices found via portal API.", file=sys.stderr)
        return 1

    print(f"[+] Devices found: {len(devices)}")
    lines = []
    for item in devices:
        name = item["device_name"].strip() or item["device_id"]
        line = f"{name}={item['device_id']}"
        lines.append(line)
        print(line)

    if args.device_map_out:
        out_path = Path(args.device_map_out).resolve()
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        print(f"[+] device_map saved: {out_path}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
