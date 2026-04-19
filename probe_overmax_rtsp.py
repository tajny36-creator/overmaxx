#!/usr/bin/env python3
"""
Probe RTSP endpoints for older OEM NVRs (including many Overmax-branded units).

Why this exists:
- Some NVRs expose proprietary ports for vendor apps (e.g. 6001/6002/6003)
- Home Assistant needs standard streams (typically RTSP) to integrate cameras
- This tool brute-tests common RTSP URL patterns with Basic/Digest auth
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import os
import re
import secrets
import socket
import textwrap
from dataclasses import dataclass
from typing import Dict, List, Tuple


DEFAULT_PORTS = [554, 8554, 10554, 6001, 6002, 6003]


@dataclass
class ProbeResult:
    url: str
    status_code: int
    status_line: str
    headers: Dict[str, str]
    ok: bool
    note: str = ""


def tcp_reachable(host: str, port: int, timeout: float) -> bool:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        return sock.connect_ex((host, port)) == 0
    except OSError:
        return False
    finally:
        sock.close()


def parse_headers(raw_response: str) -> Tuple[int, str, Dict[str, str]]:
    lines = raw_response.split("\r\n")
    if not lines:
        return 0, "", {}

    status_line = lines[0]
    code = 0
    m = re.search(r"RTSP/\d\.\d\s+(\d{3})", status_line)
    if m:
        code = int(m.group(1))

    headers: Dict[str, str] = {}
    for line in lines[1:]:
        if not line or ":" not in line:
            continue
        k, v = line.split(":", 1)
        headers[k.strip().lower()] = v.strip()
    return code, status_line, headers


def build_digest_auth(
    www_authenticate: str, method: str, uri: str, username: str, password: str
) -> str:
    # Example:
    # Digest realm="IP Camera", nonce="....", algorithm=MD5, qop="auth"
    params = {}
    for part in re.split(r",\s*", www_authenticate.replace("Digest ", "", 1)):
        if "=" not in part:
            continue
        k, v = part.split("=", 1)
        params[k.strip().lower()] = v.strip().strip('"')

    realm = params.get("realm", "")
    nonce = params.get("nonce", "")
    qop = params.get("qop", "")
    opaque = params.get("opaque", "")
    algorithm = params.get("algorithm", "MD5")

    if algorithm.upper() != "MD5":
        raise ValueError(f"Unsupported digest algorithm: {algorithm}")

    def md5_hex(s: str) -> str:
        return hashlib.md5(s.encode("utf-8")).hexdigest()

    ha1 = md5_hex(f"{username}:{realm}:{password}")
    ha2 = md5_hex(f"{method}:{uri}")

    if "auth" in qop:
        nc = "00000001"
        cnonce = secrets.token_hex(8)
        response = md5_hex(f"{ha1}:{nonce}:{nc}:{cnonce}:auth:{ha2}")
        value = (
            f'Digest username="{username}", realm="{realm}", nonce="{nonce}", '
            f'uri="{uri}", response="{response}", qop=auth, nc={nc}, cnonce="{cnonce}"'
        )
    else:
        response = md5_hex(f"{ha1}:{nonce}:{ha2}")
        value = (
            f'Digest username="{username}", realm="{realm}", nonce="{nonce}", '
            f'uri="{uri}", response="{response}"'
        )

    if opaque:
        value += f', opaque="{opaque}"'
    return value


def rtsp_request(
    host: str,
    port: int,
    uri_path: str,
    user: str,
    password: str,
    timeout: float,
) -> ProbeResult:
    full_uri = f"rtsp://{host}:{port}{uri_path}"
    cseq = 1

    def send(method: str, auth_header: str = "") -> Tuple[int, str, Dict[str, str], str]:
        nonlocal cseq
        lines = [
            f"{method} {full_uri} RTSP/1.0",
            f"CSeq: {cseq}",
            "User-Agent: HA-RTSP-Probe/1.0",
            "Accept: application/sdp",
        ]
        if auth_header:
            lines.append(f"Authorization: {auth_header}")
        raw = "\r\n".join(lines) + "\r\n\r\n"
        cseq += 1

        with socket.create_connection((host, port), timeout=timeout) as s:
            s.settimeout(timeout)
            s.sendall(raw.encode("utf-8", errors="ignore"))
            chunks = []
            while True:
                try:
                    data = s.recv(4096)
                except socket.timeout:
                    break
                if not data:
                    break
                chunks.append(data)
                # For headers-only status this is enough.
                if b"\r\n\r\n" in b"".join(chunks):
                    break
            text = b"".join(chunks).decode("utf-8", errors="ignore")
        code, status_line, headers = parse_headers(text)
        return code, status_line, headers, text

    try:
        code, status_line, headers, _ = send("DESCRIBE")
    except OSError as exc:
        return ProbeResult(
            url=full_uri,
            status_code=0,
            status_line="",
            headers={},
            ok=False,
            note=f"socket-error:{type(exc).__name__}",
        )

    if code == 200:
        return ProbeResult(full_uri, code, status_line, headers, ok=True, note="no-auth")

    if code == 401 and user:
        auth = headers.get("www-authenticate", "")
        if auth.lower().startswith("basic"):
            token = base64.b64encode(f"{user}:{password}".encode("utf-8")).decode("ascii")
            try:
                code2, sl2, h2, _ = send("DESCRIBE", f"Basic {token}")
            except OSError as exc:
                return ProbeResult(
                    full_uri,
                    0,
                    "",
                    {},
                    ok=False,
                    note=f"auth-socket-error:{type(exc).__name__}",
                )
            return ProbeResult(full_uri, code2, sl2, h2, ok=(code2 == 200), note="basic-auth")

        if auth.lower().startswith("digest"):
            try:
                digest = build_digest_auth(auth, "DESCRIBE", full_uri, user, password)
            except ValueError as exc:
                return ProbeResult(full_uri, code, status_line, headers, ok=False, note=str(exc))
            try:
                code2, sl2, h2, _ = send("DESCRIBE", digest)
            except OSError as exc:
                return ProbeResult(
                    full_uri,
                    0,
                    "",
                    {},
                    ok=False,
                    note=f"auth-socket-error:{type(exc).__name__}",
                )
            return ProbeResult(full_uri, code2, sl2, h2, ok=(code2 == 200), note="digest-auth")

    return ProbeResult(full_uri, code, status_line, headers, ok=False, note="no-match")


def build_paths(max_channels: int) -> List[str]:
    static_paths = [
        "/",
        "/live/ch00_0",
        "/live/ch00_1",
        "/h264/ch1/main/av_stream",
        "/h264/ch1/sub/av_stream",
        "/h265/ch1/main/av_stream",
        "/cam/realmonitor?channel=1&subtype=0",
        "/cam/realmonitor?channel=1&subtype=1",
        "/Streaming/Channels/101",
        "/Streaming/Channels/102",
        "/stream1",
        "/stream2",
        "/main",
        "/sub",
        "/11",
        "/12",
        "/1",
    ]

    templated = []
    for ch in range(1, max_channels + 1):
        templated.extend(
            [
                f"/cam/realmonitor?channel={ch}&subtype=0",
                f"/cam/realmonitor?channel={ch}&subtype=1",
                f"/h264/ch{ch}/main/av_stream",
                f"/h264/ch{ch}/sub/av_stream",
                f"/Streaming/Channels/{ch:02d}1",
                f"/Streaming/Channels/{ch:02d}2",
                f"/live/ch{ch-1:02d}_0",
                f"/live/ch{ch-1:02d}_1",
                f"/user=admin_password=tlJwpbo6_channel={ch}_stream=0.sdp?real_stream",
                f"/user=admin_password=tlJwpbo6_channel={ch}_stream=1.sdp?real_stream",
            ]
        )

    # Keep order deterministic and without duplicates.
    out = []
    seen = set()
    for p in static_paths + templated:
        if p not in seen:
            out.append(p)
            seen.add(p)
    return out


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Probe common RTSP URLs for Overmax/OEM NVR and print HA-ready candidates."
    )
    parser.add_argument("--host", required=True, help="NVR host/IP, e.g. 192.168.1.136")
    parser.add_argument("--user", default=os.getenv("NVR_USER", ""), help="NVR username")
    parser.add_argument("--password", default=os.getenv("NVR_PASS", ""), help="NVR password")
    parser.add_argument(
        "--ports",
        default=",".join(str(p) for p in DEFAULT_PORTS),
        help="Comma-separated RTSP ports to test (default: 554,8554,10554,6001,6002,6003)",
    )
    parser.add_argument(
        "--max-channels",
        type=int,
        default=8,
        help="Max channel count to generate candidate paths (default: 8)",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=1.0,
        help="Socket timeout in seconds per probe (default: 1.0)",
    )
    parser.add_argument(
        "--show-failed",
        action="store_true",
        help="Print failed probes too (useful for debugging)",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        ports = [int(x.strip()) for x in args.ports.split(",") if x.strip()]
    except ValueError as exc:
        raise SystemExit(f"Invalid --ports value: {exc}") from exc

    paths = build_paths(max_channels=args.max_channels)

    print(f"[+] Host: {args.host}")
    print(f"[+] Candidate ports: {ports}")
    print(f"[+] Candidate paths: {len(paths)}")
    print("[+] Checking reachable ports...")

    precheck_timeout = min(0.5, max(0.05, args.timeout / 2))
    reachable_ports = [p for p in ports if tcp_reachable(args.host, p, precheck_timeout)]
    print(f"[+] Reachable ports: {reachable_ports if reachable_ports else 'none'}")
    if not reachable_ports:
        print("[!] No reachable RTSP-like port. Enable RTSP/ONVIF in NVR settings and retry.")
        return 1

    print("[+] Validating RTSP-speaking ports...")
    rtsp_ports = []
    for port in reachable_ports:
        trial = rtsp_request(
            host=args.host,
            port=port,
            uri_path="/",
            user=args.user,
            password=args.password,
            timeout=args.timeout,
        )
        if args.show_failed:
            print(f"[precheck {port}] {trial.status_code or '-'} {trial.status_line} ({trial.note})")
        if trial.status_code != 0:
            rtsp_ports.append(port)

    print(f"[+] RTSP-speaking ports: {rtsp_ports if rtsp_ports else 'none'}")
    if not rtsp_ports:
        print("[!] Reachable ports exist, but none responded as RTSP.")
        print("    This indicates proprietary stream protocol (common on old OEM NVR).")
        return 1

    print("[+] Probing RTSP...")

    results: List[ProbeResult] = []
    for port in rtsp_ports:
        for path in paths:
            res = rtsp_request(
                host=args.host,
                port=port,
                uri_path=path,
                user=args.user,
                password=args.password,
                timeout=args.timeout,
            )
            if args.show_failed:
                print(
                    f"[{res.status_code or '-':>3}] {res.url} "
                    f"({res.note})"
                )
            results.append(res)

    ok = [r for r in results if r.ok]
    if not ok:
        print("\n[!] No working RTSP URL found with current probe set.")
        print("    This usually means one of:")
        print("    - RTSP is disabled in NVR settings")
        print("    - Different port/path is used")
        print("    - Credentials are invalid")
        print("    - NVR only exposes proprietary stream protocol")
        print("\nTry:")
        print("1) Enable RTSP/ONVIF in NVR network settings")
        print("2) Re-run with correct --user/--password")
        print("3) Add more ports: --ports 554,8554,10554,6001,6002,6003,37777,34567")
        return 1

    # Deduplicate by URL
    uniq = []
    seen = set()
    for r in ok:
        if r.url not in seen:
            uniq.append(r)
            seen.add(r.url)

    print(f"\n[+] Found {len(uniq)} working RTSP endpoint(s):")
    for i, r in enumerate(uniq, start=1):
        print(f"{i}. {r.url} [{r.note}]")

    sample = uniq[0].url
    print("\n[+] Home Assistant snippet (Generic Camera):")
    print(
        textwrap.dedent(
            f"""
            camera:
              - platform: generic
                name: Overmax NVR Camera 1
                stream_source: {sample}
            """
        ).strip()
    )

    print("\n[+] Alternative for go2rtc/frigate:")
    print(
        textwrap.dedent(
            f"""
            streams:
              overmax_cam1: {sample}
            """
        ).strip()
    )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
