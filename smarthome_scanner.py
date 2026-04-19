#!/usr/bin/env python3
"""
Smart home ecosystem scanner for local networks.

What it does:
- discovers active IPs in a subnet (ping + ARP + SSDP)
- scans common TCP ports
- grabs lightweight HTTP/HTTPS banners
- assigns likely smart-home ecosystem compatibility scores

The output is heuristic only (best-effort fingerprinting, not guaranteed detection).
"""

from __future__ import annotations

import argparse
import concurrent.futures
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
import ipaddress
import json
import platform
import re
import socket
import ssl
import subprocess
import sys
import time
from typing import Dict, Iterable, List

COMMON_TCP_PORTS = [
    80,
    81,
    82,
    88,
    443,
    554,
    1883,
    8008,
    8009,
    8080,
    8081,
    8123,
    8443,
    8883,
    49152,
    51826,
    6668,
    6669,
    7000,
]

WEB_PORTS = {80, 81, 82, 88, 443, 8008, 8009, 8080, 8081, 8123, 8443}
TLS_PORTS = {443, 8443}

OUI_VENDOR_HINTS = {
    # Apple
    "28:CF:DA": "Apple",
    "3C:07:54": "Apple",
    "AC:17:02": "Apple",
    # Google / Nest
    "3C:5A:B4": "Google",
    "A4:77:33": "Google",
    "F4:F5:D8": "Google",
    # Amazon
    "44:65:0D": "Amazon",
    "F0:27:2D": "Amazon",
    # Tuya (sample prefixes, may vary by ODM)
    "50:8A:06": "Tuya/ODM",
    "84:F3:EB": "Tuya/ODM",
    "D8:1F:CC": "Tuya/ODM",
    # Xiaomi
    "A4:C1:38": "Xiaomi",
    "E4:AA:EC": "Xiaomi",
    # Espressif (common in DIY/Tuya/Sonoff class devices)
    "30:AE:A4": "Espressif",
    "84:CC:A8": "Espressif",
    "DC:4F:22": "Espressif",
    # Sonos
    "78:28:CA": "Sonos",
    # TP-Link
    "50:C7:BF": "TP-Link",
}

ECOSYSTEM_RULES = {
    "Tuya": {
        "ports": {6668: 40, 6669: 40, 7000: 20},
        "keywords": {
            "tuya": 70,
            "smartlife": 55,
            "tywe": 45,
            "tinytuya": 35,
            "iot.tuya": 45,
        },
        "vendor_keywords": {"tuya": 35, "espressif": 10},
        "threshold": 35,
    },
    "Apple HomeKit": {
        "ports": {51826: 55},
        "keywords": {
            "homekit": 70,
            "_hap._tcp": 70,
            "hap": 30,
            "pair-setup": 30,
        },
        "vendor_keywords": {"apple": 30},
        "threshold": 30,
    },
    "Google Home": {
        "ports": {8008: 35, 8009: 35, 8443: 15},
        "keywords": {
            "google cast": 70,
            "chromecast": 70,
            "google home": 60,
            "nest": 40,
            "dial": 15,
        },
        "vendor_keywords": {"google": 30},
        "threshold": 30,
    },
    "Amazon Alexa": {
        "ports": {8883: 20},
        "keywords": {
            "alexa": 70,
            "amazon echo": 70,
            "amzn": 35,
            "echo dot": 55,
        },
        "vendor_keywords": {"amazon": 30},
        "threshold": 30,
    },
    "Home Assistant": {
        "ports": {8123: 65},
        "keywords": {
            "home assistant": 80,
            "hass": 25,
            "supervisor": 20,
        },
        "vendor_keywords": {"raspberry": 10},
        "threshold": 35,
    },
    "Shelly": {
        "ports": {80: 10, 443: 10},
        "keywords": {
            "shelly": 80,
            "allterco": 70,
        },
        "vendor_keywords": {"allterco": 50},
        "threshold": 30,
    },
    "Sonoff/eWeLink": {
        "ports": {8081: 10},
        "keywords": {
            "sonoff": 80,
            "ewelink": 75,
            "itead": 60,
        },
        "vendor_keywords": {"itead": 50},
        "threshold": 30,
    },
    "Xiaomi Mi Home": {
        "ports": {},
        "keywords": {
            "xiaomi": 70,
            "miio": 60,
            "mijia": 60,
            "yeelight": 60,
            "aqara": 60,
        },
        "vendor_keywords": {"xiaomi": 35, "aqara": 35},
        "threshold": 30,
    },
    "Matter": {
        "ports": {},
        "keywords": {
            "_matter._tcp": 75,
            "matter": 45,
            "commissionable": 40,
            "thread": 20,
        },
        "vendor_keywords": {},
        "threshold": 30,
    },
}


@dataclass
class EcosystemMatch:
    name: str
    score: int
    confidence: float
    evidence: List[str] = field(default_factory=list)


@dataclass
class HostRecord:
    ip: str
    hostname: str = ""
    mac: str = ""
    vendor: str = ""
    open_ports: List[int] = field(default_factory=list)
    http_signatures: Dict[int, str] = field(default_factory=dict)
    ssdp_headers: List[str] = field(default_factory=list)
    ecosystems: List[EcosystemMatch] = field(default_factory=list)


def normalize_mac(mac: str) -> str:
    cleaned = re.sub(r"[^0-9A-Fa-f]", "", mac)
    if len(cleaned) != 12:
        return ""
    return ":".join(cleaned[i : i + 2] for i in range(0, 12, 2)).upper()


def get_local_ip() -> str:
    # Reliable way to discover active outbound interface IP without sending payload.
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.connect(("8.8.8.8", 80))
            return sock.getsockname()[0]
    except OSError:
        pass

    try:
        hostname = socket.gethostname()
        ip = socket.gethostbyname(hostname)
        if ip and not ip.startswith("127."):
            return ip
    except OSError:
        pass

    return "127.0.0.1"


def resolve_subnet(subnet_arg: str | None) -> ipaddress.IPv4Network:
    if subnet_arg:
        try:
            network = ipaddress.ip_network(subnet_arg, strict=False)
        except ValueError as exc:
            raise SystemExit(f"Invalid subnet '{subnet_arg}': {exc}") from exc
        if not isinstance(network, ipaddress.IPv4Network):
            raise SystemExit("Only IPv4 subnet is supported in this version.")
        return network

    local_ip = get_local_ip()
    return ipaddress.ip_network(f"{local_ip}/24", strict=False)


def ping_host(ip: str, timeout_ms: int) -> bool:
    if platform.system().lower().startswith("win"):
        cmd = ["ping", "-n", "1", "-w", str(timeout_ms), ip]
    else:
        timeout_s = max(1, int(round(timeout_ms / 1000)))
        cmd = ["ping", "-c", "1", "-W", str(timeout_s), ip]

    proc = subprocess.run(
        cmd,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    return proc.returncode == 0


def discover_alive_hosts(network: ipaddress.IPv4Network, workers: int, timeout_ms: int) -> List[str]:
    candidates = [str(host) for host in network.hosts()]
    if not candidates:
        return []

    active: List[str] = []
    max_workers = min(max(4, workers), len(candidates))
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_map = {executor.submit(ping_host, ip, timeout_ms): ip for ip in candidates}
        for future in concurrent.futures.as_completed(future_map):
            ip = future_map[future]
            try:
                if future.result():
                    active.append(ip)
            except Exception:
                continue

    return sorted(active, key=lambda x: ipaddress.ip_address(x))


def parse_arp_table() -> Dict[str, str]:
    try:
        proc = subprocess.run(
            ["arp", "-a"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
            encoding="utf-8",
            errors="ignore",
        )
    except OSError:
        return {}

    ip_mac: Dict[str, str] = {}
    ip_pattern = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")
    mac_pattern = re.compile(r"\b([0-9A-Fa-f]{2}(?:[:-][0-9A-Fa-f]{2}){5})\b")

    for line in proc.stdout.splitlines():
        ip_match = ip_pattern.search(line)
        mac_match = mac_pattern.search(line)
        if not ip_match or not mac_match:
            continue

        ip = ip_match.group(1)
        mac = normalize_mac(mac_match.group(1))
        if mac:
            ip_mac[ip] = mac

    return ip_mac


def vendor_from_mac(mac: str) -> str:
    if not mac:
        return ""
    prefix = mac[:8].upper()
    return OUI_VENDOR_HINTS.get(prefix, "")


def reverse_dns(ip: str) -> str:
    try:
        host, _, _ = socket.gethostbyaddr(ip)
        return host
    except OSError:
        return ""


def scan_port(ip: str, port: int, timeout: float) -> bool:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        return sock.connect_ex((ip, port)) == 0
    except OSError:
        return False
    finally:
        sock.close()


def scan_open_ports(ip: str, ports: Iterable[int], timeout: float) -> List[int]:
    open_ports = []
    for port in ports:
        if scan_port(ip, port, timeout):
            open_ports.append(port)
    return open_ports


def fetch_http_signature(ip: str, port: int, timeout: float) -> str:
    request = (
        f"GET / HTTP/1.1\\r\\n"
        f"Host: {ip}\\r\\n"
        "User-Agent: SmartHomeNetScanner/1.0\\r\\n"
        "Connection: close\\r\\n\\r\\n"
    ).encode("ascii", errors="ignore")

    try:
        raw_chunks = []
        with socket.create_connection((ip, port), timeout=timeout) as base_sock:
            sock = base_sock
            if port in TLS_PORTS:
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                sock = context.wrap_socket(base_sock, server_hostname=ip)

            sock.settimeout(timeout)
            sock.sendall(request)

            while True:
                data = sock.recv(1024)
                if not data:
                    break
                raw_chunks.append(data)
                if sum(len(chunk) for chunk in raw_chunks) > 4096:
                    break

        text = b"".join(raw_chunks).decode("utf-8", errors="ignore")
        text = text.strip()
        if not text:
            return ""

        lower = text.lower()
        server = ""
        title = ""

        server_match = re.search(r"\\nserver:\\s*([^\\r\\n]+)", lower)
        if server_match:
            server = server_match.group(1).strip()

        title_match = re.search(r"<title>(.*?)</title>", lower, flags=re.IGNORECASE | re.DOTALL)
        if title_match:
            title = " ".join(title_match.group(1).split())

        pieces = []
        if server:
            pieces.append(f"server={server}")
        if title:
            pieces.append(f"title={title}")

        body_preview = re.sub(r"\s+", " ", lower)[:240]
        if body_preview:
            pieces.append(body_preview)

        return " | ".join(pieces)
    except OSError:
        return ""


def ssdp_discovery(timeout: float) -> Dict[str, List[str]]:
    query = (
        "M-SEARCH * HTTP/1.1\\r\\n"
        "HOST: 239.255.255.250:1900\\r\\n"
        "MAN: \"ssdp:discover\"\\r\\n"
        "MX: 1\\r\\n"
        "ST: ssdp:all\\r\\n\\r\\n"
    ).encode("ascii", errors="ignore")

    responses: Dict[str, List[str]] = {}
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    try:
        sock.settimeout(0.2)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
        sock.sendto(query, ("239.255.255.250", 1900))

        deadline = time.time() + max(0.2, timeout)
        while time.time() < deadline:
            try:
                data, (ip, _) = sock.recvfrom(4096)
            except socket.timeout:
                continue
            except OSError:
                break

            parsed = data.decode("utf-8", errors="ignore").lower()
            if parsed:
                responses.setdefault(ip, []).append(parsed[:2000])
    except OSError:
        return responses
    finally:
        sock.close()

    return responses


def confidence_from_score(score: int) -> float:
    return round(min(0.99, max(0.0, score / 120.0)), 2)


def infer_ecosystems(record: HostRecord) -> List[EcosystemMatch]:
    text_bucket = " ".join(
        [record.hostname.lower(), record.vendor.lower()]
        + [s.lower() for s in record.ssdp_headers]
        + [s.lower() for s in record.http_signatures.values()]
    )

    matches: List[EcosystemMatch] = []
    open_ports = set(record.open_ports)

    for ecosystem, rule in ECOSYSTEM_RULES.items():
        score = 0
        evidence: List[str] = []

        for port, points in rule.get("ports", {}).items():
            if port in open_ports:
                score += points
                evidence.append(f"port {port} (+{points})")

        for keyword, points in rule.get("keywords", {}).items():
            if keyword in text_bucket:
                score += points
                evidence.append(f"'{keyword}' (+{points})")

        for keyword, points in rule.get("vendor_keywords", {}).items():
            if keyword in record.vendor.lower():
                score += points
                evidence.append(f"vendor '{keyword}' (+{points})")

        threshold = int(rule.get("threshold", 1))
        if score >= threshold:
            matches.append(
                EcosystemMatch(
                    name=ecosystem,
                    score=score,
                    confidence=confidence_from_score(score),
                    evidence=evidence[:5],
                )
            )

    matches.sort(key=lambda m: m.score, reverse=True)
    return matches


def analyze_host(
    ip: str,
    arp_map: Dict[str, str],
    ssdp_map: Dict[str, List[str]],
    no_port_scan: bool,
    port_timeout: float,
    banner_timeout: float,
) -> HostRecord:
    record = HostRecord(ip=ip)
    record.hostname = reverse_dns(ip)
    record.mac = arp_map.get(ip, "")
    record.vendor = vendor_from_mac(record.mac)
    record.ssdp_headers = ssdp_map.get(ip, [])

    if not no_port_scan:
        record.open_ports = scan_open_ports(ip, COMMON_TCP_PORTS, port_timeout)
        for port in record.open_ports:
            if port in WEB_PORTS:
                signature = fetch_http_signature(ip, port, banner_timeout)
                if signature:
                    record.http_signatures[port] = signature

    record.ecosystems = infer_ecosystems(record)
    return record


def records_to_json(records: List[HostRecord]) -> List[dict]:
    payload = []
    for record in records:
        item = asdict(record)
        item["ecosystems"] = [asdict(match) for match in record.ecosystems]
        payload.append(item)
    return payload


def print_table(records: List[HostRecord]) -> None:
    headers = ["IP", "Hostname", "MAC", "Vendor", "Open ports", "Likely ecosystems"]
    rows: List[List[str]] = []

    for record in records:
        if record.ecosystems:
            eco = ", ".join(
                f"{m.name} ({int(m.confidence * 100)}%)" for m in record.ecosystems[:3]
            )
        else:
            eco = "No strong match"

        rows.append(
            [
                record.ip,
                record.hostname or "-",
                record.mac or "-",
                record.vendor or "-",
                ",".join(str(p) for p in record.open_ports) or "-",
                eco,
            ]
        )

    widths = []
    for i, header in enumerate(headers):
        max_row_width = max((len(row[i]) for row in rows), default=0)
        widths.append(max(len(header), max_row_width))

    line = "-+-".join("-" * w for w in widths)
    print(" | ".join(header.ljust(widths[i]) for i, header in enumerate(headers)))
    print(line)
    for row in rows:
        print(" | ".join(row[i].ljust(widths[i]) for i in range(len(headers))))

    print("\nNotes:")
    print("- Compatibility is estimated from network fingerprints (heuristic).")
    print("- Validate uncertain devices manually before making automation decisions.")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Scan local network and estimate smart-home ecosystem compatibility."
    )
    parser.add_argument(
        "--subnet",
        help="IPv4 subnet in CIDR notation, e.g. 192.168.1.0/24 (default: auto-detected /24)",
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=96,
        help="Max worker threads for discovery/analysis (default: 96)",
    )
    parser.add_argument(
        "--ping-timeout-ms",
        type=int,
        default=350,
        help="Ping timeout in milliseconds (default: 350)",
    )
    parser.add_argument(
        "--port-timeout",
        type=float,
        default=0.35,
        help="TCP port connect timeout per port in seconds (default: 0.35)",
    )
    parser.add_argument(
        "--banner-timeout",
        type=float,
        default=0.9,
        help="HTTP banner read timeout in seconds (default: 0.9)",
    )
    parser.add_argument(
        "--max-hosts",
        type=int,
        default=512,
        help="Safety limit for hosts in selected subnet (default: 512)",
    )
    parser.add_argument(
        "--no-port-scan",
        action="store_true",
        help="Skip TCP port scan and use only ARP/SSDP/DNS fingerprints",
    )
    parser.add_argument(
        "--json-out",
        help="Optional output path for JSON report",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    network = resolve_subnet(args.subnet)

    host_count = max(0, network.num_addresses - 2)
    if host_count > args.max_hosts:
        print(
            f"Refusing to scan {host_count} hosts in {network}. "
            f"Use a smaller subnet or raise --max-hosts.",
            file=sys.stderr,
        )
        return 2

    print(f"[+] Subnet: {network}")
    print("[+] Sending SSDP discovery...")
    ssdp_map = ssdp_discovery(timeout=1.4)

    print("[+] Discovering active hosts (ping sweep)...")
    alive = set(discover_alive_hosts(network, workers=args.workers, timeout_ms=args.ping_timeout_ms))

    arp_map = parse_arp_table()
    for ip in arp_map:
        try:
            if ipaddress.ip_address(ip) in network:
                alive.add(ip)
        except ValueError:
            continue

    for ip in ssdp_map:
        try:
            if ipaddress.ip_address(ip) in network:
                alive.add(ip)
        except ValueError:
            continue

    if not alive:
        print("[!] No active hosts discovered in selected subnet.")
        return 0

    ordered_ips = sorted(alive, key=lambda x: ipaddress.ip_address(x))
    print(f"[+] Hosts to analyze: {len(ordered_ips)}")

    records: List[HostRecord] = []
    max_workers = min(max(4, args.workers), len(ordered_ips))
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_map = {
            executor.submit(
                analyze_host,
                ip,
                arp_map,
                ssdp_map,
                args.no_port_scan,
                args.port_timeout,
                args.banner_timeout,
            ): ip
            for ip in ordered_ips
        }
        for future in concurrent.futures.as_completed(future_map):
            ip = future_map[future]
            try:
                records.append(future.result())
            except Exception as exc:
                # Keep scan robust: one failing host should not fail the whole run.
                records.append(HostRecord(ip=ip, hostname=f"analysis-error:{exc}"))

    records.sort(key=lambda r: ipaddress.ip_address(r.ip))
    print_table(records)

    if args.json_out:
        payload = {
            "generated_at_utc": datetime.now(timezone.utc).isoformat(),
            "subnet": str(network),
            "records": records_to_json(records),
        }
        with open(args.json_out, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2)
        print(f"\n[+] JSON report written: {args.json_out}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
