#!/usr/bin/env python3
"""ThreadT: Authorized reconnaissance toolkit for defensive security assessments.

This tool is designed for use on infrastructure you own or have explicit permission to test.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import json
import random
import re
import socket
import ssl
import sys
import textwrap
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

BANNERS = [
    r"""
████████╗██╗  ██╗██████╗ ███████╗ █████╗ ██████╗ ████████╗
╚══██╔══╝██║  ██║██╔══██╗██╔════╝██╔══██╗██╔══██╗╚══██╔══╝
   ██║   ███████║██████╔╝█████╗  ███████║██║  ██║   ██║   
   ██║   ██╔══██║██╔══██╗██╔══╝  ██╔══██║██║  ██║   ██║   
   ██║   ██║  ██║██║  ██║███████╗██║  ██║██████╔╝   ██║   
   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═════╝    ╚═╝   
                      ThreadT Security Recon
""",
    r"""
╔══════════════════════════════════════════════════════════╗
║ _______ _                               _ _______        ║
║|__   __| |                             | |__   __|       ║
║   | |  | |__  _ __ ___  __ _  __| |   | |  | |        ║
║   | |  | '_ \| '__/ _ \/ _` |/ _` |   | |  | |        ║
║   | |  | | | | | |  __/ (_| | (_| |   | |  | |        ║
║   |_|  |_| |_|_|  \___|\__,_|\__,_|   |_|  |_|        ║
║                 ThreadT Recon Platform                   ║
╚══════════════════════════════════════════════════════════╝
""",
    r"""
┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃   ████████╗██╗  ██╗██████╗ ███████╗ █████╗ ████████╗    ┃
┃   ╚══██╔══╝██║  ██║██╔══██╗██╔════╝██╔══██╗╚══██╔══╝    ┃
┃      ██║   ███████║██████╔╝█████╗  ███████║   ██║       ┃
┃      ██║   ██╔══██║██╔══██╗██╔══╝  ██╔══██║   ██║       ┃
┃      ██║   ██║  ██║██║  ██║███████╗██║  ██║   ██║       ┃
┃      ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝   ╚═╝       ┃
┃                 ThreadT Authorized Recon                 ┃
┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛
""",
    r"""
  _______ _                        _ _______ 
 |__   __| |                      | |__   __|
    | |  | |__  _ __ ___  __ _  __| |  | |   
    | |  | '_ \| '__/ _ \/ _` |/ _` |  | |   
    | |  | | | | | |  __/ (_| | (_| |  | |   
    |_|  |_| |_|_|  \___|\__,_|\__,_|  |_|   
        ThreadT :: Deep Recon and Asset Mapping
""",
    r"""
╭───────────────────────────────────────────────────────────╮
│ ████████╗██╗  ██╗██████╗ ███████╗ █████╗ ████████╗       │
│ ╚══██╔══╝██║  ██║██╔══██╗██╔════╝██╔══██╗╚══██╔══╝       │
│    ██║   ███████║██████╔╝█████╗  ███████║   ██║          │
│    ██║   ██╔══██║██╔══██╗██╔══╝  ██╔══██║   ██║          │
│    ██║   ██║  ██║██║  ██║███████╗██║  ██║   ██║          │
│    ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝   ╚═╝          │
│            ThreadT Exposure & Surface Tracking            │
╰───────────────────────────────────────────────────────────╯
""",
    r"""
╔═╗┬ ┬┬─┐┌─┐┌─┐┌┬┐┌┬┐
╠═╣│ │├┬┘│ │├─┘ │  │ 
╩ ╩└─┘┴└─└─┘┴   ┴  ┴ 
████████╗██╗  ██╗██████╗ ███████╗ █████╗ ████████╗
ThreadT :: Advanced Terminal Reconnaissance Platform
""",
]



COMMON_PORTS = [
    21, 22, 25, 53, 80, 110, 111, 135, 139, 143, 389, 443, 445, 587, 631,
    993, 995, 1433, 1521, 2049, 2375, 3306, 3389, 5432, 5900, 6379, 8080, 8443,
]

USER_AGENT = "ThreadT/1.0 (+authorized-security-assessment)"


@dataclass
class PortScanResult:
    port: int
    open: bool
    service_banner: str | None = None


@dataclass
class ReconReport:
    target: str
    timestamp_utc: str
    resolved_ips: list[str]
    dns_records: dict[str, list[str]]
    tls: dict[str, Any]
    http: dict[str, Any]
    discovered_subdomains: list[str]
    open_ports: list[dict[str, Any]]


def print_banner() -> None:
    print(random.choice(BANNERS))
    print("=" * 72)
    print("ThreadT | Professional terminal reconnaissance for authorized assessments")
    print("=" * 72)


def get_json(url: str, timeout: int = 8) -> Any:
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=timeout) as response:
        return json.loads(response.read().decode("utf-8", errors="replace"))


def get_text(url: str, timeout: int = 8) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=timeout) as response:
        return response.read().decode("utf-8", errors="replace")


def resolve_target(hostname: str) -> list[str]:
    seen: set[str] = set()
    for family, _, _, _, sockaddr in socket.getaddrinfo(hostname, None):
        if family in (socket.AF_INET, socket.AF_INET6):
            seen.add(sockaddr[0])
    return sorted(seen)


def get_dns_records(hostname: str) -> dict[str, list[str]]:
    records: dict[str, list[str]] = {"A/AAAA": [], "MX": [], "NS": []}
    records["A/AAAA"] = resolve_target(hostname)

    try:
        mx_data = get_json(f"https://dns.google/resolve?name={hostname}&type=MX")
        records["MX"] = [ans["data"] for ans in mx_data.get("Answer", [])]
    except Exception:
        pass

    try:
        ns_data = get_json(f"https://dns.google/resolve?name={hostname}&type=NS")
        records["NS"] = [ans["data"] for ans in ns_data.get("Answer", [])]
    except Exception:
        pass

    return records


def fetch_tls_metadata(hostname: str, port: int = 443) -> dict[str, Any]:
    context = ssl.create_default_context()
    details: dict[str, Any] = {}
    try:
        with socket.create_connection((hostname, port), timeout=6) as raw_sock:
            with context.wrap_socket(raw_sock, server_hostname=hostname) as tls_sock:
                cert = tls_sock.getpeercert()
                details["version"] = tls_sock.version()
                details["cipher"] = tls_sock.cipher()[0] if tls_sock.cipher() else None
                details["subject"] = cert.get("subject", [])
                details["issuer"] = cert.get("issuer", [])
                details["not_before"] = cert.get("notBefore")
                details["not_after"] = cert.get("notAfter")
    except Exception as exc:
        details["error"] = str(exc)

    return details


def fetch_http_metadata(target_url: str) -> dict[str, Any]:
    results: dict[str, Any] = {"url": target_url, "headers": {}, "robots_txt": None, "sitemap_xml": None}
    try:
        req = urllib.request.Request(target_url, headers={"User-Agent": USER_AGENT})
        with urllib.request.urlopen(req, timeout=8) as response:
            results["status"] = response.status
            results["headers"] = dict(response.headers.items())
    except urllib.error.URLError as exc:
        results["error"] = str(exc)
        return results

    parsed = urllib.parse.urlparse(target_url)
    base = f"{parsed.scheme}://{parsed.netloc}"

    for endpoint in ("/robots.txt", "/sitemap.xml"):
        try:
            body = get_text(base + endpoint)
            key = "robots_txt" if endpoint.endswith("robots.txt") else "sitemap_xml"
            results[key] = body[:5000]
        except Exception:
            continue

    return results


def discover_subdomains(domain: str) -> list[str]:
    discovered: set[str] = set()

    try:
        data = get_json(f"https://crt.sh/?q=%25.{domain}&output=json", timeout=12)
        for entry in data:
            value = entry.get("name_value", "")
            for item in value.splitlines():
                item = item.strip().lower()
                if item.endswith(f".{domain}") and "*" not in item:
                    discovered.add(item)
    except Exception:
        pass

    return sorted(discovered)


def probe_port(host: str, port: int, timeout: float = 1.0) -> PortScanResult:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        status = sock.connect_ex((host, port))
        if status == 0:
            banner = None
            try:
                sock.sendall(b"\n")
                data = sock.recv(128)
                cleaned = re.sub(r"[^\x20-\x7E]+", " ", data.decode(errors="ignore")).strip()
                banner = cleaned[:100] if cleaned else None
            except Exception:
                pass
            return PortScanResult(port=port, open=True, service_banner=banner)
        return PortScanResult(port=port, open=False)
    finally:
        sock.close()


def scan_ports(host: str, ports: list[int], max_workers: int = 40) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [executor.submit(probe_port, host, port) for port in ports]
        for future in concurrent.futures.as_completed(futures):
            res = future.result()
            if res.open:
                results.append(asdict(res))

    return sorted(results, key=lambda x: x["port"])


def normalize_target(target: str) -> tuple[str, str]:
    parsed = urllib.parse.urlparse(target)
    if parsed.scheme and parsed.netloc:
        hostname = parsed.hostname or parsed.netloc
        return hostname, target

    hostname = target.strip().lower()
    return hostname, f"https://{hostname}"


def save_report(report: ReconReport, output_path: Path) -> None:
    output_path.write_text(json.dumps(asdict(report), indent=2), encoding="utf-8")


def run(args: argparse.Namespace) -> int:
    if not args.authorized:
        print("[!] Refusing to run without --authorized confirmation.")
        print("    Use only on systems you own or have explicit permission to assess.")
        return 1

    hostname, url = normalize_target(args.target)
    print_banner()
    print(f"[*] Target: {hostname}")

    try:
        ips = resolve_target(hostname)
    except socket.gaierror as exc:
        print(f"[!] Could not resolve target: {exc}")
        return 1

    print(f"[*] Resolved IPs: {', '.join(ips) if ips else 'none'}")

    print("[*] Collecting DNS records...")
    dns_records = get_dns_records(hostname)

    print("[*] Collecting TLS metadata...")
    tls = fetch_tls_metadata(hostname)

    print("[*] Collecting HTTP metadata...")
    http = fetch_http_metadata(url)

    print("[*] Discovering known subdomains...")
    subdomains = discover_subdomains(hostname)

    ports: list[dict[str, Any]] = []
    if args.deep:
        print("[*] Deep mode enabled: scanning common ports...")
        if not ips:
            print("[!] No IPs available for port scan.")
        else:
            ports = scan_ports(ips[0], COMMON_PORTS)

    report = ReconReport(
        target=hostname,
        timestamp_utc=datetime.now(timezone.utc).isoformat(),
        resolved_ips=ips,
        dns_records=dns_records,
        tls=tls,
        http=http,
        discovered_subdomains=subdomains,
        open_ports=ports,
    )

    output = Path(args.output)
    save_report(report, output)
    print(f"[+] Recon complete. Report saved: {output.resolve()}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="ThreadT: terminal reconnaissance toolkit for authorized security work.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent(
            """
            Examples:
              python threadt.py --target example.com --authorized
              python threadt.py --target https://example.com --deep --authorized --output report.json
            """
        ),
    )
    parser.add_argument("--target", required=True, help="Target hostname or URL")
    parser.add_argument("--deep", action="store_true", help="Enable deeper checks including common port scan")
    parser.add_argument("--output", default="recon_report.json", help="Path to JSON output report")
    parser.add_argument(
        "--authorized",
        action="store_true",
        help="Required confirmation that you are authorized to test this target",
    )
    return parser


if __name__ == "__main__":
    raise SystemExit(run(build_parser().parse_args()))
