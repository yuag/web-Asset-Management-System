"""Lightweight TCP port-service identification (pure Python stdlib).

Only connects + reads a banner (no HTTP requests, no exploitation) - a
low-noise, passive-ish probe used to enrich assets with a port -> service map.

Layout:
- parse_ports(): turn the settings string "21,22,443" into a sorted int list
- scan_ports() / _probe(): concurrent TCP connect + banner read per port
- detect_service(): banner regex + well-known-port fallback -> service label
- scan_assets(): scan a list of assets (single bounded thread pool over
  (asset, port) pairs) and persist results via models.save_port_scan_result()

Dedup: an asset is skipped when it was scanned less than 24h ago unless
`force=True` (manual scans always force).
"""
import concurrent.futures
import json
import re
import socket
from datetime import datetime, timedelta

import config
import models

# Service identification: (lowercase substring, label) rules tried in order.
# Matching is deliberately conservative - a port that connects but has no
# recognizable banner gets the well-known label only when it is an obvious
# default (443 -> HTTPS etc, see DEFAULT_SERVICE below).
BANNER_RULES = [
    ("ssh-", "SSH"),
    ("openssh", "SSH"),
    ("dropbear", "SSH"),
    ("mysql", "MySQL"),
    ("mariadb", "MySQL"),
    ("redis", "Redis"),
    ("postgres", "PostgreSQL"),
    ("mongodb", "MongoDB"),
    ("vsftpd", "FTP"),
    ("pure-ftpd", "FTP"),
    ("proftpd", "FTP"),
    ("ftp", "FTP"),
    ("esmtp", "SMTP"),
    ("smtp", "SMTP"),
    ("postfix", "SMTP"),
    ("exim", "SMTP"),
    ("sendmail", "SMTP"),
    ("http/1", "HTTP"),
    ("rtsp/1", "RTSP"),
    ("telnet", "Telnet"),
    ("* ok", "IMAP/POP3"),
    ("+ok pop3", "IMAP/POP3"),
    ("+ok imap", "IMAP/POP3"),
]

# Well-known default service per port when the banner is unreadable/absent.
DEFAULT_SERVICE = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS",
    993: "IMAPS", 995: "POP3S", 3306: "MySQL", 5432: "PostgreSQL",
    6379: "Redis", 8080: "HTTP", 8443: "HTTPS", 9200: "Elasticsearch",
    27017: "MongoDB", 3389: "RDP", 5900: "VNC",
}

DEFAULT_PORTS = "21,22,23,25,80,443,3306,6379,8080,8443"


def parse_ports(text=None):
    """Parse a comma/space separated port list -> sorted unique int list."""
    text = (text or config.get("port_scan_ports") or DEFAULT_PORTS).strip()
    if not text:
        return []
    seen = {}
    for part in re.split(r"[,;，; ]+", text):
        part = part.strip()
        if not part or "-" in part:
            continue
        try:
            p = int(part)
        except ValueError:
            continue
        if 1 <= p <= 65535:
            seen[p] = True
    return sorted(seen)


def parse_services(raw):
    """assets.service JSON string -> {port_str: label} dict ('' unknown open)."""
    if not raw:
        return {}
    if isinstance(raw, dict):
        return raw
    try:
        data = json.loads(raw or "{}")
        return data if isinstance(data, dict) else {}
    except (ValueError, TypeError):
        return {}


def detect_service(banner, port):
    """Identify a service from the banner bytes (or the well-known port)."""
    if isinstance(banner, bytes):
        banner = banner.decode("utf-8", "ignore")
    banner = (banner or "").strip()
    low = banner.lower()
    for needle, name in BANNER_RULES:
        if needle in low:
            return name
    if not banner:
        # No banner at all: many servers wait for the client to speak first.
        # The well-known label is only a hint for obvious defaults.
        if port in DEFAULT_SERVICE:
            return DEFAULT_SERVICE[port]
        return ""
    # TLS servers start with binary handshake bytes - no text banner. Detect
    # the TLS record header (0x16 0x03) directly and default TLS ports too.
    if banner.startswith("\x16\x03") or port in (443, 8443, 993, 995):
        return "HTTPS"
    return ""


def _probe(ip, port, timeout):
    """TCP connect + short banner read. Returns banner bytes, or None when the
    port is closed/filtered/unreachable."""
    try:
        with socket.create_connection((ip, port), timeout=timeout) as s:
            s.settimeout(timeout)
            try:
                return s.recv(1024)
            except socket.timeout:
                return b""          # connected, server waits for our input
            except OSError:
                return b""
    except (socket.timeout, OSError, OverflowError):
        return None


def scan_ports(ip, ports, timeout=3, max_workers=20):
    """Scan one IP against a list of ports. Returns {port_str: service_label}
    for every port that accepted a TCP connection."""
    ports = [p for p in (ports or []) if isinstance(p, int)]
    if not ports or not ip:
        return {}
    found = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, max_workers)) as ex:
        futs = {ex.submit(_probe, ip, p, timeout): p for p in ports}
        for fut in concurrent.futures.as_completed(futs):
            port = futs[fut]
            try:
                banner = fut.result()
            except Exception:  # noqa: BLE001 - never let one probe kill the scan
                banner = None
            if banner is not None:
                found[str(port)] = detect_service(banner, port)
    return found


def _scanned_recently(asset, hours=24):
    ts = (asset.get("ports_scanned_at") or "").strip()
    if not ts:
        return False
    try:
        dt = datetime.fromisoformat(ts)
    except (ValueError, TypeError):
        return False
    return datetime.now() - dt < timedelta(hours=hours)


def scan_assets(assets, force=False):
    """Scan a list of asset dicts (each must contain id + ip).

    All (asset, port) probes share one bounded thread pool, then results are
    persisted per asset. Returns a summary list, one item per asset:
    {'asset_id', 'domain', 'ip', 'scanned': True/False, 'skip_reason'|'open'}
    """
    now = datetime.now().isoformat(timespec="seconds")
    timeout = max(1, min(15, config.get_int("port_scan_timeout", 3)))
    max_workers = max(1, min(200, config.get_int("port_scan_concurrency", 20)))
    ports = parse_ports()
    out = []

    jobs = []          # (asset, port)
    by_asset = {}      # id -> asset
    for a in assets:
        ip = (a.get("ip") or "").strip()
        if not ip:
            out.append({"asset_id": a.get("id"), "domain": a.get("domain"),
                        "ip": "", "scanned": False, "skip_reason": "无 IP"})
            continue
        if not force and _scanned_recently(a):
            out.append({"asset_id": a.get("id"), "domain": a.get("domain"),
                        "ip": ip, "scanned": False,
                        "skip_reason": "24 小时内已扫描"})
            continue
        by_asset[a["id"]] = {"asset": a, "results": {}}
        for p in ports:
            jobs.append((a, p))

    if jobs:
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as ex:
            futs = {ex.submit(_probe, a["ip"], p, timeout): (a, p) for a, p in jobs}
            for fut in concurrent.futures.as_completed(futs):
                a, p = futs[fut]
                try:
                    banner = fut.result()
                except Exception:  # noqa: BLE001
                    banner = None
                if banner is not None:
                    by_asset[a["id"]]["results"][str(p)] = detect_service(banner, p)

    for aid, info in by_asset.items():
        a = info["asset"]
        mapping = info["results"]
        models.save_port_scan_result(a["id"], mapping, scanned_at=now)
        open_n = len(mapping)
        labels = ", ".join(f"{p}:{s}" if s else str(p)
                           for p, s in sorted(mapping.items(), key=lambda kv: int(kv[0])))
        out.append({"asset_id": a["id"], "domain": a.get("domain"),
                    "ip": a.get("ip"), "scanned": True, "open": open_n,
                    "ports": sorted(mapping, key=lambda p: int(p)),
                    "summary": labels or "无开放端口"})
    return out
