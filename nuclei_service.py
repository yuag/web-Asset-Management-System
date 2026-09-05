"""Nuclei passive vulnerability scanning.

Responsibilities:
- Environment pre-check (proxy validity + exit IP + nuclei binary) that runs
  BEFORE any scan is allowed to start
- Safe command construction: system appends ``-u <target>``, ``-json`` and
  ``-proxy`` itself; advanced (manual) mode only accepts a validated token
  list and is executed WITHOUT a shell, so no command injection is possible
- Streams nuclei ``-json`` output line by line, parses each finding and
  persists it into ``nuclei_results`` (see db.py / models.py)
- Background task registry with progress + stop support

"Passive" mode: nuclei >= 3.2 supports ``-passive``, which runs only
non-intrusive templates (no exploit payloads).  Older binaries simply reject
the flag and the stderr message is surfaced to the user.
"""
import json
import shlex
import shutil
import subprocess
import sys
import threading
import time
import uuid
from collections import deque
from datetime import datetime

import requests

import config
import models


# ---------------------------------------------------------------------------
# Environment pre-check
# ---------------------------------------------------------------------------

# Order matters: httpbin.org/ip (JSON), ipify (JSON), ifconfig.me (plain text)
IP_ENDPOINTS = [
    "https://httpbin.org/ip",
    "https://api.ipify.org",
    "https://ifconfig.me",
]

UA = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}


def _extract_ip(text, url):
    text = (text or "").strip()
    if not text:
        return ""
    try:
        if "httpbin" in url or "ipify" in url:
            payload = json.loads(text)
            if isinstance(payload, dict):
                return (payload.get("origin") or payload.get("ip") or "").strip()
    except (ValueError, AttributeError):
        pass
    # plain text (ifconfig.me) or unexpected payload -> keep first token-ish line
    first = text.splitlines()[0].strip()
    if first and all(c.isalnum() or c in ":.%" for c in first):
        return first
    return ""


def _probe_ip(proxies, timeout=6):
    """Try the IP endpoints through `proxies`. Returns (ip or '', last error or '')."""
    err = ""
    for url in IP_ENDPOINTS:
        try:
            resp = requests.get(url, timeout=timeout, proxies=proxies, headers=UA)
            resp.raise_for_status()
            ip = _extract_ip(resp.text, url)
            if ip:
                return ip, ""
        except requests.exceptions.Timeout as e:
            err = "连接超时"
            break  # transport is broken (bad proxy / no network): stop retrying
        except requests.exceptions.RequestException as e:
            err = f"{type(e).__name__}: {str(e)[:120]}"
            continue
        except Exception as e:
            err = f"{type(e).__name__}: {str(e)[:120]}"
            continue
    return "", err


def find_nuclei():
    """Locate the nuclei executable.

    Priority: config `nuclei_path` -> PATH lookup.
    Returns (path or None, hint or '').
    """
    configured = (config.get("nuclei_path") or "").strip()
    if configured:
        if shutil.which(configured):
            return shutil.which(configured), ""
        return None, f"系统设置中配置的 nuclei 路径不存在: {configured}"
    found = shutil.which("nuclei")
    if found:
        return found, ""
    return None, "未在 PATH 中找到 nuclei，请在「系统设置 → Nuclei 配置」中填写可执行文件路径"


def check_environment(timeout=6, proxy_enabled=None, proxy_url=None):
    """Run the scan pre-flight check.

    `proxy_enabled` / `proxy_url` optionally override the saved config, e.g.
    to test unsaved values typed in the settings form.

    Returns a dict consumed by the UI (settings page + scan dialog):
      ready       - scan may start (nuclei found AND proxy valid when enabled)
      proxy_*     - proxy configuration + probe result
      exit_ip     - public exit IP through the active transport
      exit_source - 'proxy' | 'direct'
      server_ip   - direct server IP when the proxy is enabled (informational)
      nuclei_path - resolved binary path (may be None)
      checks      - [{level: ok|warn|err, text}] rendered with colors
    """
    checks = []
    if proxy_enabled is None:
        proxy_enabled = config.get_bool("proxy_enabled", False)
    if proxy_url is None:
        proxy_url = (config.get("proxy_url") or "").strip()
    else:
        proxy_url = str(proxy_url).strip()

    exit_ip = ""
    exit_source = "direct"
    server_ip = ""
    proxy_ok = None
    proxy_error = ""

    if proxy_enabled:
        if not proxy_url:
            proxy_ok = False
            proxy_error = "已启用代理但未填写代理地址"
            checks.append({"level": "err", "text": "⚠️ 已启用代理，但未填写代理地址，请先到系统设置中配置！"})
        else:
            ip, err = _probe_ip({"http": proxy_url, "https": proxy_url}, timeout=timeout)
            if ip:
                proxy_ok = True
                exit_ip = ip
                exit_source = "proxy"
                checks.append({"level": "ok", "text": f"✅ 代理已启用：{proxy_url}"})
                checks.append({"level": "ok", "text": f"✅ 代理连接正常（HTTP/HTTPS 均可用）"})
            else:
                proxy_ok = False
                proxy_error = err or "代理连接失败"
                checks.append({"level": "err", "text": f"⚠️ 代理已启用，但连接失败（{proxy_error}），请检查代理配置！"})
    else:
        checks.append({"level": "info", "text": "未启用代理，将使用服务器公网出口直接扫描"})

    # Exit IP: with a working proxy we already have it; otherwise fetch direct.
    if exit_ip:
        pass
    elif proxy_enabled and not proxy_ok:
        # proxy is broken -> try direct only to show where traffic WOULD come
        # from, but scanning stays blocked (see route /app.py).
        ip, _ = _probe_ip({}, timeout=timeout)
        if ip:
            server_ip = ip
            checks.append({"level": "warn", "text": f"🌐 若忽略代理故障直连，出口 IP 为服务器公网 IP：{ip}"})
    else:
        ip, err = _probe_ip({}, timeout=timeout)
        if ip:
            exit_ip = ip
            checks.append({"level": "info", "text": f"🌐 当前扫描出口 IP（服务器公网 IP）：{ip}"})
        else:
            checks.append({"level": "warn", "text": f"⚠️ 无法获取公网出口 IP（{err or '网络异常'}），请确认服务器可访问外网"})

    nuclei_path, nuclei_hint = find_nuclei()
    if nuclei_path:
        checks.append({"level": "ok", "text": f"🔧 Nuclei 可用：{nuclei_path}"})
    else:
        checks.append({"level": "err", "text": f"🔧 Nuclei 不可用：{nuclei_hint}"})

    ready = bool(nuclei_path) and (not proxy_enabled or proxy_ok is True)
    return {
        "ready": ready,
        "proxy_enabled": proxy_enabled,
        "proxy_url": proxy_url,
        "proxy_ok": proxy_ok,
        "proxy_error": proxy_error,
        "exit_ip": exit_ip,
        "exit_source": exit_source,
        "server_ip": server_ip,
        "nuclei_path": nuclei_path,
        "nuclei_hint": nuclei_hint if not nuclei_path else "",
        "checks": checks,
    }


# ---------------------------------------------------------------------------
# Command construction + safety validation
# ---------------------------------------------------------------------------

# Flags the user may NOT pass (neither visual nor advanced mode): they conflict
# with the system-managed behaviour (mandatory targets, JSON output, proxy).
# Anything else is passed through verbatim as argv tokens (no shell involved).
BLOCKED_FLAGS = {
    "-u", "-url", "-target",           # targets are auto-appended
    "-l", "-list", "-list-to-file",    # target list file
    "-json", "-jsonl", "-j",           # JSON output is auto-appended
    "-o", "-output",                   # result file output
    "-proxy", "-http-proxy", "-https-proxy",  # proxy is auto-appended
}

ADVANCED_EXAMPLE = (
    "例如: -id log4shell,CVE-2021-44228 -severity high,critical\n"
    "或: -tags cve,default-login -exclude-tags dos -rl 30"
)


def validate_advanced_args(args_text):
    """Parse + validate free-text nuclei arguments.

    Returns (tokens or None, error or '').  Rejects shell metacharacters (they
    are pointless here since argv is passed list-style without a shell) and any
    flag that would override the system-managed behaviour.
    """
    text = (args_text or "").strip()
    if not text:
        return [], "请输入 Nuclei 参数（高级模式）"
    try:
        tokens = shlex.split(text)
    except ValueError as e:
        return None, f"参数格式错误（引号未闭合等）: {e}"
    for t in tokens:
        if t.startswith("-"):
            flag = t.split("=", 1)[0].lower()
            if flag in BLOCKED_FLAGS:
                return None, f"禁止使用参数「{t}」：{flag} 由系统自动附加（目标/JSON输出/代理）"
        if any(ch in t for ch in (";", "&", "|", "`", "$", ">", "<", "\n", "\r")):
            return None, f"参数包含非法字符（禁止 shell 元字符）: {t}"
    return tokens, ""


def build_command(exe, targets, mode="visual", options=None, args_text="", proxy_url=""):
    """Build the argv list for a nuclei run.

    ``-u <target>`` / ``-json`` / ``-silent`` / ``-no-color`` and (when
    configured) ``-proxy`` are ALWAYS appended AFTER user-supplied tokens so
    the system settings win.
    Returns (cmd or None, error or '').
    """
    if not exe:
        return None, "未找到 nuclei 可执行文件"
    targets = [t for t in (targets or []) if (t or "").strip()]
    if not targets:
        return None, "没有可扫描的目标资产"

    cmd = [exe]
    mode = "advanced" if mode == "advanced" else "visual"
    if mode == "advanced":
        tokens, err = validate_advanced_args(args_text)
        if err:
            return None, err
        cmd += tokens
    else:
        options = options or {}
        if options.get("passive", True):
            cmd.append("-passive")  # only non-intrusive templates (nuclei>=3.2)
        sev = (options.get("severity") or "").strip()
        if sev:
            cmd += ["-severity", sev]
        tags = (options.get("tags") or "").strip()
        if tags:
            cmd += ["-tags", tags]
        templates = (options.get("templates") or "").strip()
        if templates:
            cmd += ["-t", templates]

    for t in targets:
        cmd += ["-u", t]
    # mandatory flags: appended last on purpose
    cmd += ["-json", "-silent", "-no-color"]
    if proxy_url:
        cmd += ["-proxy", proxy_url]
    return cmd, ""


# ---------------------------------------------------------------------------
# Targets / host mapping helpers
# ---------------------------------------------------------------------------

def asset_target_urls(asset, both_schemes=False):
    """URLs to feed nuclei for one asset. Prefers stored url when it has a
    scheme, otherwise builds https:// (or http+https when both_schemes)."""
    raw = (asset.get("url") or asset.get("domain") or "").strip()
    if not raw:
        return []
    if "://" in raw:
        return [raw]
    if both_schemes:
        return [f"http://{raw}", f"https://{raw}"]
    return [f"https://{raw}"]


def _netloc_key(s):
    s = (s or "").strip().lower()
    if "://" in s:
        s = s.split("://", 1)[1]
    return s.split("/", 1)[0].strip()


def build_host_map(assets):
    """Map host/domain/ip variants -> asset id for JSON result attribution."""
    m = {}
    for a in assets:
        try:
            aid = a["id"]
        except (KeyError, TypeError):
            continue
        keys = set()
        domain = (a.get("domain") or "").strip().lower()
        if domain:
            keys.add(domain)
        u = (a.get("url") or "").strip()
        if u:
            nl = _netloc_key(u if "://" in u else "http://" + u)
            keys.add(nl)
            if ":" in nl and nl.rsplit(":", 1)[1].isdigit():
                keys.add(nl.rsplit(":", 1)[0])
        ip = (a.get("ip") or "").strip().lower()
        if ip:
            keys.add(ip)
            port = (a.get("port") or "").strip()
            if port:
                keys.add(f"{ip}:{port}")
        for k in keys:
            if k:
                m.setdefault(k, aid)
    return m


def lookup_asset(host_map, host):
    key = _netloc_key(host)
    if key in host_map:
        return host_map[key]
    if ":" in key and key.rsplit(":", 1)[1].isdigit():
        return host_map.get(key.rsplit(":", 1)[0])
    return None


# ---------------------------------------------------------------------------
# JSON result parsing
# ---------------------------------------------------------------------------

def parse_finding(data, host_map=None, created_at=None):
    """Convert one nuclei -json line into a DB row dict (see models).
    Returns None when the line carries no usable finding."""
    if not isinstance(data, dict):
        return None
    info = data.get("info") or {}
    if not isinstance(info, dict):
        info = {}
    template_id = str(data.get("template-id") or "").strip()
    host = str(data.get("host") or data.get("matched-at") or "").strip()
    if not template_id:
        return None

    severity = str(info.get("severity") or data.get("severity") or "info").lower()
    template_name = str(info.get("name") or template_id).strip()
    extracted = data.get("extracted-results")
    if isinstance(extracted, list):
        extracted = " | ".join(str(x) for x in extracted)
    extracted = str(extracted or "").strip()[:2000]

    cls = info.get("classification") or {}
    cves = cls.get("cve-id") if isinstance(cls, dict) else None
    if isinstance(cves, list):
        vuln_type = ",".join(str(c) for c in cves if c)
    elif isinstance(cves, str):
        vuln_type = cves
    else:
        vuln_type = str(data.get("type") or "")

    return {
        "asset_id": lookup_asset(host_map, host) if host_map else None,
        "host": host,
        "template_id": template_id,
        "template_name": template_name,
        "severity": severity if severity in models.SEVERITY_RANK else "unknown",
        "vuln_type": str(vuln_type or "")[:500],
        "description": str(info.get("description") or "")[:5000],
        "matched_at": str(data.get("matched-at") or "")[:2000],
        "extracted_results": extracted,
        "curl_command": str(data.get("curl-command") or "")[:2000],
        "raw_json": json.dumps(data, ensure_ascii=False)[:10000],
        "created_at": created_at or datetime.now().isoformat(timespec="seconds"),
    }


# ---------------------------------------------------------------------------
# Background scan tasks
# ---------------------------------------------------------------------------

_tasks = {}
_tasks_lock = threading.Lock()


def _stderr_drain(proc, bucket):
    """Read stderr line-by-line so the pipe never fills; keep a capped tail."""
    try:
        for line in proc.stderr:
            bucket.append(line.rstrip("\r\n"))
            if len(bucket) > 200:
                bucket.popleft()
    except Exception:
        pass


def _flush(findings, scan_id):
    if findings:
        models.insert_nuclei_results(findings, scan_id=scan_id)


def _scan_worker(task_id, cmd, host_map, scan_id):
    task = _tasks.get(task_id, {})
    task["status"] = "running"
    bucket = deque(maxlen=200)
    asset_ids = sorted({a for a in host_map.values() if a})
    proc = None
    try:
        kwargs = {}
        if sys.platform == "win32":
            kwargs["creationflags"] = getattr(subprocess, "CREATE_NO_WINDOW", 0)
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            bufsize=1,
            **kwargs,
        )
        task["pid"] = proc.pid
        t = threading.Thread(target=_stderr_drain, args=(proc, bucket), daemon=True)
        t.start()

        findings = []
        severity_counts = task.setdefault("by_severity", {})
        matched = set()
        for line in proc.stdout:
            if task.get("stop_requested"):
                break
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
            except (ValueError, TypeError):
                continue  # ignore stray non-JSON lines
            f = parse_finding(data, host_map)
            if not f:
                continue
            findings.append(f)
            sev = f["severity"]
            severity_counts[sev] = severity_counts.get(sev, 0) + 1
            task["findings_total"] = task.get("findings_total", 0) + 1
            if f["asset_id"]:
                matched.add(f["asset_id"])
                task["assets_matched"] = len(matched)
            if len(findings) >= 40:
                _flush(findings, scan_id)
                findings = []
        _flush(findings, scan_id)

        proc.stdout.close()
        proc.wait()

        # Generation swap (P0 fix): findings were streamed in tagged with
        # `scan_id` while the PREVIOUS results stayed visible. Now that this
        # run is over we switch generations in one transaction:
        #   completed      -> drop superseded rows, keep this scan's findings
        #   stopped/error  -> drop this scan's partial rows, KEEP old results
        # A crash mid-scan therefore never leaves the asset with empty results.
        try:
            if task.get("stop_requested"):
                task["status"] = "stopped"
                models.abort_nuclei_scan(scan_id, asset_ids)
                return
            tail = "\n".join(bucket)[-3000:]
            if proc.returncode != 0:
                task["status"] = "error"
                task["error"] = (tail or f"nuclei 退出码 {proc.returncode}")[:1000]
                models.abort_nuclei_scan(scan_id, asset_ids)
            else:
                task["status"] = "completed"
                models.finalize_nuclei_scan(scan_id, asset_ids)
                if not task.get("findings_total") and tail:
                    task["notice"] = tail[:500]
        except Exception as e:  # pragma: no cover - cleanup must not lose the task
            task["cleanup_error"] = str(e)[:500]
    except Exception as e:  # pragma: no cover - defensive
        task["status"] = "error"
        task["error"] = str(e)[:1000]
        try:
            models.abort_nuclei_scan(scan_id, asset_ids)  # keep old results
        except Exception:
            pass
        if proc is not None:
            try:
                proc.terminate()
            except Exception:
                pass
    finally:
        task["end_time"] = time.time()


def start_scan(cmd, host_map, meta=None):
    """Start a background nuclei scan. Returns task_id.

    Every run gets its own `scan_id` generation tag. Findings are inserted with
    that tag while old results remain visible; the worker atomically swaps
    generations when the run finishes (see finalize/abort in models.py)."""
    task_id = str(uuid.uuid4())
    scan_id = uuid.uuid4().hex
    task = {
        "status": "starting",
        "findings_total": 0,
        "by_severity": {},
        "assets_matched": 0,
        "error": None,
        "notice": None,
        "cleanup_error": None,
        "stop_requested": False,
        "pid": None,
        "start_time": time.time(),
        "scan_id": scan_id,
        "targets": meta or {},
    }
    with _tasks_lock:
        _tasks[task_id] = task
    thread = threading.Thread(
        target=_scan_worker, args=(task_id, cmd, host_map, scan_id), daemon=True
    )
    thread.start()
    return task_id


def get_task(task_id):
    task = _tasks.get(task_id)
    if not task:
        return None
    out = dict(task)
    out["elapsed"] = round(time.time() - task.get("start_time", time.time()), 1)
    return out


def stop_task(task_id):
    task = _tasks.get(task_id)
    if not task:
        return False
    task["stop_requested"] = True
    pid = task.get("pid")
    if pid:
        try:
            import os
            os.kill(pid, 9)  # SIGKILL -> cross-platform terminate of the child
        except Exception:
            pass
    return True
