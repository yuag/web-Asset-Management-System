"""Root-domain scanning via crt.sh + FOFA with fingerprinting, proxy, changelog."""
import re
import base64
import requests
import config
import models

CRT_SH_URL = "https://crt.sh/?q=%.{domain}&output=json"
CRTNAME_URL = "https://crt.name/v1/search"
FOFA_API_URL = "https://fofa.info/api/v1/search/all"


def _timeout():
    return config.get_int("scan_timeout", 30)


def _proxies():
    return config.proxy_dict()


def _clean_host(name):
    name = (name or "").strip().lower().lstrip("*.")
    return name


COUNTRY_CODE_MAP = {
    "中国": "CN", "美国": "US", "日本": "JP", "德国": "DE", "英国": "GB",
    "法国": "FR", "加拿大": "CA", "澳大利亚": "AU", "印度": "IN", "巴西": "BR",
    "俄罗斯": "RU", "韩国": "KR", "新加坡": "SG",
}

WAF_SIGNATURES = [
    (re.compile(r"cloudflare", re.I), "Cloudflare"),
    (re.compile(r"aliyun|safedog|yundun", re.I), "阿里云WAF"),
    (re.compile(r"aws|amazon", re.I), "AWS WAF"),
    (re.compile(r"akamai", re.I), "Akamai"),
    (re.compile(r"incapsula", re.I), "Incapsula"),
    (re.compile(r"sucuri", re.I), "Sucuri"),
]


def detect_waf(text):
    if not text:
        return "None"
    for pat, name in WAF_SIGNATURES:
        if pat.search(text):
            return name
    return "None"


def parse_server(server_header):
    """Extract middleware name from Server header. Returns (server, cms_guess)."""
    s = (server_header or "").strip()
    if not s:
        return "", ""
    low = s.lower()
    server_name = s
    cms = ""
    if "nginx" in low:
        server_name = s
    elif "apache" in low:
        server_name = s
    elif "tomcat" in low:
        server_name = s
    elif "iis" in low:
        server_name = s
    if "wordpress" in low:
        cms = "WordPress"
    elif "drupal" in low:
        cms = "Drupal"
    elif "joomla" in low:
        cms = "Joomla"
    return server_name, cms


def scan_crtsh(root_domain):
    results = []
    url = CRT_SH_URL.format(domain=root_domain)
    try:
        resp = requests.get(url, timeout=_timeout(), proxies=_proxies(),
                            headers={"User-Agent": "Mozilla/5.0"})
        resp.raise_for_status()
        data = resp.json()
    except Exception:
        return results

    seen = set()
    for entry in data:
        name_value = entry.get("name_value", "") or entry.get("name", "")
        for raw in name_value.split("\n"):
            host = _clean_host(raw)
            if not host or host == root_domain:
                continue
            if not re.match(r"^[\w.-]+$", host):
                continue
            if host in seen:
                continue
            seen.add(host)
            results.append({
                "domain": host,
                "url": host,
                "ip": "",
                "port": "",
                "title": "",
                "country": "",
                "country_code": "",
                "cms": "",
                "server": "",
                "waf": "None",
                "status_code": None,
                "source": "crt",
                "tags": ["crt"],
                "root_domain": root_domain,
            })
    return results


def scan_crtname(root_domain):
    """Scan crt.name for subdomains (free, no token, 100 req/day/IP)."""
    results = []
    crtname_error = None
    params = {"apex": root_domain, "format": "json"}
    try:
        resp = requests.get(CRTNAME_URL, params=params, timeout=_timeout(),
                            proxies=_proxies(), headers={"User-Agent": "Mozilla/5.0"})
        resp.raise_for_status()
        data = resp.json()
    except requests.exceptions.JSONDecodeError:
        # crt.name may return plain text (one subdomain per line)
        try:
            lines = resp.text.strip().splitlines()
            seen = set()
            for line in lines:
                host = _clean_host(line)
                if not host or host == root_domain:
                    continue
                if not re.match(r"^[\w.-]+$", host):
                    continue
                if host in seen:
                    continue
                seen.add(host)
                results.append({
                    "domain": host, "url": host, "ip": "", "port": "",
                    "title": "", "country": "", "country_code": "",
                    "cms": "", "server": "", "waf": "None",
                    "status_code": None, "source": "crtname",
                    "tags": ["crtname"], "root_domain": root_domain,
                })
            return results, crtname_error
        except Exception:
            crtname_error = "crt.name 响应解析失败"
            return results, crtname_error
    except Exception as e:
        crtname_error = f"crt.name 请求失败: {e}"
        return results, crtname_error

    # Handle JSON array of subdomain strings
    seen = set()
    entries = data if isinstance(data, list) else data.get("results", data.get("subdomains", []))
    for entry in entries:
        # entry could be a string or a dict with name/subdomain field
        if isinstance(entry, dict):
            name = entry.get("name") or entry.get("subdomain") or entry.get("domain") or ""
        else:
            name = str(entry)
        host = _clean_host(name)
        if not host or host == root_domain:
            continue
        if not re.match(r"^[\w.-]+$", host):
            continue
        if host in seen:
            continue
        seen.add(host)
        results.append({
            "domain": host, "url": host, "ip": "", "port": "",
            "title": "", "country": "", "country_code": "",
            "cms": "", "server": "", "waf": "None",
            "status_code": None, "source": "crtname",
            "tags": ["crtname"], "root_domain": root_domain,
        })
    return results, crtname_error


def scan_fofa(root_domain):
    results = []
    fofa_error = None
    conf = config.get_all()
    email = conf.get("fofa_email", "").strip()
    api_key = conf.get("fofa_api_key", "").strip()
    if not email or not api_key:
        return results, fofa_error

    query = f'domain="{root_domain}"'
    q_b64 = base64.b64encode(query.encode("utf-8")).decode("ascii")
    params = {"email": email, "key": api_key, "qbase64": q_b64, "size": 100,
              "fields": "host,ip,port,title,server,country"}
    try:
        resp = requests.get(FOFA_API_URL, params=params, timeout=_timeout(), proxies=_proxies())
        resp.raise_for_status()
        data = resp.json()
    except Exception as e:
        fofa_error = f"FOFA 请求失败: {e}"
        return results, fofa_error

    if data.get("error"):
        fofa_error = f"FOFA API 错误: {data['error']}"
        return results, fofa_error
    if not data.get("results"):
        return results, fofa_error

    for row in data.get("results", []):
        if not row or len(row) < 5:
            continue
        host = (row[0] or "").strip()
        ip = (row[1] or "").strip()
        port = (row[2] or "").strip()
        title = (row[3] or "").strip()
        server_field = (row[4] or "").strip()
        country_field = (row[5] or "").strip() if len(row) > 5 else ""

        server_name, cms_guess = parse_server(server_field)
        waf = detect_waf(server_field + " " + title)
        country_code = ""
        country = country_field
        if country_field in COUNTRY_CODE_MAP:
            country_code = COUNTRY_CODE_MAP[country_field]
        elif country_field and len(country_field) == 2:
            country_code = country_field.upper()

        results.append({
            "domain": host,
            "url": host,
            "ip": ip,
            "port": port,
            "title": title,
            "country": country,
            "country_code": country_code,
            "cms": cms_guess,
            "server": server_name,
            "waf": waf,
            "status_code": None,
            "source": "fofa",
            "tags": ["fofa"],
            "root_domain": root_domain,
        })
    return results, fofa_error


def scan_root_domains(domains, tags=None, concurrency=None, auto_fingerprint=True):
    """Scan many root domains in parallel (sharded scan).

    Each domain is scanned independently; results are returned in completion
    order as (root_domain, summary, discovered) tuples. `concurrency` defaults
    to the scan_concurrency config (see config.py).
    """
    import concurrent.futures
    domains = [d for d in (domains or []) if (d or "").strip()]
    if not domains:
        return []
    if concurrency is None:
        concurrency = config.get_int("scan_concurrency", 5)
    concurrency = max(1, int(concurrency))

    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as executor:
        futures = {executor.submit(scan_root_domain, d, tags, auto_fingerprint): d for d in domains}
        for fut in concurrent.futures.as_completed(futures):
            domain = futures[fut]
            try:
                summary, discovered = fut.result()
            except Exception as e:  # keep going even if one domain fails
                summary, discovered = {"error": str(e)}, []
            results.append((domain, summary, discovered))
    return results


def scan_root_domain(root_domain, tags=None, auto_fingerprint=True):
    """Scan root domain via crt.sh + crt.name + FOFA.
    `tags`: extra user tags (str like "项目A,核心资产" or list) merged into every
    discovered asset's tags on top of the automatic source tags (crt/fofa/both).
    `auto_fingerprint`: if True, automatically run fingerprinting on new assets after scan.
    """
    root_domain = (root_domain or "").strip().lower().lstrip("*.")
    if not root_domain:
        return {"error": "empty domain"}, []

    manual_tags = []
    if isinstance(tags, str):
        manual_tags = [t.strip() for t in re.split(r"[,，、]", tags) if t.strip()]
    elif isinstance(tags, (list, tuple)):
        manual_tags = [str(t).strip() for t in tags if str(t).strip()]

    crt_results = scan_crtsh(root_domain)
    crtname_results, crtname_error = scan_crtname(root_domain)
    fofa_results, fofa_error = scan_fofa(root_domain)

    all_results = crt_results + crtname_results + fofa_results
    if manual_tags:
        mset = set(manual_tags)
        for item in all_results:
            item["tags"] = list(set(item["tags"]) | mset)

    merged = {}
    for item in all_results:
        key = item["domain"]
        if not key:
            continue
        if key in merged:
            ex = merged[key]
            ex_sources = set((ex["source"] or "").split(","))
            ex_sources.add(item["source"])
            ex["source"] = ",".join(sorted(ex_sources))
            ex_tags = set(ex["tags"]) | set(item["tags"])
            if len(ex_sources) >= 2:
                ex_tags.add("both")
            ex["tags"] = list(ex_tags)
            for f in ("ip", "port", "title", "country", "country_code", "cms", "server", "waf"):
                if not ex.get(f) and item.get(f):
                    ex[f] = item[f]
        else:
            merged[key] = dict(item)

    discovered = []
    new_assets = []  # Track newly discovered assets for fingerprinting
    for item in merged.values():
        asset, change_type = models.upsert_asset(item)
        item["id"] = asset.get("id") if asset else None
        item["change_type"] = change_type
        discovered.append(item)
        if change_type == "新增":
            new_assets.append(item)

    # Auto-run fingerprinting on new assets
    if auto_fingerprint and new_assets:
        _run_fingerprint_background(new_assets)
    # Lightweight TCP banner scan for newly discovered hosts that carry an IP
    # (background, never blocks the scan; gated by port_scan_auto_enabled).
    _auto_port_scan_new_assets(new_assets)

    summary = {"crtsh_count": len(crt_results), "crtname_count": len(crtname_results),
               "fofa_count": len(fofa_results), "new_count": len(new_assets)}
    if manual_tags:
        summary["tags"] = manual_tags
    errors = []
    if crtname_error:
        errors.append(crtname_error)
    if fofa_error:
        errors.append(fofa_error)
    if errors:
        summary["errors"] = errors
    return summary, discovered


def _auto_port_scan_new_assets(new_assets):
    """Fire-and-forget port-service probe for assets discovered by a scan.

    Only newly inserted assets that carry an IP address are probed (crt.sh/
    crt.name rows have no IP and are skipped). Runs in a daemon thread so the
    discovery flow returns immediately; results land in assets.port /.service.
    """
    if not config.get_bool("port_scan_auto_enabled", False):
        return
    targets = [a for a in (new_assets or []) if (a.get("ip") or "").strip()]
    if not targets:
        return
    import threading
    import port_scanner

    def _run():
        try:
            port_scanner.scan_assets(targets)
        except Exception as e:  # background: log & keep the scan flow clean
            print(f"auto port scan failed: {e}")

    threading.Thread(target=_run, daemon=True).start()


def _run_fingerprint_background(assets, progress_callback=None):
    """Run fingerprinting in background for a list of assets.
    
    Args:
        assets: list of asset dicts to fingerprint
        progress_callback: optional callback(current, total) for progress updates
    """
    import concurrent.futures
    from fingerprint_service import verify_and_fingerprint

    def _update_asset(result):
        domain = result.get("domain", "")
        asset = models.get_asset_by_domain(domain)
        if not asset:
            return
        
        update_data = {
            "domain": domain,
            "status_code": result.get("status_code", 0),
        }
        
        # Update CMS and server if detected
        if result.get("cms"):
            update_data["cms"] = result["cms"]
        if result.get("server"):
            update_data["server"] = result["server"]
        
        # More accurate "已失效" tag logic:
        # - Only add "已失效" if status_code is 0 (connection failed) or error indicates connection issue
        # - Don't add "已失效" for timeout or other non-critical errors
        # - Remove "已失效" if site is now alive (status 200-499)
        existing_tags = asset.get("tags", [])
        error_msg = result.get("error", "") or ""
        status_code = result.get("status_code", 0)
        is_alive = result.get("alive", False)
        
        # Only mark as "已失效" if:
        # 1. Connection failed completely (status_code == 0), OR
        # 2. TCP connection error (not timeout)
        should_mark_inactive = (
            not is_alive and (
                status_code == 0 or
                "TCP 连接失败" in error_msg or
                "ConnectionError" in error_msg
            )
        )
        
        if should_mark_inactive:
            if "已失效" not in existing_tags:
                update_data["tags"] = existing_tags + ["已失效"]
        else:
            # Remove "已失效" tag if now alive or if error is not critical
            if "已失效" in existing_tags:
                update_data["tags"] = [t for t in existing_tags if t != "已失效"]
        
        models.upsert_asset(update_data)
    
    # Get concurrency setting from config
    max_workers = config.get_int("fingerprint_concurrency", 20)
    
    # Use thread pool for parallel verification
    completed_count = 0
    total_count = len([a for a in assets if a.get("domain")])
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = []
        domain_map = {}  # Map futures to domains
        for asset in assets:
            domain = asset.get("domain")
            if domain:
                future = executor.submit(verify_and_fingerprint, domain)
                domain_map[future] = domain
                futures.append(future)
        
        for future in concurrent.futures.as_completed(futures):
            try:
                result = future.result()
                result["domain"] = domain_map[future]  # Add domain to result
                _update_asset(result)
                completed_count += 1
                if progress_callback:
                    progress_callback(completed_count, total_count)
            except Exception as e:
                # Log error but continue
                print(f"Fingerprint error: {e}")
                completed_count += 1
                if progress_callback:
                    progress_callback(completed_count, total_count)
