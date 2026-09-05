"""Configuration stored in SQLite config table (key-value)."""
import db
import cache

DEFAULTS = {
    "fofa_email": "",
    "fofa_api_key": "",
    "scan_timeout": "30",
    # parallel root-domain scanning (sharded scan)
    "scan_concurrency": "5",
    # fingerprint concurrency
    "fingerprint_concurrency": "20",
    "fingerprint_timeout": "3",
    "fingerprint_batch_size": "100",
    # scheduler
    "scheduled_scan_enabled": "false",
    "scheduled_scan_time": "02:00",
    # dingtalk
    "dingtalk_enabled": "false",
    "dingtalk_webhook": "",
    "dingtalk_notify_new": "true",
    "dingtalk_notify_change": "true",
    "dingtalk_notify_cve": "true",
    # proxy
    "proxy_enabled": "false",
    "proxy_url": "",
    # nuclei (passive vuln scanning)
    "nuclei_path": "",
    # lightweight TCP port-service identification (pure python socket)
    "port_scan_auto_enabled": "true",
    "port_scan_ports": "21,22,23,25,80,443,3306,6379,8080,8443",
    "port_scan_timeout": "3",
    "port_scan_concurrency": "20",
    # AI assistant - legacy single-provider keys (migrated into ai_providers)
    "ai_api_key": "",
    "ai_base_url": "https://api.deepseek.com",
    "ai_model": "deepseek-chat",
    # AI assistant - multi-model: auto-retry a transient failure on the next
    # enabled provider (default off: explicit is safer for paid APIs)
    "ai_fallback_enabled": "false",
}


def _load_all():
    raw = db.get_all_config()
    merged = dict(DEFAULTS)
    merged.update(raw)
    # typed conversion helpers kept as strings; conversion done at call site
    return merged


def get_all():
    return cache.get("config:all", _load_all, ttl=5)


def get(key, default=None):
    return get_all().get(key) or DEFAULTS.get(key, default or "")


def set(key, value):
    db.set_config(key, str(value))
    cache.invalidate("config:all")


def update(partial):
    for k, v in partial.items():
        db.set_config(k, str(v))
    cache.invalidate("config:all")


def get_int(key, default=0):
    try:
        return int(get(key, str(default)))
    except (ValueError, TypeError):
        return default


def get_bool(key, default=False):
    v = str(get(key, str(default))).strip().lower()
    return v in ("1", "true", "yes", "on")


def proxy_dict():
    """Return proxies dict for requests if proxy enabled, else None."""
    if get_bool("proxy_enabled") and get("proxy_url"):
        return {"http": get("proxy_url"), "https": get("proxy_url")}
    return None
