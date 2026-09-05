"""Flask application: Web Asset Management System (extended)."""
import csv
import io
import json
import os
from flask import Flask, render_template, request, jsonify, Response, send_from_directory, stream_with_context

import db
import config
import models
import scanner
import notifier
import nvd
import whois_lookup
import scheduler
import nuclei_service
import ai_assistant
import ai_providers
import port_scanner

app = Flask(__name__)
app.config["JSON_AS_ASCII"] = False

db.init_db()
# Mark fingerprint tasks left 'running' by a previous process as interrupted
# (their checkpoints survive, so the user can resume them after a restart).
models.recover_interrupted_fingerprint_tasks()
# Seed the builtin multi-model AI providers + adopt legacy DeepSeek keys.
ai_providers.ensure_seeded()


@app.before_request
def _ensure_db():
    db.init_db()


# ---------- Pages ----------

@app.route("/")
def index():
    stats = models.dashboard_stats()
    tags = models.all_tags()
    changelog = models.recent_changelog(15)
    return render_template("dashboard.html", stats=stats, tags=tags, changelog=changelog)


@app.route("/scan")
def scan_page():
    return render_template("scan.html", conf=config.get_all())


@app.route("/assets")
def assets_page():
    tags = models.all_tags()
    return render_template("assets.html", tags=tags)


@app.route("/search")
def search_page():
    tags = models.all_tags()
    return render_template("global_search.html", tags=tags)


@app.route("/txt-import")
def txt_import_page():
    return render_template("txt_import.html")


@app.route("/settings")
def settings_page():
    return render_template("settings.html", conf=config.get_all())


@app.route("/ai")
def ai_page():
    return render_template("ai.html")


@app.route("/graph")
def graph_page():
    return render_template("graph.html")


# ---------- Scan API ----------

@app.route("/api/scan", methods=["POST"])
def api_scan():
    data = request.get_json(silent=True) or {}
    domain = (data.get("domain") or "").strip()
    if not domain:
        return jsonify({"ok": False, "error": "请输入根域"}), 400
    summary, discovered = scanner.scan_root_domain(domain, tags=data.get("tags"))
    if isinstance(summary, dict) and "error" in summary:
        return jsonify({"ok": False, "error": summary["error"]}), 400
    changes = [(d.get("domain", ""), d.get("change_type", "")) for d in discovered]
    notifier.notify_scan_complete(domain, summary, changes)
    return jsonify({"ok": True, "summary": summary, "discovered": discovered})


# ---------- Assets API ----------

@app.route("/api/assets")
def api_list_assets():
    filters = {
        "search": request.args.get("search") or None,
        "country": request.args.get("country") or None,
        "cms": request.args.get("cms") or None,
        "source": request.args.get("source") or None,
        "tag": request.args.get("tag") or None,
        "tags_multi": request.args.getlist("tags") or None,
    }
    page = request.args.get("page", 1, type=int)
    per_page = request.args.get("per_page", 20, type=int)
    sort = request.args.get("sort", "updated_at")
    order = request.args.get("order", "desc")
    assets, total = models.list_assets(filters, page, per_page, sort, order)
    return jsonify({"ok": True, "assets": assets, "total": total,
                    "page": page, "per_page": per_page})


@app.route("/api/assets/import", methods=["POST"])
def api_import_selected():
    data = request.get_json(silent=True) or {}
    items = data.get("items", [])
    if not items:
        return jsonify({"ok": False, "error": "未选择资产"}), 400
    # Batch upsert: single transaction + pre-fetched lookups (fast for big scans)
    imported, updated, _ = models.batch_upsert_assets(items)
    return jsonify({"ok": True, "imported": imported, "updated": updated})


@app.route("/api/assets/add", methods=["POST"])
def api_add_asset():
    data = request.get_json(silent=True) or {}
    asset, ct = models.upsert_asset(data)
    return jsonify({"ok": True, "created": ct == "新增", "asset": asset})


@app.route("/api/assets/<int:asset_id>", methods=["GET", "PUT", "DELETE"])
def api_asset_detail(asset_id):
    if request.method == "GET":
        asset = models.get_asset(asset_id)
        if not asset:
            return jsonify({"ok": False, "error": "资产不存在"}), 404
        return jsonify({"ok": True, "asset": asset})
    if request.method == "DELETE":
        models.delete_asset(asset_id)
        return jsonify({"ok": True})
    # PUT
    existing = models.get_asset(asset_id)
    if not existing:
        return jsonify({"ok": False, "error": "资产不存在"}), 404
    data = request.get_json(silent=True) or {}
    data["domain"] = data.get("domain") or existing["domain"]
    models.upsert_asset(data)
    return jsonify({"ok": True})


@app.route("/api/assets/batch-delete", methods=["POST"])
def api_batch_delete():
    data = request.get_json(silent=True) or {}
    ids = data.get("ids", [])
    if not ids:
        return jsonify({"ok": False, "error": "未选择资产"}), 400
    models.delete_assets(ids)
    return jsonify({"ok": True, "deleted": len(ids)})


import uuid
import threading
import time
from datetime import datetime


def _start_fingerprint_worker(task_id):
    """Background loop driving /api/assets/identify.

    The DB row (fingerprint_tasks) is the durable checkpoint: completed
    assets are committed per asset, and `processed` is persisted as batches
    finish, so a crash/restart loses at most the in-flight batch. The task
    row survives with status 'interrupted' and the resume endpoint continues
    from the tail of `asset_ids`."""
    from scanner import _run_fingerprint_background

    def _run() -> None:
        task = models.get_fingerprint_task(task_id)
        if not task:
            return
        try:
            try:
                ids = json.loads(task.get("asset_ids") or "[]")
            except ValueError:
                ids = []
            ids = [int(x) for x in ids]
            batch_size = config.get_int("fingerprint_batch_size", 100)
            pos = min(int(task.get("processed") or 0), len(ids))
            while pos < len(ids):
                batch_ids = ids[pos:pos + batch_size]
                batch = []
                for aid in batch_ids:
                    a = models.get_asset(aid)
                    if a:
                        batch.append(a)
                base = pos
                if batch:
                    def progress_callback(current, total_batch, _base=base):
                        models.update_fingerprint_task(task_id, processed=_base + current)
                    _run_fingerprint_background(batch, progress_callback)
                pos += len(batch_ids)
            models.update_fingerprint_task(task_id, processed=len(ids), status="completed")
        except Exception as e:
            models.update_fingerprint_task(task_id, status="error", error=str(e))

    t = threading.Thread(target=_run, daemon=True)
    t.start()


@app.route("/api/assets/identify", methods=["POST"])
def api_identify_assets():
    """Identify CMS fingerprint for assets (crash-safe, resumable)."""
    data = request.get_json(silent=True) or {}
    asset_ids = data.get("ids", [])
    use_current_page = data.get("use_current_page", False)
    page = data.get("page", 1)
    per_page = data.get("per_page", 20)
    sort = data.get("sort", "updated_at")
    order = data.get("order", "desc")
    
    # Get assets to identify
    if asset_ids:
        assets = []
        for aid in asset_ids:
            a = models.get_asset(int(aid))
            if a:
                assets.append(a)
    elif use_current_page:
        # Identify all assets on current page
        filters = {
            "search": data.get("search"),
            "country": data.get("country"),
            "cms": data.get("cms"),
            "source": data.get("source"),
            "tag": data.get("tag"),
            "tags_multi": data.get("tags_multi"),
        }
        assets, _ = models.list_assets(filters, page, per_page, sort, order)
    else:
        return jsonify({"ok": False, "error": "未选择资产"}), 400
    
    if not assets:
        return jsonify({"ok": False, "error": "无资产可识别"}), 400

    # Create task ID
    task_id = str(uuid.uuid4())
    models.create_fingerprint_task(task_id, [a["id"] for a in assets])
    _start_fingerprint_worker(task_id)
    return jsonify({
        "ok": True,
        "task_id": task_id,
        "message": f"正在识别 {len(assets)} 个资产的CMS指纹",
        "count": len(assets)
    })


@app.route("/api/assets/identify/<task_id>/progress")
def api_identify_progress(task_id):
    """Get identification progress (read from the persisted task row)."""
    task = models.get_fingerprint_task(task_id)
    if not task:
        return jsonify({"ok": False, "error": "任务不存在"}), 404
    try:
        started = datetime.fromisoformat(task["created_at"] or "").timestamp()
        elapsed = round(max(0.0, time.time() - started), 1)
    except (ValueError, TypeError):
        elapsed = None
    return jsonify({
        "ok": True,
        "task_id": task_id,
        "status": task["status"],
        "current": task["processed"],
        "total": task["total"],
        "error": task["error"],
        "elapsed": elapsed
    })


@app.route("/api/assets/identify/<task_id>/resume", methods=["POST"])
def api_identify_resume(task_id):
    """Resume an interrupted / errored fingerprint task from its checkpoint.
    Remaining work = asset_ids[processed:]; completed assets are never
    re-fingerprinted because each asset is committed individually."""
    task = models.get_fingerprint_task(task_id)
    if not task:
        return jsonify({"ok": False, "error": "任务不存在"}), 404
    if task["status"] == "running":
        return jsonify({"ok": False, "error": "任务正在运行中"}), 400
    try:
        ids = json.loads(task["asset_ids"] or "[]")
        ids = [int(x) for x in ids]
    except ValueError:
        ids = []
    remaining = len(ids) - int(task.get("processed") or 0)
    if remaining <= 0:
        models.update_fingerprint_task(task_id, status="completed")
        return jsonify({"ok": True, "already_completed": True})
    models.update_fingerprint_task(task_id, status="running", error="")
    _start_fingerprint_worker(task_id)
    return jsonify({"ok": True, "remaining": remaining})


@app.route("/api/assets/<int:asset_id>/cve")
def api_asset_cve(asset_id):
    asset = models.get_asset(asset_id)
    if not asset:
        return jsonify({"ok": False, "error": "资产不存在"}), 404
    server = asset.get("server", "")
    cms = asset.get("cms", "")
    if not server and not cms:
        return jsonify({"ok": False, "error": "请先完善资产指纹信息（server 或 cms）"}), 400
    cves, keywords = nvd.lookup_cves(server, cms)
    if cves:
        notifier.notify_cve(asset["domain"], cves)
    return jsonify({"ok": True, "cves": cves, "keywords": keywords})


@app.route("/api/assets/<int:asset_id>/whois")
def api_asset_whois(asset_id):
    asset = models.get_asset(asset_id)
    if not asset:
        return jsonify({"ok": False, "error": "资产不存在"}), 404
    exp = whois_lookup.lookup_expiration(asset["domain"])
    if exp:
        models.upsert_asset({**asset, "expiration_date": exp, "tags": asset.get("tags", [])})
    return jsonify({"ok": True, "expiration_date": exp})


# ---------- Nuclei (passive vulnerability scanning) ----------

MAX_NUCLEI_TARGETS = 1000


def _gather_scan_assets(data):
    """Resolve the asset dicts a nuclei scan should cover.
    Supports explicit ids, the current filtered page, or every asset matching
    the current filters (capped by MAX_NUCLEI_TARGETS)."""
    ids = data.get("ids") or []
    if ids:
        assets = []
        for aid in ids:
            a = models.get_asset(int(aid))
            if a:
                assets.append(a)
        return assets
    filters = {
        "search": data.get("search") or None,
        "country": data.get("country") or None,
        "cms": data.get("cms") or None,
        "source": data.get("source") or None,
        "tag": data.get("tag") or None,
        "tags_multi": data.get("tags_multi") or None,
    }
    if data.get("use_current_page"):
        page = data.get("page", 1)
        per_page = data.get("per_page", 20)
        assets, _ = models.list_assets(
            filters, page, per_page,
            data.get("sort", "updated_at"), data.get("order", "desc"),
        )
        return assets
    if data.get("all_filtered"):
        assets = []
        for shard in models.iter_asset_shards(filters, shard_size=1000):
            assets.extend(shard)
            if len(assets) >= MAX_NUCLEI_TARGETS:
                break
        return assets
    return []


@app.route("/api/nuclei/env-check", methods=["GET", "POST"])
def api_nuclei_env_check():
    """Pre-scan environment check (proxy + exit IP + nuclei binary).
    A POST body may carry unsaved proxy_enabled/proxy_url to test before saving."""
    data = request.get_json(silent=True) if request.method == "POST" else {}
    pe = data.get("proxy_enabled")
    if isinstance(pe, str):
        pe = pe.strip().lower() in ("1", "true", "yes", "on")
    pu = (data.get("proxy_url") or "").strip()
    env = nuclei_service.check_environment(
        proxy_enabled=pe if pe is not None else None,
        proxy_url=pu or None,
    )
    return jsonify({"ok": True, **env})


@app.route("/api/nuclei/scan", methods=["POST"])
def api_nuclei_scan():
    data = request.get_json(silent=True) or {}
    mode = data.get("mode", "visual")
    if mode not in ("visual", "advanced"):
        return jsonify({"ok": False, "error": "无效的扫描模式"}), 400

    assets = _gather_scan_assets(data)
    if not assets:
        return jsonify({"ok": False, "error": "未选择任何资产"}), 400
    targets = []
    for a in assets:
        targets += nuclei_service.asset_target_urls(a, bool(data.get("both_schemes")))
    if not targets:
        return jsonify({"ok": False, "error": "所选资产均缺少可扫描的域名/URL"}), 400
    if len(targets) > MAX_NUCLEI_TARGETS:
        return jsonify({
            "ok": False,
            "error": f"目标过多（{len(targets)} > {MAX_NUCLEI_TARGETS}），请分批扫描或缩小筛选范围",
        }), 400

    # --- 扫描前预检（服务端强制，无法绕过） ---
    env = nuclei_service.check_environment()
    if not env["ready"]:
        reasons = "；".join(c["text"] for c in env["checks"] if c["level"] in ("err",))
        return jsonify({
            "ok": False,
            "error": "环境预检未通过，已禁止扫描。" + (f" {reasons}" if reasons else ""),
            "checks": env["checks"],
        }), 400

    proxy_url = env["proxy_url"] if env.get("proxy_ok") else ""
    cmd, err = nuclei_service.build_command(
        env["nuclei_path"], targets, mode,
        options=data.get("options") or {},
        args_text=data.get("args") or "",
        proxy_url=proxy_url,
    )
    if err:
        return jsonify({"ok": False, "error": err}), 400

    # Old findings are NOT deleted up-front anymore: the scan streams new
    # results tagged with its own scan_id while previous results stay visible,
    # and the background worker swaps generations atomically on success / keeps
    # the old results on failure (see finalize_nuclei_scan / abort_nuclei_scan).
    host_map = nuclei_service.build_host_map(assets)
    task_id = nuclei_service.start_scan(cmd, host_map, meta={
        "mode": mode,
        "assets": len(assets),
        "targets": len(targets),
        "proxy": bool(proxy_url),
        "exit_ip": env.get("exit_ip"),
        "exit_source": env.get("exit_source"),
        "asset_ids": [a["id"] for a in assets],
    })
    return jsonify({
        "ok": True,
        "task_id": task_id,
        "assets": len(assets),
        "targets": len(targets),
        "exit_ip": env.get("exit_ip"),
        "exit_source": env.get("exit_source"),
        "proxy": bool(proxy_url),
        "warnings": [c["text"] for c in env["checks"] if c["level"] in ("warn", "info")],
    })


@app.route("/api/nuclei/scan/<task_id>")
def api_nuclei_task(task_id):
    task = nuclei_service.get_task(task_id)
    if not task:
        return jsonify({"ok": False, "error": "任务不存在"}), 404
    return jsonify({"ok": True, **task})


@app.route("/api/nuclei/scan/<task_id>/stop", methods=["POST"])
def api_nuclei_task_stop(task_id):
    if not nuclei_service.stop_task(task_id):
        return jsonify({"ok": False, "error": "任务不存在"}), 404
    return jsonify({"ok": True})


@app.route("/api/assets/<int:asset_id>/nuclei")
def api_asset_nuclei_results(asset_id):
    asset = models.get_asset(asset_id)
    if not asset:
        return jsonify({"ok": False, "error": "资产不存在"}), 404
    results = models.get_asset_nuclei_results(asset_id)
    summary = models.nuclei_severity_summary(asset_id)
    return jsonify({"ok": True, "results": results, "summary": summary})


@app.route("/api/assets/<int:asset_id>/nuclei", methods=["DELETE"])
def api_asset_nuclei_clear(asset_id):
    asset = models.get_asset(asset_id)
    if not asset:
        return jsonify({"ok": False, "error": "资产不存在"}), 404
    deleted = models.clear_asset_nuclei_results(asset_id)
    return jsonify({"ok": True, "deleted": deleted})


# ---------- Asset graph + port-service identification ----------

@app.route("/api/assets/graph")
def api_assets_graph():
    """Graph payload: nodes (root/subdomain/ip/service) + edges around one
    root domain, or the Top-10 root domains when no domain is given."""
    domain = request.args.get("domain") or None
    return jsonify({"ok": True, **models.graph_data(domain)})


@app.route("/api/assets/by-ip/<ip>")
def api_assets_by_ip(ip):
    """All assets resolving to one IP (with their stored service maps).
    Used by the graph IP popup."""
    assets = models.assets_by_ip(ip)
    return jsonify({"ok": True, "assets": assets})


@app.route("/api/assets/<int:asset_id>/ports")
def api_asset_ports(asset_id):
    """Stored port-service scan result for one asset."""
    asset = models.get_asset(asset_id)
    if not asset:
        return jsonify({"ok": False, "error": "资产不存在"}), 404
    try:
        services = json.loads(asset.get("service") or "{}")
        if not isinstance(services, dict):
            services = {}
    except ValueError:
        services = {}
    return jsonify({
        "ok": True,
        "asset_id": asset_id,
        "domain": asset.get("domain"),
        "ip": asset.get("ip"),
        "port": asset.get("port"),
        "services": services,
        "ports_scanned_at": asset.get("ports_scanned_at") or "",
        "scanned": bool((asset.get("ports_scanned_at") or "").strip()),
    })


MAX_PORT_SCAN_ASSETS = 200


@app.route("/api/assets/scan-ports", methods=["POST"])
def api_assets_scan_ports():
    """Manually trigger the lightweight TCP port-service probe for selected
    assets (selected ids, or the current filtered page). `force` bypasses the
    24h dedup window (used by the graph IP popup's "立即扫描")."""
    data = request.get_json(silent=True) or {}
    ids = data.get("ids") or []
    assets = []
    if ids:
        for aid in ids[:MAX_PORT_SCAN_ASSETS]:
            a = models.get_asset(int(aid))
            if a:
                assets.append(a)
    elif data.get("use_current_page"):
        filters = {
            "search": data.get("search") or None,
            "country": data.get("country") or None,
            "cms": data.get("cms") or None,
            "source": data.get("source") or None,
            "tag": data.get("tag") or None,
            "tags_multi": data.get("tags_multi") or None,
        }
        page_assets, _ = models.list_assets(
            filters, int(data.get("page", 1)), int(data.get("per_page", 20)),
            data.get("sort", "updated_at"), data.get("order", "desc"))
        assets = page_assets
    if not assets:
        return jsonify({"ok": False, "error": "未选择资产"}), 400
    if len(ids) > MAX_PORT_SCAN_ASSETS:
        return jsonify({
            "ok": False,
            "error": f"一次最多扫描 {MAX_PORT_SCAN_ASSETS} 个资产，请分批执行",
        }), 400
    force = bool(data.get("force"))
    results = port_scanner.scan_assets(assets, force=force)
    scanned = [r for r in results if r.get("scanned")]
    skipped = [r for r in results if not r.get("scanned")]
    return jsonify({
        "ok": True,
        "scanned": len(scanned),
        "skipped": len(skipped),
        "results": results,
    })


# ---------- CSV ----------

@app.route("/api/assets/csv", methods=["POST"])
def api_csv_import():
    file = request.files.get("file")
    if not file:
        return jsonify({"ok": False, "error": "未上传文件"}), 400
    stream = io.TextIOWrapper(file.stream, encoding="utf-8")
    reader = csv.DictReader(stream)
    imported = updated = 0
    batch = []
    for row in reader:
        domain = (row.get("domain") or row.get("Domain") or "").strip()
        if not domain:
            continue
        batch.append({
            "domain": domain,
            "url": (row.get("url") or "").strip(),
            "ip": (row.get("ip") or "").strip(),
            "port": (row.get("port") or "").strip(),
            "title": (row.get("title") or "").strip(),
            "country": (row.get("country") or "").strip(),
            "cms": (row.get("cms") or "").strip(),
            "server": (row.get("server") or "").strip(),
            "waf": (row.get("waf") or "").strip(),
            "owner": (row.get("owner") or "").strip(),
            "remark": (row.get("remark") or "").strip(),
            "source": "manual",
            "tags": (row.get("tags") or "").strip(),
            "root_domain": (row.get("root_domain") or "").strip(),
        })
        # flush periodically to keep memory bounded on huge files
        if len(batch) >= 2000:
            imp, upd, _ = models.batch_upsert_assets(batch)
            imported += imp
            updated += upd
            batch = []
    if batch:
        imp, upd, _ = models.batch_upsert_assets(batch)
        imported += imp
        updated += upd
    return jsonify({"ok": True, "imported": imported, "updated": updated})


@app.route("/api/assets/export")
def api_csv_export():
    filters = {
        "search": request.args.get("search") or None,
        "country": request.args.get("country") or None,
        "cms": request.args.get("cms") or None,
        "source": request.args.get("source") or None,
        "tag": request.args.get("tag") or None,
        "tags_multi": request.args.getlist("tags") or None,
    }
    # Sharded (keyset) scan: streams the whole table in chunks, no OFFSET blowup
    assets = []
    for shard in models.iter_asset_shards(filters, shard_size=2000):
        assets.extend(shard)
    out = io.StringIO()
    writer = csv.writer(out)
    writer.writerow(["id", "domain", "url", "ip", "port", "title", "country",
                     "country_code", "cms", "server", "waf", "owner", "remark",
                     "expiration_date", "status_code", "source", "tags",
                     "root_domain", "created_at", "updated_at"])
    for a in assets:
        writer.writerow([a.get("id"), a.get("domain"), a.get("url"), a.get("ip"),
                         a.get("port"), a.get("title"), a.get("country"),
                         a.get("country_code"), a.get("cms"), a.get("server"),
                         a.get("waf"), a.get("owner"), a.get("remark"),
                         a.get("expiration_date"), a.get("status_code"),
                         a.get("source"), ",".join(a.get("tags", [])),
                         a.get("root_domain"), a.get("created_at"), a.get("updated_at")])
    return Response(
        "\ufeff" + out.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=assets.csv"},
    )


# ---------- TXT import ----------

@app.route("/api/txt-import", methods=["POST"])
def api_txt_import():
    file = request.files.get("file")
    if not file:
        return jsonify({"ok": False, "error": "未上传文件"}), 400
    stream = io.TextIOWrapper(file.stream, encoding="utf-8")
    domains = []
    for line in stream:
        d = line.strip()
        if d and not d.startswith("#"):
            domains.append(d)
    return jsonify({"ok": True, "domains": domains})


@app.route("/api/txt-import/confirm", methods=["POST"])
def api_txt_import_confirm():
    data = request.get_json(silent=True) or {}
    items = data.get("items", [])
    if not items:
        return jsonify({"ok": False, "error": "无数据"}), 400
    for it in items:
        it["source"] = "txt_import"
        if not it.get("tags"):
            it["tags"] = []
        elif isinstance(it["tags"], str):
            it["tags"] = [t.strip() for t in it["tags"].split(",") if t.strip()]
    # Batch upsert: single transaction + pre-fetched lookups
    imported, updated, _ = models.batch_upsert_assets(items)
    return jsonify({"ok": True, "imported": imported, "updated": updated})


# ---------- Settings ----------

@app.route("/api/settings", methods=["POST"])
def api_save_settings():
    data = request.get_json(silent=True) or {}
    config.update(data)
    scheduler.reinit_scheduler(app)
    return jsonify({"ok": True})


@app.route("/api/stats")
def api_stats():
    return jsonify({"ok": True, **models.dashboard_stats()})


@app.route("/api/tags")
def api_tags():
    return jsonify({"ok": True, "tags": models.all_tags()})


@app.route("/api/tags/add", methods=["POST"])
def api_tag_add():
    data = request.get_json(silent=True) or {}
    ok, msg = models.add_tag(data.get("name"))
    if not ok:
        return jsonify({"ok": False, "error": msg}), 400
    return jsonify({"ok": True, "message": msg})


@app.route("/api/tags/delete", methods=["POST"])
def api_tag_delete():
    data = request.get_json(silent=True) or {}
    ok = models.delete_tag(data.get("name"))
    if not ok:
        return jsonify({"ok": False, "error": "标签不存在或已删除"}), 404
    return jsonify({"ok": True})


# ---------- Dict options (country / cms / source dictionaries) ----------

@app.route("/api/dict")
def api_dict_list():
    dtype = request.args.get("type") or None
    return jsonify({"ok": True, "options": models.list_dict_options(dtype)})


@app.route("/api/dict/add", methods=["POST"])
def api_dict_add():
    data = request.get_json(silent=True) or {}
    ok, msg = models.add_dict_option(data.get("type"), data.get("value"))
    if not ok:
        return jsonify({"ok": False, "error": msg}), 400
    return jsonify({"ok": True, "message": msg})


@app.route("/api/dict/delete", methods=["POST"])
def api_dict_delete():
    data = request.get_json(silent=True) or {}
    deleted = models.delete_dict_option(data.get("type"), data.get("value"))
    if not deleted:
        return jsonify({"ok": False, "error": "选项不存在或已删除"}), 404
    return jsonify({"ok": True})


@app.route("/api/changelog")
def api_changelog():
    return jsonify({"ok": True, "changelog": models.recent_changelog(50)})


# ---------- AI assistant ----------

REPORTS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "reports")


@app.route("/reports/<path:filename>")
def reports_file(filename):
    os.makedirs(REPORTS_DIR, exist_ok=True)
    return send_from_directory(REPORTS_DIR, filename)


@app.route("/api/ai/sessions", methods=["GET", "POST"])
def api_ai_sessions():
    if request.method == "POST":
        return jsonify({"ok": True, "session": models.create_chat_session()})
    return jsonify({"ok": True, "sessions": models.list_chat_sessions()})


@app.route("/api/ai/sessions/<session_id>", methods=["GET", "DELETE"])
def api_ai_session(session_id):
    sess = models.get_chat_session(session_id)
    if not sess:
        return jsonify({"ok": False, "error": "会话不存在"}), 404
    if request.method == "DELETE":
        models.delete_chat_session(session_id)
        return jsonify({"ok": True})
    return jsonify({"ok": True, "session": sess,
                    "messages": models.get_chat_messages(session_id)})


@app.route("/api/ai/sessions/<session_id>/rename", methods=["POST"])
def api_ai_session_rename(session_id):
    data = request.get_json(silent=True) or {}
    title = (data.get("title") or "").strip()
    if not title:
        return jsonify({"ok": False, "error": "标题不能为空"}), 400
    models.update_chat_session_title(session_id, title)
    return jsonify({"ok": True})


@app.route("/api/ai/chat", methods=["POST"])
def api_ai_chat():
    data = request.get_json(silent=True) or {}
    session_id = (data.get("session_id") or "").strip()
    message = (data.get("message") or "").strip()
    if not session_id or not message:
        return jsonify({"ok": False, "error": "缺少 session_id 或消息内容"}), 400
    if not ai_assistant.session_exists(session_id):
        return jsonify({"ok": False, "error": "会话不存在"}), 404

    def gen():
        for ev in ai_assistant.chat_events(session_id, message):
            yield f"data: {json.dumps(ev, ensure_ascii=False)}\n\n"

    return Response(stream_with_context(gen()), mimetype="text/event-stream")


@app.route("/api/ai/confirm", methods=["POST"])
def api_ai_confirm():
    """User decides on a dangerous tool call (approve / reject).
    Returns an SSE stream continuing the conversation."""
    data = request.get_json(silent=True) or {}
    session_id = (data.get("session_id") or "").strip()
    confirm_id = (data.get("confirm_id") or "").strip()
    if not session_id or not confirm_id:
        return jsonify({"ok": False, "error": "参数不完整"}), 400
    approve = bool(data.get("approve"))

    def gen():
        for ev in ai_assistant.resume_after_confirm(session_id, confirm_id, approve):
            yield f"data: {json.dumps(ev, ensure_ascii=False)}\n\n"

    return Response(stream_with_context(gen()), mimetype="text/event-stream")


@app.route("/api/ai/tool-log")
def api_ai_tool_log():
    return jsonify({"ok": True, "log": models.recent_ai_tool_log(50)})


@app.route("/api/ai/call-log")
def api_ai_call_log():
    return jsonify({"ok": True, "log": models.recent_ai_call_log(50),
                    "summary": models.ai_cost_summary()})


@app.route("/api/ai/models")
def api_ai_models():
    """Enabled providers + their selectable models for the chat model picker."""
    providers, default = ai_providers.list_picker_models()
    return jsonify({"ok": True, "providers": providers, "default": default})


@app.route("/api/ai/sessions/<session_id>/model", methods=["POST"])
def api_ai_session_model(session_id):
    """Set which model ('provider:model', or '' = global default) the session's
    NEXT turn will use."""
    if not models.get_chat_session(session_id):
        return jsonify({"ok": False, "error": "会话不存在"}), 404
    data = request.get_json(silent=True) or {}
    model = (data.get("model") or "").strip()
    if model:
        name, mid = ai_providers.split_model_key(model)
        prow = models.get_ai_provider(name) if name else None
        valid = (prow and prow.get("enabled")
                 and (mid == prow.get("model") or mid in (prow.get("models_list") or [])))
        if not valid:
            return jsonify({"ok": False, "error": "无效或未启用的模型"}), 400
    models.set_chat_session_model(session_id, model)
    return jsonify({"ok": True})


@app.route("/api/ai/providers", methods=["GET", "POST"])
def api_ai_providers():
    """GET: all provider rows (keys masked) for the settings page.
    POST: bulk-save provider edits from the settings page."""
    if request.method == "GET":
        return jsonify({"ok": True, "providers": models.list_ai_providers(True)})
    data = request.get_json(silent=True) or {}
    items = data.get("providers") or []
    if not items:
        return jsonify({"ok": False, "error": "无数据"}), 400
    errors = []
    for it in items:
        name = (it.get("name") or "").strip()
        if not name:
            errors.append("缺少 provider name")
            continue
        row = dict(it)
        # normalize models list -> JSON string column
        if isinstance(row.get("models"), list):
            row["models"] = json.dumps(row["models"], ensure_ascii=False)
        elif isinstance(row.get("models"), str):
            parts = [p.strip() for p in row["models"].replace("，", ",").split(",") if p.strip()]
            row["models"] = json.dumps(parts, ensure_ascii=False)
        # provider_type must be one of the two adapters
        ptype = (row.get("provider_type") or "openai_compat").strip().lower()
        row["provider_type"] = ptype if ptype in ("openai_compat", "anthropic") else "openai_compat"
        _, err = models.save_ai_provider(row)
        if err:
            errors.append(f"{name}: {err}")
    # keep a default selected whenever something is enabled
    models.clear_default_ai_provider()
    return jsonify({"ok": not errors, "errors": errors,
                    "providers": models.list_ai_providers(True)})


@app.route("/api/ai/providers/test", methods=["POST"])
def api_ai_provider_test():
    """Probe one provider with (possibly unsaved) form values, so the settings
    page can test credentials before saving."""
    data = request.get_json(silent=True) or {}
    res = ai_providers.test_connection(data)
    return jsonify({"ok": bool(res.get("ok")), **res})


if __name__ == "__main__":
    scheduler.init_scheduler(app)
    app.run(host="0.0.0.0", port=5000, debug=True)
