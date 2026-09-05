"""Smoke tests: dict options CRUD, asset auto-registration, CVE guard + lookup, TXT import.

Run:  python -m unittest test_smoke -v
Uses a temporary database; does not touch assets.db data (only ensures schema exists).
"""
import os
import sqlite3
import tempfile
import unittest
import json
from unittest import mock

import requests

import db
import models
import config
import cache
# Use a temp DB BEFORE importing app (app calls db.init_db() at import time).
db.DB_PATH = os.path.join(tempfile.mkdtemp(), "test_assets.db")

import app as app_module
import scanner
import nuclei_service
import ai_assistant
import ai_providers
import port_scanner


class SmokeTest(unittest.TestCase):
    def setUp(self):
        db.init_db()
        # Seed builtin providers and enable DeepSeek with a test key so chat
        # tests are deterministic regardless of test ordering.
        ai_providers.ensure_seeded()
        models.save_ai_provider({
            "name": "deepseek", "api_key": "test-key",
            "enabled": True, "is_default": True,
        })
        # Never auto-trigger real socket scans from discovery in tests.
        config.set("port_scan_auto_enabled", "false")
        self.client = app_module.app.test_client()

    def test_dict_defaults_and_crud(self):
        r = self.client.get("/api/dict").get_json()
        self.assertTrue(r["ok"])
        self.assertIn("中国", r["options"]["country"])
        self.assertIn("WordPress", r["options"]["cms"])
        self.assertIn("fofa", r["options"]["source"])

        # add
        r = self.client.post("/api/dict/add", json={"type": "country", "value": "越南"}).get_json()
        self.assertTrue(r["ok"])
        r = self.client.get("/api/dict?type=country").get_json()
        self.assertIn("越南", r["options"])
        # duplicate add is idempotent
        r = self.client.post("/api/dict/add", json={"type": "country", "value": "越南"}).get_json()
        self.assertTrue(r["ok"])
        # invalid type rejected
        r = self.client.post("/api/dict/add", json={"type": "bogus", "value": "x"})
        self.assertEqual(r.status_code, 400)
        # delete existing
        r = self.client.post("/api/dict/delete", json={"type": "country", "value": "越南"}).get_json()
        self.assertTrue(r["ok"])
        # delete nonexistent -> 404
        resp = self.client.post("/api/dict/delete", json={"type": "country", "value": "越南"})
        self.assertEqual(resp.status_code, 404)

    def test_asset_add_auto_registers_options(self):
        r = self.client.post("/api/assets/add", json={
            "domain": "test.example.com",
            "country": "马耳他", "cms": "WebLogic", "source": "manual",
        }).get_json()
        self.assertTrue(r["ok"])
        opts = self.client.get("/api/dict").get_json()["options"]
        self.assertIn("马耳他", opts["country"])
        self.assertIn("WebLogic", opts["cms"])

    def test_cve_fingerprint_guard(self):
        r = self.client.post("/api/assets/add", json={"domain": "bare.example.com"}).get_json()
        aid = r["asset"]["id"]
        resp = self.client.get(f"/api/assets/{aid}/cve")
        self.assertEqual(resp.status_code, 400)
        body = resp.get_json()
        self.assertFalse(body["ok"])
        self.assertIn("请先完善资产指纹信息", body["error"])

    def test_cve_lookup_with_mock(self):
        r = self.client.post("/api/assets/add", json={
            "domain": "wp.example.com", "server": "nginx/1.18.0", "cms": "WordPress 5.9",
        }).get_json()
        aid = r["asset"]["id"]
        fake = {
            "vulnerabilities": [
                {"cve": {"id": "CVE-2021-23017", "descriptions": [{"lang": "en", "value": "nginx resolver"}],
                         "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 7.7}}]},
                         "published": "2021-09-01T00:00:00"}},
                {"cve": {"id": "CVE-2021-23017", "descriptions": [{"lang": "en", "value": "dup"}],
                         "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 7.7}}]},
                         "published": "2021-09-01T00:00:00"}},
                {"cve": {"id": "CVE-2019-9511", "descriptions": [{"lang": "en", "value": "HTTP/2"}],
                         "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 5.3}}]},
                         "published": "2019-08-13T00:00:00"}},
            ]
        }
        with mock.patch("nvd.requests.get",
                        return_value=mock.Mock(raise_for_status=lambda: None, json=lambda: fake)):
            body = self.client.get(f"/api/assets/{aid}/cve").get_json()
        self.assertTrue(body["ok"])
        self.assertEqual(len(body["cves"]), 2)  # deduped
        self.assertEqual(body["cves"][0]["id"], "CVE-2021-23017")  # sorted by CVSS desc
        self.assertIn("nginx 1.18.0", body["keywords"])

    def test_txt_import_confirm(self):
        r = self.client.post("/api/txt-import/confirm", json={
            "items": [
                {"domain": "a.example.com", "country": "韩国", "cms": "Tomcat", "tags": "官网,测试", "source": "txt_import"},
                {"domain": "b.example.com", "country": "", "cms": "", "tags": "", "source": "txt_import"},
            ]
        }).get_json()
        self.assertTrue(r["ok"])
        self.assertEqual(r["imported"], 2)
        # re-import => update, not new
        r = self.client.post("/api/txt-import/confirm", json={
            "items": [{"domain": "a.example.com", "country": "韩国", "cms": "Tomcat",
                       "tags": "官网,测试", "source": "txt_import"}]
        }).get_json()
        self.assertEqual(r["updated"], 1)

    def test_tag_management(self):
        # add custom tag
        r = self.client.post("/api/tags/add", json={"name": "项目A"}).get_json()
        self.assertTrue(r["ok"])
        self.assertIn("项目A", self.client.get("/api/tags").get_json()["tags"])
        # empty name rejected
        resp = self.client.post("/api/tags/add", json={"name": "  "})
        self.assertEqual(resp.status_code, 400)
        # tag usable on assets and counts appear
        self.client.post("/api/assets/add", json={"domain": "tagged.example.com", "tags": "项目A,核心资产"})
        tags = self.client.get("/api/tags").get_json()["tags"]
        self.assertEqual(tags.get("项目A"), 1)
        # delete detaches from assets
        r = self.client.post("/api/tags/delete", json={"name": "项目A"}).get_json()
        self.assertTrue(r["ok"])
        self.assertNotIn("项目A", self.client.get("/api/tags").get_json()["tags"])
        # asset remains, tag removed
        assets = self.client.get("/api/assets?search=tagged.example.com").get_json()["assets"]
        self.assertEqual(assets[0]["tags"], ["核心资产"])
        # deleting nonexistent -> 404
        resp = self.client.post("/api/tags/delete", json={"name": "项目A"})
        self.assertEqual(resp.status_code, 404)

    def test_pages_render(self):
        for path in ("/", "/search", "/scan", "/assets", "/txt-import", "/ai", "/graph", "/settings"):
            resp = self.client.get(path)
            self.assertEqual(resp.status_code, 200, path)

    def test_single_asset_get_and_server_search(self):
        self.client.post("/api/assets/add", json={
            "domain": "gs.example.com", "server": "nginx/1.18.0", "cms": "WordPress",
            "source": "manual", "tags": "核心资产",
        })
        assets = self.client.get("/api/assets").get_json()["assets"]
        aid = next(a["id"] for a in assets if a["domain"] == "gs.example.com")
        body = self.client.get(f"/api/assets/{aid}").get_json()
        self.assertTrue(body["ok"])
        self.assertEqual(body["asset"]["domain"], "gs.example.com")
        # server field must be searchable (previously it was not)
        r = self.client.get("/api/assets?search=nginx").get_json()
        self.assertTrue(any(a["domain"] == "gs.example.com" for a in r["assets"]))

    def test_scan_applies_manual_tags(self):
        def fake_item(src):
            return {"domain": "t1.example.com", "url": "t1.example.com", "ip": "1.2.3.4",
                    "port": "80", "title": "", "country": "", "country_code": "", "cms": "",
                    "server": "", "waf": "None", "status_code": None, "source": src,
                    "tags": [src], "root_domain": "example.com"}
        with mock.patch("scanner.scan_crtsh", return_value=[fake_item("crt")]), \
             mock.patch("scanner.scan_crtname", return_value=([fake_item("crtname")], None)), \
             mock.patch("scanner.scan_fofa", return_value=([], None)):
            summary, discovered = scanner.scan_root_domain("example.com", tags="项目A,核心资产")
        self.assertEqual(len(discovered), 1)
        self.assertEqual(discovered[0]["change_type"], "新增")
        self.assertEqual(summary["tags"], ["项目A", "核心资产"])
        asset = self.client.get(f"/api/assets/{discovered[0]['id']}").get_json()["asset"]
        self.assertIn("项目A", asset["tags"])
        self.assertIn("核心资产", asset["tags"])
        # auto tag stays too
        self.assertIn("crt", asset["tags"])

    def test_batch_import_and_shard_scan(self):
        """Batch upsert: single transaction, correct counts, tags merged."""
        items = [{"domain": f"bulk{i}.example.com", "country": "中国", "cms": "Tomcat",
                  "tags": ["批量"]} for i in range(50)]
        imported, updated, unchanged = models.batch_upsert_assets(items, chunk_size=7)
        self.assertEqual(imported, 50)
        self.assertEqual(updated, 0)
        self.assertEqual(unchanged, 0)

        # re-import with a real change -> counted as updates, tags preserved
        upd = [{"domain": f"bulk{i}.example.com", "country": "美国"} for i in range(50)]
        imported, updated, unchanged = models.batch_upsert_assets(upd, chunk_size=7)
        self.assertEqual(imported, 0)
        self.assertEqual(updated, 50)
        a = models.get_asset_by_domain("bulk0.example.com")
        self.assertEqual(a["country"], "美国")
        self.assertIn("批量", a["tags"])  # existing tag kept

        # sharded (keyset) scan: every asset exactly once, in id order
        seen = []
        for shard in models.iter_asset_shards(shard_size=11):
            seen.extend(shard)
        ids = [a["id"] for a in seen]
        self.assertEqual(len(ids), len(set(ids)))
        self.assertEqual(ids, sorted(ids))
        self.assertGreaterEqual(len(ids), 50)
        # max_shards caps the yield
        capped = sum(len(s) for s in models.iter_asset_shards(shard_size=11, max_shards=2))
        self.assertLessEqual(capped, 22)

        # items without a domain are skipped, rest still imported
        mixed = [{"domain": f"roll{i}.example.com"} for i in range(5)] + [{}]
        imported, updated, unchanged = models.batch_upsert_assets(mixed)
        self.assertEqual(imported, 5)
        self.assertEqual(unchanged, 0)

    def test_fts_search_and_sync(self):
        """FTS5: insert/update/delete stay searchable; special chars are safe."""
        if not db.FTS_AVAILABLE:
            self.skipTest("FTS5 not available in this SQLite build")
        self.client.post("/api/assets/add", json={
            "domain": "fts.example.com", "server": "nginx/1.18.0",
            "title": "管理后台 Dashboard", "source": "manual",
        })
        aid = models.get_asset_by_domain("fts.example.com")["id"]

        r = self.client.get("/api/assets?search=nginx").get_json()
        self.assertTrue(any(a["domain"] == "fts.example.com" for a in r["assets"]))
        r = self.client.get("/api/assets?search=管理").get_json()
        self.assertTrue(any(a["domain"] == "fts.example.com" for a in r["assets"]))
        # special characters must not break the MATCH expression
        r = self.client.get("/api/assets?search=nginx OR x ()").get_json()
        self.assertTrue(r["ok"])

        # update propagates into the index
        self.client.put(f"/api/assets/{aid}", json={"cms": "WordPress 5.9"})
        r = self.client.get("/api/assets?search=wordpress").get_json()
        self.assertTrue(any(a["domain"] == "fts.example.com" for a in r["assets"]))

        # delete removes it from the index
        self.client.delete(f"/api/assets/{aid}")
        r = self.client.get("/api/assets?search=nginx").get_json()
        self.assertFalse(any(a["domain"] == "fts.example.com" for a in r["assets"]))

    def test_dashboard_stats_cached_and_invalidated(self):
        s1 = models.dashboard_stats()
        s2 = models.dashboard_stats()
        self.assertIs(s1, s2)  # served from cache
        self.client.post("/api/assets/add", json={"domain": "cache-test.example.com"})
        s3 = models.dashboard_stats()
        self.assertEqual(s3["total"], s1["total"] + 1)  # invalidated after write

    def test_scan_root_domains_parallel(self):
        def fake(src, dom):
            return {"domain": dom, "url": dom, "ip": "1.2.3.4", "port": "80",
                    "title": "", "country": "", "country_code": "", "cms": "",
                    "server": "", "waf": "None", "status_code": None, "source": src,
                    "tags": [src], "root_domain": "example.com"}
        with mock.patch("scanner.scan_crtsh", side_effect=lambda dom: [fake("crt", dom)]), \
             mock.patch("scanner.scan_crtname", return_value=([], None)), \
             mock.patch("scanner.scan_fofa", return_value=([], None)):
            results = scanner.scan_root_domains(["pa.example.com", "pb.example.com"],
                                                concurrency=2, auto_fingerprint=False)
        self.assertEqual(len(results), 2)
        self.assertEqual(sorted(d for d, _, _ in results), ["pa.example.com", "pb.example.com"])
        for _, summary, discovered in results:
            self.assertEqual(len(discovered), 1)
            self.assertEqual(discovered[0]["change_type"], "新增")

    # ---------- nuclei ----------

    def test_nuclei_advanced_args_safety(self):
        # normal advanced args pass through
        tokens, err = nuclei_service.validate_advanced_args("-id log4shell -severity critical")
        self.assertEqual(err, "")
        self.assertEqual(tokens, ["-id", "log4shell", "-severity", "critical"])
        # empty rejected
        _, err = nuclei_service.validate_advanced_args("   ")
        self.assertIn("请输入", err)
        # shell metacharacters rejected
        tokens, err = nuclei_service.validate_advanced_args("-id x; rm -rf /")
        self.assertIsNone(tokens)
        self.assertIn("非法字符", err)
        # flags that would override system-managed behaviour are blocked
        for bad in ("-u http://evil.example.com", "-json", "-o out.txt",
                    "-proxy http://127.0.0.1:9999", "-l targets.txt"):
            tokens, err = nuclei_service.validate_advanced_args(bad)
            self.assertIsNone(tokens, bad)
            self.assertIn("禁止", err)
        # unclosed quote -> format error
        tokens, err = nuclei_service.validate_advanced_args('-tags "abc')
        self.assertIsNone(tokens)
        self.assertIn("引号", err)

    def test_nuclei_build_command_appends_mandatory(self):
        exe = "/fake/nuclei"
        cmd, err = nuclei_service.build_command(
            exe, ["https://a.example.com", "https://b.example.com"],
            mode="advanced", args_text="-id log4shell",
            proxy_url="http://127.0.0.1:7890",
        )
        self.assertIsNone(err)
        self.assertEqual(cmd[0], exe)
        self.assertEqual(cmd.count("-u"), 2)          # one per target, appended
        self.assertLess(cmd.index("-id"), cmd.index("-u"))
        self.assertLess(cmd.index("-json"), cmd.index("-proxy"))  # mandatory after user tokens
        self.assertEqual(cmd[-2:], ["-proxy", "http://127.0.0.1:7890"])

        # visual mode: passive default on, removable; no free text
        cmd, _ = nuclei_service.build_command(exe, ["https://x.example.com"],
                                              mode="visual", options={}, proxy_url="")
        self.assertIn("-passive", cmd)
        cmd, _ = nuclei_service.build_command(exe, ["https://x.example.com"],
                                              mode="visual", options={"passive": False,
                                              "severity": "high,critical"}, proxy_url="")
        self.assertNotIn("-passive", cmd)
        self.assertEqual(cmd[cmd.index("-severity") + 1], "high,critical")
        # blocked override inside build_command surfaces as an error
        _, err = nuclei_service.build_command(exe, ["https://x.example.com"],
                                              mode="advanced",
                                              args_text="-proxy http://oops.example.com")
        self.assertIn("禁止", err)
        # no executable / no targets
        _, err = nuclei_service.build_command("", ["https://x.example.com"])
        self.assertIn("未找到", err)
        _, err = nuclei_service.build_command(exe, [])
        self.assertIn("没有可扫描", err)

    def test_nuclei_parse_and_host_map(self):
        assets = [
            {"id": 1, "domain": "a.example.com", "url": "https://a.example.com",
             "ip": "1.1.1.1", "port": "443"},
            {"id": 2, "domain": "b.example.com", "url": "", "ip": "2.2.2.2", "port": "8080"},
        ]
        hm = nuclei_service.build_host_map(assets)
        self.assertEqual(nuclei_service.lookup_asset(hm, "https://a.example.com"), 1)
        self.assertEqual(nuclei_service.lookup_asset(hm, "a.example.com:443"), 1)  # port stripped
        self.assertEqual(nuclei_service.lookup_asset(hm, "http://2.2.2.2:8080/x"), 2)
        self.assertIsNone(nuclei_service.lookup_asset(hm, "https://other.example.com"))

        line = {
            "template-id": "log4shell", "host": "https://a.example.com",
            "type": "http",
            "info": {"name": "Log4Shell", "severity": "critical", "description": "desc",
                      "classification": {"cve-id": ["CVE-2021-44228"]}},
            "matched-at": "https://a.example.com/", "extracted-results": ["x", "y"],
            "curl-command": "curl -k ...",
        }
        f = nuclei_service.parse_finding(line, hm)
        self.assertIsNotNone(f)
        self.assertEqual(f["asset_id"], 1)
        self.assertEqual(f["severity"], "critical")
        self.assertEqual(f["template_name"], "Log4Shell")
        self.assertEqual(f["vuln_type"], "CVE-2021-44228")
        self.assertEqual(f["extracted_results"], "x | y")
        # junk / unusable lines -> None
        self.assertIsNone(nuclei_service.parse_finding({}, hm))
        self.assertIsNone(nuclei_service.parse_finding({"host": "x"}, hm))
        self.assertIsNone(nuclei_service.parse_finding("not-a-dict", hm))
        # template-id only (no host) still kept
        self.assertIsNotNone(nuclei_service.parse_finding({"template-id": "tpl", "info": {}}, hm))

    def test_nuclei_results_db_roundtrip_and_api(self):
        self.client.post("/api/assets/add", json={"domain": "nuclei.example.com"})
        aid = models.get_asset_by_domain("nuclei.example.com")["id"]
        rows = [
            {"asset_id": aid, "host": "https://nuclei.example.com",
             "template_id": "cve-2021-44228", "template_name": "Log4Shell",
             "severity": "critical", "vuln_type": "CVE-2021-44228",
             "description": "d", "matched_at": "https://nuclei.example.com/",
             "extracted_results": "x", "curl_command": "", "raw_json": "{}",
             "created_at": "2026-01-01T00:00:00"},
            {"asset_id": aid, "host": "https://nuclei.example.com",
             "template_id": "http-missing-security-headers", "template_name": "Missing Headers",
             "severity": "low", "vuln_type": "", "description": "",
             "matched_at": "", "extracted_results": "", "curl_command": "",
             "raw_json": "{}", "created_at": "2026-01-02T00:00:00"},
        ]
        self.assertEqual(models.insert_nuclei_results(rows), 2)
        results = models.get_asset_nuclei_results(aid)
        self.assertEqual(len(results), 2)
        self.assertEqual(results[0]["severity"], "critical")  # critical first
        self.assertEqual(models.nuclei_severity_summary(aid)["critical"], 1)

        # api surface
        body = self.client.get(f"/api/assets/{aid}/nuclei").get_json()
        self.assertTrue(body["ok"])
        self.assertEqual(len(body["results"]), 2)
        self.assertEqual(body["summary"]["low"], 1)
        # asset not found -> 404
        self.assertEqual(self.client.get("/api/assets/999999/nuclei").status_code, 404)
        # clear via API
        resp = self.client.delete(f"/api/assets/{aid}/nuclei")
        self.assertEqual(resp.get_json()["deleted"], 2)
        self.assertEqual(self.client.get(f"/api/assets/{aid}/nuclei").get_json()["results"], [])

    def test_nuclei_scan_blocked_when_proxy_broken(self):
        """Server-side preflight must refuse the scan when the configured proxy
        is unreachable (network probe mocked, no real requests)."""
        self.client.post("/api/assets/add", json={"domain": "blocked.example.com"})
        aid = models.get_asset_by_domain("blocked.example.com")["id"]
        config.set("proxy_enabled", "true")
        config.set("proxy_url", "http://127.0.0.1:1")
        try:
            def boom(url, *a, **kw):
                raise requests.exceptions.ConnectTimeout("mocked timeout")
            with mock.patch("nuclei_service.requests.get", side_effect=boom):
                resp = self.client.post("/api/nuclei/scan", json={"ids": [aid], "mode": "visual"})
            self.assertEqual(resp.status_code, 400)
            body = resp.get_json()
            self.assertFalse(body["ok"])
            self.assertIn("环境预检未通过", body["error"])
            levels = [c["level"] for c in body["checks"]]
            self.assertIn("err", levels)  # colored error surfaced to the UI
        finally:
            config.set("proxy_enabled", "false")
            config.set("proxy_url", "")

    # ---------- asset graph + port-service identification ----------

    def test_port_service_detection_and_dedup(self):
        """detect_service/parse_ports are pure logic; scan_assets persists
        results and honors the 24h dedup (probe fully mocked, no sockets)."""
        self.assertEqual(port_scanner.detect_service("SSH-2.0-OpenSSH", 22), "SSH")
        self.assertEqual(port_scanner.detect_service(b"SSH-2.0-OpenSSH", 22), "SSH")
        self.assertEqual(port_scanner.detect_service("HTTP/1.1 200 OK", 80), "HTTP")
        self.assertEqual(port_scanner.detect_service("mysql_native_password", 3306), "MySQL")
        self.assertEqual(port_scanner.detect_service("", 443), "HTTPS")     # TLS default
        self.assertEqual(port_scanner.detect_service("", 8080), "HTTP")     # web default
        self.assertEqual(port_scanner.detect_service("", 9999), "")         # unknown
        self.assertEqual(port_scanner.parse_ports("21, 22,3306, 99999,0"), [21, 22, 3306])
        self.assertEqual(port_scanner.parse_services('{"80":"HTTP"}'), {"80": "HTTP"})

        # two assets on one IP + one on another
        self.client.post("/api/assets/add", json={"domain": "ps1.example.com",
                                                   "ip": "10.0.0.1", "root_domain": "example.com"})
        self.client.post("/api/assets/add", json={"domain": "ps2.example.com",
                                                   "ip": "10.0.0.1", "root_domain": "example.com"})
        self.client.post("/api/assets/add", json={"domain": "ps3.example.com",
                                                   "ip": "10.0.0.2", "root_domain": "example.com"})
        assets = [
            models.get_asset(models.get_asset_by_domain("ps1.example.com")["id"]),
            models.get_asset(models.get_asset_by_domain("ps2.example.com")["id"]),
            models.get_asset(models.get_asset_by_domain("ps3.example.com")["id"]),
        ]

        def fake_probe(ip, port, timeout):
            if port == 22:
                return b"SSH-2.0-OpenSSH"
            if port == 80:
                return b"HTTP/1.1 400 Bad Request"
            return None

        with mock.patch("port_scanner._probe", side_effect=fake_probe):
            res = port_scanner.scan_assets(assets, force=True)
        self.assertEqual(len([r for r in res if r["scanned"]]), 3)
        a1 = models.get_asset_by_domain("ps1.example.com")
        self.assertEqual(a1["port"], "22,80")
        self.assertEqual(port_scanner.parse_services(a1["service"]),
                         {"22": "SSH", "80": "HTTP"})
        self.assertTrue(a1["ports_scanned_at"])
        a3 = models.get_asset_by_domain("ps3.example.com")
        self.assertEqual(a3["port"], "")

        # 24h window: a non-forced rescan is skipped and the timestamp kept
        ts_before = a1["ports_scanned_at"]
        with mock.patch("port_scanner._probe", side_effect=fake_probe):
            res2 = port_scanner.scan_assets([a1])
        self.assertEqual(res2[0]["scanned"], False)
        self.assertIn("24 小时", res2[0]["skip_reason"])
        self.assertEqual(models.get_asset_by_domain("ps1.example.com")["ports_scanned_at"],
                         ts_before)
        # manual force bypasses the window
        with mock.patch("port_scanner._probe", side_effect=fake_probe):
            res3 = port_scanner.scan_assets([a1], force=True)
        self.assertEqual(res3[0]["scanned"], True)

        # assets_by_ip groups both hosts of the shared IP
        rows = models.assets_by_ip("10.0.0.1")
        self.assertEqual(sorted(r["domain"] for r in rows),
                         ["ps1.example.com", "ps2.example.com"])
        self.assertIn("service_map", rows[0])
        # asset detail ports endpoint exposes the map
        body = self.client.get(f"/api/assets/{a1['id']}/ports").get_json()
        self.assertTrue(body["ok"])
        self.assertEqual(body["services"], {"22": "SSH", "80": "HTTP"})
        self.assertTrue(body["scanned"])
        self.assertEqual(self.client.get("/api/assets/999999/ports").status_code, 404)

    def test_asset_graph_api(self):
        """graph payload: node types/colors source + edges; Top-10 fallback;
        unknown domain -> empty."""
        self.client.post("/api/assets/add", json={
            "domain": "www.g.example.com", "ip": "10.1.1.10", "port": "443",
            "root_domain": "g.example.com"})
        self.client.post("/api/assets/add", json={
            "domain": "api.g.example.com", "ip": "10.1.1.11",
            "root_domain": "g.example.com"})
        # give one asset a service map
        aid = models.get_asset_by_domain("www.g.example.com")["id"]
        models.save_port_scan_result(aid, {"443": "HTTPS", "80": "HTTP"})

        body = self.client.get("/api/assets/graph",
                               query_string={"domain": "g.example.com"}).get_json()
        self.assertTrue(body["ok"])
        types = {n["type"] for n in body["nodes"]}
        self.assertEqual(types, {"root", "subdomain", "ip", "service"})
        names = {n["name"] for n in body["nodes"]}
        self.assertIn("g.example.com", names)
        self.assertIn("www.g.example.com", names)
        self.assertIn("10.1.1.10", names)
        self.assertIn("443:HTTPS", names)
        roots = [e for e in body["edges"] if e["source"].startswith("root:")]
        self.assertEqual(len(roots), 2)
        ip_edges = [e for e in body["edges"] if e["target"].startswith("svc:")]
        self.assertEqual(len(ip_edges), 2)
        # subdomain nodes carry asset ids for the click-through
        sub = next(n for n in body["nodes"] if n["name"] == "www.g.example.com")
        self.assertEqual(sub["asset_id"], aid)

        # no domain -> Top-10 roots include g.example.com
        top = self.client.get("/api/assets/graph").get_json()
        self.assertTrue(top["ok"])
        self.assertIn("g.example.com", {r["root"] for r in top["roots"]})
        # unknown root domain -> zero nodes, still ok
        miss = self.client.get("/api/assets/graph",
                               query_string={"domain": "nope.invalid"}).get_json()
        self.assertTrue(miss["ok"])
        self.assertEqual(miss["nodes"], [])

    def test_port_scan_api_endpoints(self):
        """Manual trigger endpoint resolves ids / current page; mocked probes."""
        self.client.post("/api/assets/add", json={"domain": "scan.api.example.com",
                                                   "ip": "10.9.9.9", "root_domain": "scan.example.com"})
        aid = models.get_asset_by_domain("scan.api.example.com")["id"]

        def fake_probe(ip, port, timeout):
            return b"SSH-2.0-OpenSSH" if port == 22 else None

        with mock.patch("port_scanner._probe", side_effect=fake_probe):
            resp = self.client.post("/api/assets/scan-ports",
                                    json={"ids": [aid], "force": True})
        body = resp.get_json()
        self.assertTrue(body["ok"])
        self.assertEqual(body["scanned"], 1)
        self.assertEqual(body["results"][0]["summary"], "22:SSH")
        # no selection at all -> 400
        resp = self.client.post("/api/assets/scan-ports", json={})
        self.assertEqual(resp.status_code, 400)
        # by-ip endpoint used by the graph IP popup
        byip = self.client.get("/api/assets/by-ip/10.9.9.9").get_json()
        self.assertTrue(byip["ok"])
        self.assertEqual(byip["assets"][0]["domain"], "scan.api.example.com")

    # ---------- P0/P1/P2 hardening ----------

    def test_batch_upsert_unique_race_recovery(self):
        """Simulate the cross-connection UNIQUE race (another writer committed
        a domain between our prefetch SELECT and the INSERT): the chunk must
        recover by re-reading the row and applying it as an update instead of
        aborting all 500 rows."""
        self.client.post("/api/assets/add", json={"domain": "race.example.com", "cms": "旧"})
        # Force the prefetch to see NO existing rows although the domain exists,
        # exactly what happens when a concurrent writer commits mid-batch.
        with mock.patch("models._prefetch_chunk", return_value=({}, {})):
            imported, updated, unchanged = models.batch_upsert_assets(
                [{"domain": "race.example.com", "cms": "新", "tags": ["赛后标签"]}]
            )
        self.assertEqual((imported, updated, unchanged), (0, 1, 0))
        a = models.get_asset_by_domain("race.example.com")
        self.assertEqual(a["cms"], "新")
        self.assertIn("赛后标签", a["tags"])
        log = models.recent_changelog(50)
        upd = [l for l in log if l["domain"] == "race.example.com" and l["change_type"] == "更新"]
        self.assertEqual(len(upd), 1)  # accurate old->new changelog preserved

    def test_busy_retry_wrapper(self):
        """db.retry_on_busy: transient "database is locked" is retried with
        backoff; unrelated errors propagate immediately."""
        calls = {"n": 0}

        def flaky():
            calls["n"] += 1
            if calls["n"] < 3:
                raise sqlite3.OperationalError("database is locked")
            return "ok"

        self.assertEqual(db.retry_on_busy(flaky, attempts=5, base=0.01), "ok")
        self.assertEqual(calls["n"], 3)
        with self.assertRaises(sqlite3.OperationalError):
            db.retry_on_busy(
                lambda: (_ for _ in ()).throw(sqlite3.OperationalError("no such table")),
                attempts=3, base=0.01,
            )

    def test_nuclei_generation_swap_atomic(self):
        """Old findings stay visible while a scan runs; finalize swaps
        generations atomically; abort keeps the previous results."""
        self.client.post("/api/assets/add", json={"domain": "swap.example.com"})
        aid = models.get_asset_by_domain("swap.example.com")["id"]

        def finding(tpl, sev):
            return {"asset_id": aid, "host": "https://swap.example.com", "template_id": tpl,
                    "template_name": tpl, "severity": sev, "vuln_type": "", "description": "",
                    "matched_at": "", "extracted_results": "", "curl_command": "",
                    "raw_json": "{}", "created_at": "2026-01-01T00:00:00"}

        # pre-existing (legacy, pre-upgrade) results
        self.assertEqual(models.insert_nuclei_results([finding("legacy-tpl", "high")]), 1)
        scan = "scan-gen-1"
        # new scan streams tagged findings in while old rows remain visible
        models.insert_nuclei_results([finding("log4shell", "critical")], scan_id=scan)
        self.assertEqual(len(models.get_asset_nuclei_results(aid)), 2)  # old + partial
        # success -> atomic swap: only this scan's rows survive
        self.assertEqual(models.finalize_nuclei_scan(scan, [aid]), 1)
        after = models.get_asset_nuclei_results(aid)
        self.assertEqual([r["template_id"] for r in after], ["log4shell"])
        # a LATER scan fails -> abort removes only its partial rows, old kept
        bad_scan = "scan-gen-2"
        models.insert_nuclei_results([finding("new-vuln", "medium")], scan_id=bad_scan)
        self.assertEqual(len(models.get_asset_nuclei_results(aid)), 2)
        models.abort_nuclei_scan(bad_scan, [aid])
        after2 = models.get_asset_nuclei_results(aid)
        self.assertEqual([r["template_id"] for r in after2], ["log4shell"])
        # default scan_id still inserts (plain callers keep working)
        self.assertEqual(models.insert_nuclei_results([finding("x", "low")]), 1)
        self.assertEqual(models.clear_asset_nuclei_results(aid), 2)

    def test_fingerprint_task_checkpoint_and_resume(self):
        """Fingerprint tasks persist their checkpoint; startup recovery marks
        running tasks interrupted; resume endpoint guards + completion."""
        tid = "fp-checkpoint-1"
        models.create_fingerprint_task(tid, [11, 22, 33, 44])
        t = models.get_fingerprint_task(tid)
        self.assertEqual(t["status"], "running")
        self.assertEqual(t["total"], 4)
        self.assertEqual(t["processed"], 0)
        models.update_fingerprint_task(tid, processed=2)
        # startup recovery: running -> interrupted, checkpoint kept
        models.recover_interrupted_fingerprint_tasks()
        t = models.get_fingerprint_task(tid)
        self.assertEqual(t["status"], "interrupted")
        self.assertEqual(t["processed"], 2)
        # progress endpoint reads the DB row (no in-memory registry anymore)
        body = self.client.get(f"/api/assets/identify/{tid}/progress").get_json()
        self.assertEqual(body["status"], "interrupted")
        self.assertEqual(body["current"], 2)
        # a running task cannot be resumed
        models.update_fingerprint_task(tid, status="running")
        resp = self.client.post(f"/api/assets/identify/{tid}/resume")
        self.assertEqual(resp.status_code, 400)
        # unknown task
        self.assertEqual(self.client.post("/api/assets/identify/nope/resume").status_code, 404)
        # fully-processed task -> already completed (no worker thread spawned)
        models.update_fingerprint_task(tid, status="interrupted", processed=4)
        resp = self.client.post(f"/api/assets/identify/{tid}/resume")
        self.assertTrue(resp.get_json()["already_completed"])
        body = self.client.get(f"/api/assets/identify/{tid}/progress").get_json()
        self.assertEqual(body["status"], "completed")

    def test_search_result_cache(self):
        """Identical search requests are served from cache; writes invalidate."""
        cache.clear()
        self.client.post("/api/assets/add", json={"domain": "cache.srch.example.com", "cms": "Nginx"})
        a1, t1 = models.list_assets({"cms": "Nginx"}, page=1, per_page=20)
        a2, t2 = models.list_assets({"cms": "Nginx"}, page=1, per_page=20)
        self.assertIs(a1, a2)  # same cached object (no second query/sort)
        self.assertEqual(t1, t2)
        # a write invalidates the cached search result
        self.client.post("/api/assets/add", json={"domain": "cache2.srch.example.com", "cms": "Nginx"})
        a3, t3 = models.list_assets({"cms": "Nginx"}, page=1, per_page=20)
        self.assertEqual(t3, t1 + 1)
        self.assertIsNot(a1, a3)

    def test_chinese_search_hybrid_substring(self):
        """CJK queries route to the (substring-correct) multi-term LIKE path -
        unicode61-FTS would miss '平台' inside '自动化测试平台' because it
        stores the whole CJK run as one token."""
        self.client.post("/api/assets/add", json={
            "domain": "cjk.example.com", "title": "自动化测试平台 数据看板",
            "cms": "nginx/1.18.0", "server": "nginx/1.18.0", "source": "manual"})
        for q in ("平台", "自动化 测试", "nginx 看板", "数据 看板"):
            r = self.client.get("/api/assets", query_string={"search": q}).get_json()
            self.assertTrue(r["ok"])
            self.assertTrue(any(a["domain"] == "cjk.example.com" for a in r["assets"]), q)
        # AND semantics: a word that is absent must exclude the row
        r = self.client.get("/api/assets", query_string={"search": "平台 数据库x"}).get_json()
        self.assertFalse(any(a["domain"] == "cjk.example.com" for a in r["assets"]))
        # CJK queries are routed to LIKE (None = no FTS id list); Latin queries
        # still resolve through FTS5 when the build supports it
        self.assertIsNone(models._resolve_search_ids(None, "平台"))
        if db.FTS_AVAILABLE:
            class _FakeConn:
                def execute(self, *a, **kw):
                    return []
            self.assertEqual(models._resolve_search_ids(_FakeConn(), "nginx"), [])

    # ---------- AI assistant ----------

    def test_ai_sessions_crud(self):
        r = self.client.post("/api/ai/sessions").get_json()
        self.assertTrue(r["ok"])
        sid = r["session"]["session_id"]
        sessions = self.client.get("/api/ai/sessions").get_json()["sessions"]
        self.assertTrue(any(s["session_id"] == sid for s in sessions))
        # rename + detail
        self.client.post(f"/api/ai/sessions/{sid}/rename", json={"title": "测试会话"})
        detail = self.client.get(f"/api/ai/sessions/{sid}").get_json()
        self.assertEqual(detail["session"]["title"], "测试会话")
        self.assertEqual(detail["messages"], [])
        # chat validation
        resp = self.client.post("/api/ai/chat", json={"session_id": sid, "message": "  "})
        self.assertEqual(resp.status_code, 400)
        resp = self.client.post("/api/ai/chat", json={"session_id": "nope", "message": "hi"})
        self.assertEqual(resp.status_code, 404)
        # delete
        resp = self.client.delete(f"/api/ai/sessions/{sid}")
        self.assertTrue(resp.get_json()["ok"])
        self.assertEqual(self.client.get(f"/api/ai/sessions/{sid}").status_code, 404)

    def test_ai_export_csv(self):
        self.client.post("/api/assets/add", json={"domain": "csv.ai.example.com", "cms": "WordPress"})
        filename, text = models.export_csv({"cms": "WordPress"})
        self.assertTrue(filename.endswith(".csv"))
        self.assertIn("csv.ai.example.com", text)
        self.assertTrue(text.startswith("id,domain"))
        # max_rows caps the output (header + 1 row)
        _, capped = models.export_csv(None, max_rows=1)
        self.assertEqual(capped.count("\n"), 2)

    def test_ai_safe_tools(self):
        self.client.post("/api/assets/add", json={
            "domain": "tool.ai.example.com", "cms": "Nginx",
            "country": "中国", "tags": "核心资产"})
        res = ai_assistant._run_safe_tool("query_assets", {"cms": "Nginx"})
        self.assertTrue(res["ok"])
        self.assertIn("tool.ai.example.com", res["text"])
        res = ai_assistant._run_safe_tool("get_dashboard_stats", {})
        self.assertTrue(res["ok"])
        self.assertIn("总资产数", res["text"])
        res = ai_assistant._run_safe_tool("unknown_tool", {})
        self.assertFalse(res["ok"])
        # dangerous tool previews resolve targets but do NOT execute
        norm, preview = ai_assistant._preview_apply_asset_tags(
            {"domains": ["tool.ai.example.com"], "tags": "测试"})
        self.assertEqual(norm["domains"], ["tool.ai.example.com"])
        self.assertIn("测试", preview)
        a = models.get_asset_by_domain("tool.ai.example.com")
        self.assertNotIn("测试", a["tags"])  # still not applied
        norm, preview = ai_assistant._preview_delete_assets({"domains": ["tool.ai.example.com"]})
        self.assertEqual(len(norm["ids"]), 1)
        self.assertIsNotNone(models.get_asset_by_domain("tool.ai.example.com"))  # still exists
        # no match -> cancelled
        norm, preview = ai_assistant._preview_apply_asset_tags(
            {"domains": ["nope.example.com"], "tags": "x"})
        self.assertIsNone(norm)

    def test_ai_cve_tool(self):
        with mock.patch("nvd.requests.get",
                        return_value=mock.Mock(raise_for_status=lambda: None,
                                               json=lambda: {"vulnerabilities": []})):
            res = ai_assistant._run_safe_tool("get_cve_info", {"keyword": "nginx"})
        self.assertTrue(res["ok"])
        self.assertIn("未查询到", res["text"])
        # missing keyword rejected
        res = ai_assistant._run_safe_tool("get_cve_info", {})
        self.assertFalse(res["ok"])

    def _fake_deepseek(self, url, **kw):
        """Simulate DeepSeek: first call requests apply_asset_tags, later calls answer."""
        payload = kw.get("json") or {}
        msgs = payload.get("messages") or []
        if any(m.get("role") == "tool" for m in msgs):
            return mock.Mock(status_code=200, json=lambda: {
                "choices": [{"message": {"role": "assistant", "content": "已完成标签添加。"}}]})
        return mock.Mock(status_code=200, json=lambda: {
            "choices": [{"message": {"role": "assistant", "content": "",
                                       "tool_calls": [{"id": "call_abc", "type": "function",
                                                        "function": {"name": "apply_asset_tags",
                                                                      "arguments": json.dumps(
                                                                          {"domains": ["confirm.ai.example.com"],
                                                                           "tags": ["测试"]})}}]}}]})

    def test_ai_chat_confirm_flow(self):
        """Dangerous tool: pauses with needs_confirmation, executes only after approval."""
        self.client.post("/api/assets/add", json={"domain": "confirm.ai.example.com"})
        sid = models.create_chat_session()["session_id"]
        with mock.patch("ai_providers.requests.post", side_effect=self._fake_deepseek):
            events = list(ai_assistant.chat_events(sid, "给 confirm.ai.example.com 打上 测试 标签"))
        types = [e["type"] for e in events]
        self.assertIn("needs_confirmation", types)
        nc = next(e for e in events if e["type"] == "needs_confirmation")
        self.assertEqual(nc["tool"], "apply_asset_tags")
        # NOT executed yet
        a = models.get_asset_by_domain("confirm.ai.example.com")
        self.assertNotIn("测试", a["tags"])
        # audit log records the blocked call
        log = models.recent_ai_tool_log(20)
        self.assertTrue(any(l["status"] == "awaiting_confirmation"
                            and l["tool"] == "apply_asset_tags" for l in log))
        # approve -> tool executes, model answers, tags applied
        with mock.patch("ai_providers.requests.post", side_effect=self._fake_deepseek):
            events2 = list(ai_assistant.resume_after_confirm(sid, nc["confirm_id"], True))
        self.assertTrue(any(e["type"] == "done" for e in events2))
        text = "".join(e["delta"] for e in events2 if e["type"] == "text_delta")
        self.assertIn("已完成", text)
        a = models.get_asset_by_domain("confirm.ai.example.com")
        self.assertIn("测试", a["tags"])
        self.assertTrue(any(l["status"] == "ok" and l["tool"] == "apply_asset_tags" for l in
                            models.recent_ai_tool_log(20)))

    def test_ai_chat_endpoint_stream(self):
        """/api/ai/chat returns an SSE stream; history is persisted with model tags."""
        sid = models.create_chat_session()["session_id"]

        def fake_simple(url, **kw):
            return mock.Mock(status_code=200, json=lambda: {
                "choices": [{"message": {"role": "assistant", "content": "你好！有什么可以帮你？"}}],
                "usage": {"prompt_tokens": 12, "completion_tokens": 7},
                "model": "deepseek-chat"})

        with mock.patch("ai_providers.requests.post", side_effect=fake_simple):
            resp = self.client.post("/api/ai/chat", json={"session_id": sid, "message": "你好"})
        self.assertEqual(resp.status_code, 200)
        body = resp.get_data(as_text=True)
        self.assertIn("text_delta", body)
        self.assertIn("done", body)
        msgs = models.get_chat_messages(sid)
        self.assertEqual([m["role"] for m in msgs], ["user", "assistant"])
        # every message is tagged with the canonical model key + usage recorded
        self.assertEqual(msgs[0]["model"], "deepseek:deepseek-chat")
        self.assertEqual(msgs[1]["model"], "deepseek:deepseek-chat")
        self.assertEqual(msgs[1]["usage"]["prompt_tokens"], 12)
        # session auto-titled from the first message
        sess = models.get_chat_session(sid)
        self.assertEqual(sess["title"], "你好")
        # upstream audit trail has exactly one ok call
        logs = models.recent_ai_call_log(5)
        self.assertEqual(logs[0]["provider"], "deepseek")
        self.assertEqual(logs[0]["ok"], 1)
        self.assertEqual(logs[0]["completion_tokens"], 7)

    # ---------- multi-model AI providers ----------

    def test_ai_providers_seed_and_routes(self):
        rows = models.list_ai_providers(True)
        names = {r["name"] for r in rows}
        for expect in ("deepseek", "openai", "anthropic", "gemini", "qwen",
                       "moonshot", "zhipu", "groq", "mistral", "xai",
                       "openrouter", "ollama", "siliconflow"):
            self.assertIn(expect, names)
        body = self.client.get("/api/ai/models").get_json()
        self.assertTrue(body["ok"])
        pick = {p["name"] for p in body["providers"]}
        self.assertIn("deepseek", pick)
        self.assertNotIn("anthropic", pick)      # disabled providers are hidden
        self.assertEqual(body["default"], "deepseek:deepseek-chat")
        # picker exposes the model ids per provider
        dp = next(p for p in body["providers"] if p["name"] == "deepseek")
        self.assertIn("deepseek-reasoner", dp["models"])
        # settings list masks api keys
        provs = self.client.get("/api/ai/providers").get_json()["providers"]
        masked = next(p for p in provs if p["name"] == "deepseek")["api_key"]
        self.assertNotEqual(masked, "test-key")
        self.assertIn("…", masked)

    def test_ai_session_model_route(self):
        sid = models.create_chat_session()["session_id"]
        # disabled provider model rejected
        r = self.client.post(f"/api/ai/sessions/{sid}/model",
                             json={"model": "anthropic:claude-sonnet-4-20250514"}).get_json()
        self.assertFalse(r["ok"])
        # enabled model accepted and persisted
        r = self.client.post(f"/api/ai/sessions/{sid}/model",
                             json={"model": "deepseek:deepseek-chat"}).get_json()
        self.assertTrue(r["ok"])
        self.assertEqual(models.get_chat_session(sid)["model"], "deepseek:deepseek-chat")
        # empty resets to follow the global default
        r = self.client.post(f"/api/ai/sessions/{sid}/model", json={"model": ""}).get_json()
        self.assertTrue(r["ok"])
        self.assertEqual(models.get_chat_session(sid)["model"], "")
        # unknown session
        resp = self.client.post("/api/ai/sessions/nope/model",
                                json={"model": "deepseek:deepseek-chat"})
        self.assertEqual(resp.status_code, 404)

    def test_ai_provider_settings_roundtrip(self):
        # bulk-save enables openai + stores its key and model list
        resp = self.client.post("/api/ai/providers", json={"providers": [{
            "name": "openai", "api_key": "sk-test", "enabled": True,
            "is_default": False, "display_name": "OpenAI GPT",
            "models": ["gpt-4o", "gpt-4o-mini"]}]})
        body = resp.get_json()
        self.assertTrue(body["ok"], body.get("errors"))
        row = models.get_ai_provider("openai")
        self.assertEqual(row["enabled"], 1)
        self.assertEqual(row["api_key"], "sk-test")
        self.assertEqual(row["models_list"], ["gpt-4o", "gpt-4o-mini"])
        # exactly one default remains (deepseek), even with two enabled
        provs = models.list_ai_providers(True)
        self.assertEqual(sum(1 for p in provs if p["is_default"]), 1)
        # empty api_key keeps the stored key (settings round-trip semantics)
        resp = self.client.post("/api/ai/providers", json={"providers": [{
            "name": "openai", "api_key": "", "display_name": "OpenAI GPT"}]})
        self.assertTrue(resp.get_json()["ok"])
        self.assertEqual(models.get_ai_provider("openai")["api_key"], "sk-test")

    def test_ai_openai_adapter_params(self):
        """OpenAI-compatible adapter: correct wire payload + reasoning-model
        param adaptation + response normalization."""
        captured = {}

        def fake_post(url, **kw):
            captured.update(kw)
            return mock.Mock(status_code=200, json=lambda: {
                "choices": [{"message": {"role": "assistant", "content": "hi",
                                           "tool_calls": [{"id": "call_9", "type": "function",
                                                            "function": {"name": "query_assets",
                                                                          "arguments": "{}"}}]}}],
                "usage": {"prompt_tokens": 10, "completion_tokens": 5},
                "model": "deepseek-chat"})

        row = models.get_ai_provider("deepseek")
        with mock.patch("ai_providers.requests.post", side_effect=fake_post):
            inst = ai_providers.build_provider(dict(row), "deepseek-chat",
                                               temperature=0.3, max_tokens=2048, timeout=30)
            reply = inst.chat([{"role": "user", "content": "x"}], tools=ai_assistant.TOOLS)
        body = captured["json"]
        self.assertEqual(body["model"], "deepseek-chat")
        self.assertEqual(body["temperature"], 0.3)
        self.assertEqual(body["max_tokens"], 2048)
        self.assertTrue(body["tools"])
        self.assertEqual(captured["headers"]["Authorization"], "Bearer test-key")
        self.assertTrue(captured["url"].endswith("/chat/completions"))
        self.assertEqual(reply.content, "hi")
        self.assertEqual(reply.tool_calls[0]["function"]["name"], "query_assets")
        self.assertEqual(reply.usage, {"prompt_tokens": 10, "completion_tokens": 5})

        # reasoning models (o3-mini) reject temperature/max_tokens
        captured.clear()
        row2 = dict(models.get_ai_provider("openai"))
        row2["api_key"] = "sk"
        with mock.patch("ai_providers.requests.post", side_effect=fake_post):
            inst = ai_providers.build_provider(row2, "o3-mini",
                                               temperature=0.7, max_tokens=1000, timeout=30)
            inst.chat([{"role": "user", "content": "x"}])
        body = captured["json"]
        self.assertNotIn("temperature", body)
        self.assertNotIn("max_tokens", body)
        self.assertEqual(body["max_completion_tokens"], 1000)

    def test_ai_anthropic_adapter_translation(self):
        """Claude native adapter: canonical OpenAI messages/tools -> Messages
        API wire format and back; system/tool_result placement + clamps."""
        captured = {}

        def fake_post(url, **kw):
            captured.update(kw)
            return mock.Mock(status_code=200, json=lambda: {
                "content": [
                    {"type": "tool_use", "id": "toolu_1",
                     "name": "query_assets", "input": {"cms": "Nginx"}},
                    {"type": "text", "text": "我查一下。"}],
                "usage": {"input_tokens": 20, "output_tokens": 8},
                "model": "claude-sonnet-4"})

        row = models.get_ai_provider("anthropic")
        row["api_key"] = "sk-ant"
        msgs = [
            {"role": "system", "content": "你是助手"},
            {"role": "user", "content": "查 Nginx"},
            {"role": "assistant", "content": "", "tool_calls": [
                {"id": "call_1", "type": "function",
                 "function": {"name": "query_assets", "arguments": '{"cms":"Nginx"}'}}]},
            {"role": "tool", "tool_call_id": "call_1", "content": "ok"},
        ]
        with mock.patch("ai_providers.requests.post", side_effect=fake_post):
            inst = ai_providers.build_provider(dict(row), "claude-sonnet-4-20250514",
                                               temperature=1.7, max_tokens=3000, timeout=30)
            reply = inst.chat(msgs, tools=ai_assistant.TOOLS)
        self.assertEqual(captured["url"], "https://api.anthropic.com/v1/messages")
        self.assertEqual(captured["headers"]["x-api-key"], "sk-ant")
        self.assertEqual(captured["headers"]["anthropic-version"], "2023-06-01")
        body = captured["json"]
        self.assertEqual(body["model"], "claude-sonnet-4-20250514")
        self.assertEqual(body["max_tokens"], 3000)
        self.assertLessEqual(body["temperature"], 1.0)   # clamped to Claude's 0..1
        self.assertEqual(body["system"], "你是助手")      # system is a top-level field
        self.assertEqual(body["messages"][0]["role"], "user")  # must open with user
        # tools: parameters -> input_schema
        self.assertIn("input_schema", body["tools"][0])
        self.assertNotIn("parameters", body["tools"][0])
        # tool result arrives as a user content block referencing the tool_use
        last = body["messages"][-1]
        self.assertEqual(last["role"], "user")
        self.assertEqual(last["content"][0]["type"], "tool_result")
        self.assertEqual(last["content"][0]["tool_use_id"], "call_1")
        # normalized back to canonical OpenAI shape
        self.assertEqual(reply.tool_calls[0]["id"], "toolu_1")
        self.assertEqual(reply.tool_calls[0]["function"]["name"], "query_assets")
        self.assertEqual(json.loads(reply.tool_calls[0]["function"]["arguments"]),
                         {"cms": "Nginx"})
        self.assertIn("我查一下", reply.content)
        self.assertEqual(reply.usage, {"prompt_tokens": 20, "completion_tokens": 8})

    def test_ai_fallback_and_call_log(self):
        """Transient failure falls back to the next enabled provider when the
        switch is on; every attempt lands in ai_call_log with cost attribution."""
        self.client.post("/api/ai/providers", json={"providers": [{
            "name": "openai", "api_key": "sk-openai",
            "enabled": True, "is_default": False}]})
        config.set("ai_fallback_enabled", "true")
        seq = {"n": 0}

        def flaky(url, **kw):
            seq["n"] += 1
            if seq["n"] == 1:
                raise requests.exceptions.Timeout("mocked timeout")
            return mock.Mock(status_code=200, json=lambda: {
                "choices": [{"message": {"role": "assistant", "content": "兜底成功"}}],
                "usage": {"prompt_tokens": 100, "completion_tokens": 50},
                "model": "gpt-4o"})

        sid = models.create_chat_session()["session_id"]
        with mock.patch("ai_providers.requests.post", side_effect=flaky):
            reply, used = ai_providers.call_model(
                "deepseek:deepseek-chat", [{"role": "user", "content": "hi"}],
                session_id=sid)
        self.assertEqual(seq["n"], 2)                       # primary + fallback
        self.assertIn("openai", used)                       # answered by the fallback
        self.assertEqual(reply.content, "兜底成功")
        logs = models.recent_ai_call_log(10)
        self.assertEqual(logs[0]["provider"], "openai")    # newest first
        self.assertEqual(logs[0]["ok"], 1)
        self.assertEqual(logs[1]["provider"], "deepseek")
        self.assertEqual(logs[1]["ok"], 0)
        self.assertEqual(logs[1]["error_type"], "timeout")
        # cost attributed only to the successful fallback call
        summary = models.ai_cost_summary()
        row = next((s for s in summary if s["provider"] == "openai"), None)
        self.assertIsNotNone(row)
        self.assertGreater(row["cost_est"], 0)
        # fallback disabled -> single attempt, error propagates
        config.set("ai_fallback_enabled", "false")
        seq2 = {"n": 0}

        def always_fail(url, **kw):
            seq2["n"] += 1
            raise requests.exceptions.Timeout("mocked timeout")

        with mock.patch("ai_providers.requests.post", side_effect=always_fail):
            with self.assertRaises(ai_providers.AIError):
                ai_providers.call_model("deepseek:deepseek-chat",
                                        [{"role": "user", "content": "hi"}],
                                        session_id=sid)
        self.assertEqual(seq2["n"], 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
