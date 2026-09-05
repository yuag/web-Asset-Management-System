"""Search benchmark: how fast / how accurate is asset search on a large DB?

Compares the two engines the app can use on each query:
  * FTS5 (unicode61)  - used for pure-Latin queries (nginx, wordpress, 1.18)
  * SQL LIKE (multi-term AND) - used for CJK-bearing queries and as the
    no-FTS5 fallback

Why this matters (see models._resolve_search_ids):
  unicode61 does NOT segment Chinese: a contiguous CJK run such as
  "自动化测试平台" is stored as ONE token. Querying "平台" as a prefix term
  therefore never matches it, even though the substring is present. LIKE is
  slower (full scan, no index for leading wildcards) but semantically correct
  for Chinese. This script measures the actual trade-off so you can decide
  whether to add a jieba/trigram index later.

Run:  python benchmark_search.py [asset_count]   (default 50_000)
Creates a throwaway database in a temp dir - never touches assets.db.
"""
import os
import sys
import tempfile
import time

import db

ASSETS = int(sys.argv[1]) if len(sys.argv) > 1 else 50_000

# Redirect to a scratch DB BEFORE importing anything that opens connections.
_db_dir = tempfile.mkdtemp(prefix="search_bench_")
db.DB_PATH = os.path.join(_db_dir, "bench.db")

import cache  # noqa: E402
import models  # noqa: E402

# Deterministic synthetic dataset -------------------------------------------------
CJK_TITLES = ["自动化测试平台", "数据中台 看板", "管理后台", "官网首页 商城",
              "运维监控中心", "日志分析系统", "API网关", "注册登录服务"]
SERVERS = ["nginx/1.18.0", "nginx/1.20.2", "apache/2.4", "tomcat/9.0", "IIS/10.0"]
CMSS = ["", "WordPress 5.9", "ThinkPHP 5.0", "Laravel", "Spring Boot"]


def build_db(n):
    print(f"building {n} synthetic assets ...", flush=True)
    items = []
    for i in range(n):
        items.append({
            "domain": f"host{i}.bench.example.com",
            "url": f"https://host{i}.bench.example.com",
            "ip": f"10.{i % 250}.{(i // 250) % 250}.{i % 250}",
            "title": CJK_TITLES[i % len(CJK_TITLES)],
            "server": SERVERS[i % len(SERVERS)],
            "cms": CMSS[i % len(CMSS)],
            "country": "中国",
            "source": "bench",
        })
    t0 = time.perf_counter()
    imported, updated, _ = models.batch_upsert_assets(items, chunk_size=2000)
    print(f"  imported {imported} updated {updated} in "
          f"{time.perf_counter() - t0:.1f}s")


QUERIES = [
    # (label, search text, expected minimum matches)
    ("latin exact  ", "nginx", None),
    ("latin multi  ", "wordpress nginx", None),
    ("mixed cjk    ", "nginx 看板", None),
    ("cjk word     ", "平台", None),
    ("cjk multi    ", "自动化 看板", None),
    ("cjk two-char ", "中台", None),
]


def _fmt(sec):
    return f"{sec * 1000:8.1f} ms"


def run_query(label, q, force_like):
    # warm & measure like list_assets does (cold path, cache disabled)
    cache.clear()
    def _once():
        return models.list_assets({"search": q}, page=1, per_page=20)
    t0 = time.perf_counter()
    assets, total = _once()
    cold = time.perf_counter() - t0
    t0 = time.perf_counter()
    _once()
    hot = time.perf_counter() - t0  # served from the search cache
    engine = "LIKE (CJK route)" if models._has_cjk(q) else "FTS5"
    if force_like:
        engine = "LIKE (forced)"
    return total, engine, cold, hot


def main():
    build_db(ASSETS)
    total_assets = models.dashboard_stats()["total"] or ASSETS
    print(f"DB has {total_assets} assets | FTS available: {db.FTS_AVAILABLE}\n")
    print(f"{'query':<14}{'engine':<18}{'matches':>9}{'cold':>12}{'cached':>10}")
    print("-" * 64)

    # Actual app behaviour (hybrid routing)
    print("-- app behaviour (hybrid: CJK->LIKE, latin->FTS5) --")
    for label, q, _ in QUERIES:
        total, engine, cold, hot = run_query(label, q, force_like=False)
        print(f"{label:<14}{engine:<18}{total:>9}{_fmt(cold):>12}{_fmt(hot):>10}")

    # What pure-FTS5 (unicode61) would give Chinese queries: the SAME queries
    # forced through MATCH show the recall gap.
    if db.FTS_AVAILABLE:
        print("\n-- forced LIKE vs unicode61-FTS5 recall on CJK queries --")
        import sqlite3
        conn = db.get_conn()
        for label, q, _ in QUERIES:
            if not models._has_cjk(q):
                continue
            like_total, _, _, _ = run_query(label, q, force_like=True)
            fts_total = None
            try:
                match_q = models._fts_query(q)
                n = conn.execute(
                    "SELECT COUNT(*) FROM assets_fts WHERE assets_fts MATCH ?",
                    (match_q,),
                ).fetchone()[0]
                fts_total = n
            except sqlite3.OperationalError:
                fts_total = "err"
            print(f"{label:<14}{'LIKE':<18}{like_total:>9}   FTS5={fts_total}")
        conn.close()

    print("\nNumbers are per-page (20 rows) queries. Cold = no cache; "
          "cached = hot 8s search-cache hit. Lower is better; for recall, "
          "LIKE>=FTS5 for CJK is the point of the hybrid routing.")
    print("If CJK latency here is unacceptable at your real scale, the next "
          "step is a trigram or jieba-tokenized FTS index.")


if __name__ == "__main__":
    main()
