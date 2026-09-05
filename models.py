"""Asset CRUD, tag management, changelog, dashboard stats, AI chat history.

Performance:
- FTS5 full-text search with automatic LIKE fallback (CJK queries route to
  LIKE: unicode61 cannot segment Chinese, see benchmark_search.py)
- batched bulk import (one transaction, pre-fetched lookups, UNIQUE-race safe)
- sharded (keyset) scanning for large result sets
- TTL caching of aggregates AND hot search results, invalidated on every write
- busy-retry wrappers (db.retry_on_busy) around all writers
"""
import hashlib
import sqlite3
import json
import re
import csv
import io
import uuid
from datetime import datetime, date
import db
import cache


# ---------- cache helpers ----------

def _invalidate_asset_cache():
    """Drop cached aggregates + search results after any write touching
    assets / tags / dicts."""
    cache.invalidate_prefix("stats:")
    cache.invalidate_prefix("changelog:")
    cache.invalidate("tags:all")
    cache.invalidate_prefix("dict:")
    cache.invalidate_prefix("search:")


# ---------- dict options (country / cms / source dictionaries) ----------

DICT_TYPES = ("country", "cms", "source")


def list_dict_options(dtype=None):
    key = f"dict:{dtype or 'all'}"

    def _load():
        conn = db.get_conn()
        try:
            if dtype:
                rows = conn.execute(
                    "SELECT value FROM dict_options WHERE dtype=? ORDER BY value", (dtype,)
                ).fetchall()
                return [r["value"] for r in rows]
            rows = conn.execute(
                "SELECT dtype, value FROM dict_options ORDER BY dtype, value"
            ).fetchall()
            grouped = {}
            for r in rows:
                grouped.setdefault(r["dtype"], []).append(r["value"])
            return grouped
        finally:
            conn.close()

    return cache.get(key, _load, ttl=60)


def add_dict_option(dtype, value):
    """Add a dictionary option. Returns (ok, message)."""
    dtype = (dtype or "").strip()
    value = (value or "").strip()
    if dtype not in DICT_TYPES:
        return False, "无效的字典类型"
    if not value:
        return False, "选项值不能为空"
    if len(value) > 100:
        return False, "选项值过长"
    conn = db.get_conn()
    try:
        exists = conn.execute(
            "SELECT 1 FROM dict_options WHERE dtype=? AND value=?", (dtype, value)
        ).fetchone()
        if exists:
            return True, "已存在"
        conn.execute("INSERT INTO dict_options (dtype, value) VALUES (?,?)", (dtype, value))
        conn.commit()
        _invalidate_asset_cache()
        return True, "ok"
    finally:
        conn.close()


def delete_dict_option(dtype, value):
    """Remove a dictionary option. Returns True if a row was deleted."""
    conn = db.get_conn()
    try:
        cur = conn.execute(
            "DELETE FROM dict_options WHERE dtype=? AND value=?", (dtype, value)
        )
        conn.commit()
        _invalidate_asset_cache()
        return cur.rowcount > 0
    finally:
        conn.close()


def _dict_pairs(fields):
    """Yield (dtype, value) pairs to auto-register from an asset's fields."""
    pairs = []
    for field, dtype in (("country", "country"), ("cms", "cms"), ("source", "source")):
        v = (fields.get(field) or "").strip()
        if not v:
            continue
        # source may be a merged comma list like "crt,fofa"
        for part in v.split(","):
            part = part.strip()
            if part:
                pairs.append((dtype, part))
    return pairs


def register_dict_values(conn, fields):
    """Auto-register country/cms/source values from an asset into the dictionary.
    `conn` is an open connection; called inside upsert_asset's transaction."""
    for dtype, value in _dict_pairs(fields):
        conn.execute(
            "INSERT OR IGNORE INTO dict_options (dtype, value) VALUES (?,?)",
            (dtype, value),
        )


# ---------- tags ----------

def get_or_create_tag(conn, name):
    name = name.strip()
    if not name:
        return None
    r = conn.execute("SELECT id FROM tags WHERE name=?", (name,)).fetchone()
    if r:
        return r["id"]
    cur = conn.execute("INSERT INTO tags (name) VALUES (?)", (name,))
    return cur.lastrowid


def set_asset_tags(conn, asset_id, tag_names):
    conn.execute("DELETE FROM asset_tags WHERE asset_id=?", (asset_id,))
    for name in tag_names:
        name = name.strip()
        if not name:
            continue
        tag_id = get_or_create_tag(conn, name)
        if tag_id:
            conn.execute(
                "INSERT OR IGNORE INTO asset_tags (asset_id, tag_id) VALUES (?,?)",
                (asset_id, tag_id),
            )


def get_asset_tags(conn, asset_id):
    rows = conn.execute(
        "SELECT t.name FROM tags t JOIN asset_tags at ON at.tag_id=t.id WHERE at.asset_id=?",
        (asset_id,),
    ).fetchall()
    return [r["name"] for r in rows]


def _bulk_tags(conn, ids):
    """Fetch tags for many asset ids in chunks (avoids N+1 queries).
    Returns {asset_id: [tag_names]}."""
    tags = {}
    for i in range(0, len(ids), 900):
        group = ids[i:i + 900]
        ph = ",".join("?" * len(group))
        rows = conn.execute(
            f"SELECT at.asset_id, t.name FROM asset_tags at JOIN tags t ON t.id=at.tag_id "
            f"WHERE at.asset_id IN ({ph})",
            group,
        ).fetchall()
        for r in rows:
            tags.setdefault(r["asset_id"], []).append(r["name"])
    return tags


def all_tags():
    def _load():
        conn = db.get_conn()
        try:
            rows = conn.execute(
                "SELECT t.name, COUNT(at.asset_id) c FROM tags t "
                "LEFT JOIN asset_tags at ON at.tag_id=t.id "
                "GROUP BY t.id ORDER BY c DESC, t.name"
            ).fetchall()
            return {r["name"]: r["c"] for r in rows}
        finally:
            conn.close()

    return cache.get("tags:all", _load, ttl=30)


def add_tag(name):
    """Manually create a custom tag (idempotent). Returns (ok, message)."""
    name = (name or "").strip()
    if not name:
        return False, "标签名称不能为空"
    if len(name) > 50:
        return False, "标签名称过长（最多50字符）"
    conn = db.get_conn()
    try:
        conn.execute("INSERT OR IGNORE INTO tags (name) VALUES (?)", (name,))
        conn.commit()
        _invalidate_asset_cache()
        return True, "ok"
    finally:
        conn.close()


def delete_tag(name):
    """Delete a custom tag and detach it from all assets. Returns True if removed."""
    name = (name or "").strip()
    if not name:
        return False
    conn = db.get_conn()
    try:
        r = conn.execute("SELECT id FROM tags WHERE name=?", (name,)).fetchone()
        if not r:
            return False
        conn.execute("DELETE FROM asset_tags WHERE tag_id=?", (r["id"],))
        conn.execute("DELETE FROM tags WHERE id=?", (r["id"],))
        conn.commit()
        _invalidate_asset_cache()
        return True
    finally:
        conn.close()


# ---------- changelog ----------

def add_changelog(conn, asset_id, domain, changed_fields, old_value, new_value, change_type):
    conn.execute(
        """INSERT INTO asset_changelog
           (asset_id, domain, changed_fields, old_value, new_value, change_type, created_at)
           VALUES (?,?,?,?,?,?,?)""",
        (
            asset_id,
            domain,
            json.dumps(changed_fields, ensure_ascii=False),
            json.dumps(old_value, ensure_ascii=False) if old_value else "{}",
            json.dumps(new_value, ensure_ascii=False) if new_value else "{}",
            change_type,
            datetime.now().isoformat(timespec="seconds"),
        ),
    )


def recent_changelog(limit=20):
    def _load():
        conn = db.get_conn()
        try:
            rows = conn.execute(
                "SELECT * FROM asset_changelog ORDER BY created_at DESC, id DESC LIMIT ?",
                (limit,),
            ).fetchall()
            return [dict(r) for r in rows]
        finally:
            conn.close()

    return cache.get(f"changelog:{limit}", _load, ttl=10)


def today_changelog_counts():
    conn = db.get_conn()
    try:
        today = date.today().isoformat()
        base = "SELECT change_type, COUNT(*) c FROM asset_changelog WHERE substr(created_at,1,10)=?"
        rows = conn.execute(base, (today,)).fetchall()
        return {r["change_type"]: r["c"] for r in rows}
    finally:
        conn.close()


# ---------- assets ----------

TRACKED_FIELDS = ["url", "ip", "port", "title", "country", "country_code",
                  "cms", "server", "waf", "status_code", "expiration_date"]

ASSET_COLUMNS = ["domain", "url", "ip", "port", "title", "country", "country_code",
                 "cms", "server", "waf", "owner", "remark", "expiration_date",
                 "status_code", "source", "root_domain"]


def _normalize_fields(data):
    """Normalize an input dict into the exact columns stored on assets."""
    fields = {c: (data.get(c) or "").strip() for c in ASSET_COLUMNS if c != "status_code"}
    fields["status_code"] = data.get("status_code")
    if fields["status_code"] in ("", None):
        fields["status_code"] = None
    try:
        fields["status_code"] = int(fields["status_code"]) if fields["status_code"] is not None else None
    except (ValueError, TypeError):
        fields["status_code"] = None
    fields["domain"] = (data.get("domain") or "").strip()
    fields["source"] = (data.get("source") or "manual").strip()
    return fields


def _normalize_tags(data):
    tag_names = data.get("tags", [])
    if isinstance(tag_names, str):
        tag_names = [t.strip() for t in tag_names.split(",") if t.strip()]
    return [str(t).strip() for t in tag_names if str(t).strip()]


def _diff_fields(old, fields):
    """Compare stored row against new fields; returns (changed, old_val, new_val)."""
    changed, old_val, new_val = [], {}, {}
    for f in TRACKED_FIELDS:
        new_v = fields.get(f)
        old_v = old.get(f)
        # normalize None / '' comparison
        if (new_v or "") != (old_v or ""):
            if new_v or new_v == 0:
                changed.append(f)
                old_val[f] = old_v
                new_val[f] = new_v
    return changed, old_val, new_val


def _merge_source(old_source, new_source):
    existing_sources = {s.strip() for s in (old_source or "").split(",") if s.strip()}
    existing_sources.add(new_source)
    merged_source = ",".join(sorted(existing_sources))
    if {"crt", "fofa"}.issubset(existing_sources):
        merged_source = "both"
    return merged_source


def _changelog_row(asset_id, domain, changed_fields, old_value, new_value, change_type):
    return (
        asset_id,
        domain,
        json.dumps(changed_fields, ensure_ascii=False),
        json.dumps(old_value, ensure_ascii=False) if old_value else "{}",
        json.dumps(new_value, ensure_ascii=False) if new_value else "{}",
        change_type,
        datetime.now().isoformat(timespec="seconds"),
    )


def _prefetch_chunk(conn, chunk):
    """Bulk-fetch existing rows + their tags for a chunk of items.
    Returns (existing_map: domain -> row dict, tag_map: asset_id -> [names])."""
    domains = [d for d in ((item.get("domain") or "").strip() for item in chunk) if d]
    existing_map = {}
    tag_map = {}
    if not domains:
        return existing_map, tag_map
    qmarks = ",".join("?" * len(domains))
    rows = conn.execute(f"SELECT * FROM assets WHERE domain IN ({qmarks})", domains).fetchall()
    existing_map = {r["domain"]: dict(r) for r in rows}
    ids = [old["id"] for old in existing_map.values()]
    if ids:
        ph = ",".join("?" * len(ids))
        tag_rows = conn.execute(
            f"SELECT at.asset_id, t.name FROM asset_tags at JOIN tags t ON t.id=at.tag_id "
            f"WHERE at.asset_id IN ({ph})",
            ids,
        ).fetchall()
        for r in tag_rows:
            tag_map.setdefault(r["asset_id"], []).append(r["name"])
    return existing_map, tag_map


def upsert_asset(data):
    """Insert or update by domain. Records changelog. Returns (asset_dict, change_type).
    Busy-safe: retried with backoff when parallel writers hold the write lock."""
    return db.retry_on_busy(_upsert_asset_once, data)


def _upsert_asset_once(data):
    domain = (data.get("domain") or "").strip()
    if not domain:
        return None, None
    now = datetime.now().isoformat(timespec="seconds")
    fields = _normalize_fields(data)
    tag_names = _normalize_tags(data)

    conn = db.get_conn()
    try:
        existing = conn.execute("SELECT * FROM assets WHERE domain=?", (domain,)).fetchone()
        if existing:
            old = dict(existing)
            changed, old_val, new_val = _diff_fields(old, fields)
            # merge source
            merged_source = _merge_source(old.get("source"), fields["source"])
            if merged_source != old.get("source"):
                changed.append("source")
                old_val["source"] = old.get("source")
                new_val["source"] = merged_source
            fields["source"] = merged_source

            if changed:
                set_cols = ", ".join(f"{c}=?" for c in changed)
                set_vals = [fields[c] for c in changed]
                set_cols += ", updated_at=?"
                set_vals.append(now)
                set_vals.append(old["id"])
                conn.execute(f"UPDATE assets SET {set_cols} WHERE id=?", set_vals)
                add_changelog(conn, old["id"], domain, changed, old_val, new_val, "更新")
                change_type = "更新"
            else:
                conn.execute("UPDATE assets SET updated_at=? WHERE id=?", (now, old["id"]))
                change_type = "无变化"
            asset_id = old["id"]
        else:
            cols = ASSET_COLUMNS + ["created_at", "updated_at"]
            vals = [fields[c] for c in ASSET_COLUMNS] + [now, now]
            placeholders = ",".join("?" for _ in cols)
            cur = conn.execute(
                f"INSERT INTO assets ({','.join(cols)}) VALUES ({placeholders})", vals
            )
            asset_id = cur.lastrowid
            add_changelog(conn, asset_id, domain, ["*"], {}, fields, "新增")
            change_type = "新增"

        if tag_names:
            if existing:
                existing_tags = set(get_asset_tags(conn, asset_id))
                merged = existing_tags | set(tag_names)
                set_asset_tags(conn, asset_id, list(merged))
            else:
                set_asset_tags(conn, asset_id, tag_names)

        register_dict_values(conn, fields)
        conn.commit()
        row = conn.execute("SELECT * FROM assets WHERE id=?", (asset_id,)).fetchone()
        asset = dict(row)
        asset["tags"] = get_asset_tags(conn, asset_id)
        return asset, change_type
    finally:
        conn.close()
        _invalidate_asset_cache()


def batch_upsert_assets(items, chunk_size=500):
    """Bulk upsert inside ONE transaction with pre-fetched lookups.

    Much faster than N x upsert_asset() for large imports: 1 connection,
    1 commit, 2 bulk SELECTs per chunk, and executemany flushes for
    tags / dictionary options / changelog.

    Robustness:
    - the whole batch is retried with exponential backoff when SQLite reports
      the DB busy/locked (parallel writers) - each attempt is a clean tx
    - a UNIQUE violation caused by a concurrent writer inserting the same
      domain between our prefetch SELECT and this INSERT no longer aborts the
      chunk: the row is re-read and applied as an update instead
    Returns (imported, updated, unchanged).
    """
    items = list(items)
    if not items:
        return 0, 0, 0
    return db.retry_on_busy(_batch_upsert_once, items, chunk_size)


class _DomainInsertConflict(Exception):
    """Internal sentinel: our INSERT hit UNIQUE(domain) because another
    connection committed the same domain between prefetch and insert."""

    def __init__(self, domain):
        super().__init__(domain)
        self.domain = domain


def _batch_upsert_once(items, chunk_size):
    """Run one full batch inside a single transaction. See batch_upsert_assets()."""
    imported = updated = unchanged = 0
    changelog_rows = []   # (asset_id, domain, changed_fields, old_value, new_value, change_type, created_at)
    tag_assign = []       # (asset_id, tag_name)
    dict_pairs = []       # (dtype, value)

    conn = db.get_conn()
    try:
        conn.execute("BEGIN")
        try:
            def do_update(old, fields, new_tags, domain, now):
                nonlocal updated, unchanged
                asset_id = old["id"]
                changed, old_val, new_val = _diff_fields(old, fields)
                merged_source = _merge_source(old.get("source"), fields["source"])
                if merged_source != old.get("source"):
                    changed.append("source")
                    old_val["source"] = old.get("source")
                    new_val["source"] = merged_source
                fields["source"] = merged_source
                if changed:
                    set_cols = ", ".join(f"{c}=?" for c in changed) + ", updated_at=?"
                    vals = [fields[c] for c in changed] + [now, asset_id]
                    conn.execute(f"UPDATE assets SET {set_cols} WHERE id=?", vals)
                    changelog_rows.append(_changelog_row(asset_id, domain, changed, old_val, new_val, "更新"))
                    updated += 1
                else:
                    conn.execute("UPDATE assets SET updated_at=? WHERE id=?", (now, asset_id))
                    unchanged += 1
                # keep the map fresh so duplicate domains inside one chunk
                # behave like sequential upserts
                merged_row = dict(old)
                merged_row.update({c: fields[c] for c in changed})
                merged_row["source"] = merged_source
                merged_row["updated_at"] = now
                existing_map[domain] = merged_row
                if new_tags:
                    for t in sorted(set(tag_map.get(asset_id, [])) | set(new_tags)):
                        tag_assign.append((asset_id, t))

            def do_insert(fields, new_tags, domain, now):
                nonlocal imported
                cols = ASSET_COLUMNS + ["created_at", "updated_at"]
                vals = [fields[c] for c in ASSET_COLUMNS] + [now, now]
                try:
                    cur = conn.execute(
                        f"INSERT INTO assets ({','.join(cols)}) VALUES ({','.join('?' * len(cols))})", vals
                    )
                except sqlite3.IntegrityError:
                    raise _DomainInsertConflict(domain) from None
                asset_id = cur.lastrowid
                changelog_rows.append(_changelog_row(asset_id, domain, ["*"], {}, fields, "新增"))
                imported += 1
                existing_map[domain] = {**{c: fields[c] for c in ASSET_COLUMNS},
                                        "id": asset_id, "created_at": now, "updated_at": now}
                for t in new_tags:
                    tag_assign.append((asset_id, t))

            for start in range(0, len(items), chunk_size):
                chunk = items[start:start + chunk_size]
                existing_map, tag_map = _prefetch_chunk(conn, chunk)
                for item in chunk:
                    domain = (item.get("domain") or "").strip()
                    if not domain:
                        continue
                    now = datetime.now().isoformat(timespec="seconds")
                    fields = _normalize_fields(item)
                    new_tags = _normalize_tags(item)
                    old = existing_map.get(domain)
                    if old is not None:
                        do_update(old, fields, new_tags, domain, now)
                    else:
                        try:
                            do_insert(fields, new_tags, domain, now)
                        except _DomainInsertConflict as c:
                            # Another connection committed this domain between
                            # our prefetch SELECT and the INSERT: re-read and
                            # apply as an update, never abort the whole chunk.
                            row = conn.execute(
                                "SELECT * FROM assets WHERE domain=?", (c.domain,)
                            ).fetchone()
                            if row is None:
                                # The other writer rolled back; retry the insert.
                                do_insert(fields, new_tags, domain, now)
                            else:
                                old = dict(row)
                                existing_map[domain] = old
                                tag_map.update(_bulk_tags(conn, [old["id"]]))
                                do_update(old, fields, new_tags, domain, now)
                    for dtype, value in _dict_pairs(fields):
                        dict_pairs.append((dtype, value))


            # --- bulk flushes (executemany) ---
            if tag_assign:
                names = sorted({t for _, t in tag_assign})
                conn.executemany("INSERT OR IGNORE INTO tags (name) VALUES (?)", [(n,) for n in names])
                id_rows = conn.execute(
                    f"SELECT id, name FROM tags WHERE name IN ({','.join('?' * len(names))})", names
                ).fetchall()
                name2id = {r["name"]: r["id"] for r in id_rows}
                conn.executemany(
                    "INSERT OR IGNORE INTO asset_tags (asset_id, tag_id) VALUES (?,?)",
                    [(aid, name2id[t]) for aid, t in tag_assign],
                )
            if dict_pairs:
                conn.executemany(
                    "INSERT OR IGNORE INTO dict_options (dtype, value) VALUES (?,?)", dict_pairs
                )
            if changelog_rows:
                conn.executemany(
                    """INSERT INTO asset_changelog
                       (asset_id, domain, changed_fields, old_value, new_value, change_type, created_at)
                       VALUES (?,?,?,?,?,?,?)""",
                    changelog_rows,
                )
            conn.commit()
            return imported, updated, unchanged
        except Exception:
            conn.rollback()
            raise
    finally:
        conn.close()
        _invalidate_asset_cache()


# ---------- search (FTS5 with LIKE fallback) ----------

_FTS_TOKEN_RE = re.compile(r"[0-9A-Za-z\u4e00-\u9fff]+")
# unicode61 cannot segment Chinese text: a contiguous CJK run becomes ONE
# token, so cross-word queries silently miss. Any query bearing CJK is routed
# to the (correct substring) LIKE path instead - see benchmark_search.py for
# the accuracy/latency trade-off.
_CJK_RE = re.compile(r"[\u4e00-\u9fff]")


def _has_cjk(text):
    return bool(_CJK_RE.search(text or ""))


def _fts_query(text):
    """Build a safe FTS5 MATCH expression from free-text input.
    Each token becomes a prefix term; tokens are ANDed (fuzzy, LIKE-like)."""
    tokens = _FTS_TOKEN_RE.findall((text or "").strip())
    if not tokens:
        return None
    return " AND ".join(f'"{t}"*' for t in tokens)


def _resolve_search_ids(conn, search):
    """Return matching asset ids via FTS5, or None to fall back to LIKE.
    Queries containing CJK always fall back to LIKE (see module note)."""
    if not search or not db.FTS_AVAILABLE or _has_cjk(search):
        return None
    match_q = _fts_query(search)
    if not match_q:
        return None
    try:
        rows = conn.execute(
            "SELECT rowid FROM assets_fts WHERE assets_fts MATCH ? LIMIT 100000", (match_q,)
        ).fetchall()
    except sqlite3.OperationalError:
        return None
    return [r[0] for r in rows]


def _apply_search_ids(conn, q, params, ids):
    """Fold an FTS id list into the query (chunked to avoid the SQLite
    variable limit). ids=None means the caller should fall back to LIKE."""
    if ids is None:
        return q, params
    if not ids:
        return None, None
    if len(ids) <= 900:
        q += f" AND a.id IN ({','.join('?' * len(ids))})"
        params += ids
        return q, params
    conn.execute("CREATE TEMP TABLE IF NOT EXISTS _fts_ids (id INTEGER PRIMARY KEY)")
    conn.execute("DELETE FROM _fts_ids")
    conn.executemany("INSERT OR IGNORE INTO _fts_ids (id) VALUES (?)", [(i,) for i in ids])
    q += " AND a.id IN (SELECT id FROM _fts_ids)"
    return q, params


def _build_asset_query(conn, filters, search_ids):
    """Build (where_sql, params) applied to `assets a`, including all filters.
    Returns (None, None) when FTS matched nothing."""
    q = " WHERE 1=1"
    params = []
    if filters.get("search"):
        if search_ids is not None:
            q, params = _apply_search_ids(conn, q, params, search_ids)
            if q is None:
                return None, None
        else:
            # Multi-term AND: each whitespace/comma separated term must appear
            # in at least one of the text columns. This is what makes Chinese
            # search usable (unicode61 cannot segment CJK) and mirrors the AND
            # semantics of the FTS path for Latin text.
            terms = [t for t in re.split(r"[\s,，、;；|/]+", filters["search"]) if t]
            if not terms:
                terms = [filters["search"]]
            for term in terms:
                like = f"%{term}%"
                q += " AND (a.domain LIKE ? OR a.url LIKE ? OR a.ip LIKE ? OR a.title LIKE ? OR a.server LIKE ? OR a.cms LIKE ?)"
                params += [like] * 6
    if filters.get("country"):
        q += " AND a.country=?"
        params.append(filters["country"])
    if filters.get("cms"):
        q += " AND a.cms=?"
        params.append(filters["cms"])
    if filters.get("source"):
        # Match source in comma-separated list, or "both" which means crt+fofa
        src = filters["source"]
        q += " AND (a.source = ? OR a.source LIKE ? OR a.source LIKE ? OR a.source LIKE ?"
        if src in ('crt', 'fofa'):
            q += " OR a.source = 'both'"
        q += ")"
        params += [src, f"%,{src}", f"{src},%", f"%,{src},%"]
    if filters.get("tag"):
        q += " AND EXISTS(SELECT 1 FROM asset_tags at JOIN tags t ON t.id=at.tag_id WHERE at.asset_id=a.id AND t.name=?)"
        params.append(filters["tag"])
    if filters.get("tags_multi"):
        placeholders = ",".join("?" for _ in filters["tags_multi"])
        q += f" AND a.id IN (SELECT at2.asset_id FROM asset_tags at2 JOIN tags t2 ON t2.id=at2.tag_id WHERE t2.name IN ({placeholders}) GROUP BY at2.asset_id HAVING COUNT(DISTINCT t2.name)=?)"
        params += filters["tags_multi"]
        params.append(len(filters["tags_multi"]))
    return q, params


SEARCH_CACHE_TTL = 8  # seconds a hot search result stays cached


def _search_cache_key(filters, page, per_page, sort, order):
    payload = json.dumps({"f": filters, "p": page, "pp": per_page, "s": sort, "o": order},
                         sort_keys=True, ensure_ascii=False, default=str)
    return "search:" + hashlib.md5(payload.encode("utf-8")).hexdigest()


def list_assets(filters=None, page=1, per_page=20, sort="updated_at", order="desc"):
    """Paginated asset listing/search with a short hot-query cache.

    Identical requests (filters + page + sort) are served from the TTL cache
    instead of re-running the FTS/LIKE query + COUNT + ORDER BY sort. Every
    write touching assets / tags / dictionaries invalidates the whole
    "search:" prefix (see _invalidate_asset_cache), so results are never stale
    beyond the current request cycle.
    """
    filters = filters or {}
    key = _search_cache_key(filters, page, per_page, sort, order)
    return cache.get(key,
                     lambda: _list_assets_uncached(filters, page, per_page, sort, order),
                     ttl=SEARCH_CACHE_TTL)


def _list_assets_uncached(filters, page, per_page, sort, order):
    filters = filters or {}
    conn = db.get_conn()
    try:
        search_ids = _resolve_search_ids(conn, filters.get("search"))
        where, params = _build_asset_query(conn, filters, search_ids)
        if where is None:
            return [], 0
        total = conn.execute(f"SELECT COUNT(*) FROM assets a{where}", params).fetchone()[0]

        allowed_sort = {"domain", "created_at", "updated_at", "ip", "title"}
        sort_col = sort if sort in allowed_sort else "updated_at"
        order_dir = "DESC" if order.lower() == "desc" else "ASC"
        offset = (page - 1) * per_page
        q = f"SELECT a.* FROM assets a{where} ORDER BY a.{sort_col} {order_dir} LIMIT ? OFFSET ?"
        rows = conn.execute(q, params + [per_page, offset]).fetchall()

        ids = [r["id"] for r in rows]
        tags = _bulk_tags(conn, ids)
        assets = []
        for r in rows:
            a = dict(r)
            a["tags"] = tags.get(a["id"], [])
            assets.append(a)
        return assets, total
    finally:
        conn.close()


def iter_asset_shards(filters=None, shard_size=1000, max_shards=None):
    """Sharded (keyset) scan of all matching assets, ordered by id.

    Keyset pagination (id > last_id) avoids the OFFSET slowdown that kicks in
    on large tables, and lets big jobs (CSV export, re-scan, cleanup) stream
    the table in bounded chunks. Each yielded shard is a list of asset dicts.
    `max_shards` optionally caps the number of shards yielded.
    """
    filters = filters or {}
    conn = db.get_conn()
    try:
        search_ids = _resolve_search_ids(conn, filters.get("search"))
        where, params = _build_asset_query(conn, filters, search_ids)
        if where is None:
            return
        base = f"SELECT * FROM assets a{where}"
        last_id = 0
        yielded = 0
        while True:
            if max_shards is not None and yielded >= max_shards:
                break
            rows = conn.execute(
                base + " AND a.id > ? ORDER BY a.id ASC LIMIT ?",
                params + [last_id, shard_size],
            ).fetchall()
            if not rows:
                break
            ids = [r["id"] for r in rows]
            tags = _bulk_tags(conn, ids)
            shard = []
            for r in rows:
                a = dict(r)
                a["tags"] = tags.get(a["id"], [])
                shard.append(a)
            last_id = rows[-1]["id"]
            yielded += 1
            yield shard
    finally:
        conn.close()


def get_asset(asset_id):
    conn = db.get_conn()
    try:
        r = conn.execute("SELECT * FROM assets WHERE id=?", (asset_id,)).fetchone()
        if not r:
            return None
        a = dict(r)
        a["tags"] = get_asset_tags(conn, asset_id)
        return a
    finally:
        conn.close()


def get_asset_by_domain(domain):
    """Get asset by domain name."""
    conn = db.get_conn()
    try:
        r = conn.execute("SELECT * FROM assets WHERE domain=?", (domain,)).fetchone()
        if not r:
            return None
        a = dict(r)
        a["tags"] = get_asset_tags(conn, a["id"])
        return a
    finally:
        conn.close()


def delete_asset(asset_id):
    conn = db.get_conn()
    try:
        r = conn.execute("SELECT domain FROM assets WHERE id=?", (asset_id,)).fetchone()
        domain = r["domain"] if r else ""
        conn.execute("DELETE FROM asset_tags WHERE asset_id=?", (asset_id,))
        conn.execute("DELETE FROM assets WHERE id=?", (asset_id,))
        if domain:
            add_changelog(conn, None, domain, ["*"], {}, {}, "消失")
        conn.commit()
        _invalidate_asset_cache()
    finally:
        conn.close()


def delete_assets(ids):
    conn = db.get_conn()
    try:
        for asset_id in ids:
            r = conn.execute("SELECT domain FROM assets WHERE id=?", (asset_id,)).fetchone()
            domain = r["domain"] if r else ""
            conn.execute("DELETE FROM asset_tags WHERE asset_id=?", (asset_id,))
            conn.execute("DELETE FROM assets WHERE id=?", (asset_id,))
            if domain:
                add_changelog(conn, None, domain, ["*"], {}, {}, "消失")
        conn.commit()
        _invalidate_asset_cache()
    finally:
        conn.close()


def all_root_domains():
    conn = db.get_conn()
    try:
        rows = conn.execute(
            "SELECT DISTINCT root_domain FROM assets WHERE root_domain <> ''"
        ).fetchall()
        return [r["root_domain"] for r in rows]
    finally:
        conn.close()


def dashboard_stats():
    return cache.get("stats:dashboard", _load_dashboard_stats, ttl=15)


def _load_dashboard_stats():
    conn = db.get_conn()
    try:
        total = conn.execute("SELECT COUNT(*) c FROM assets").fetchone()["c"]
        root_count = conn.execute(
            "SELECT COUNT(DISTINCT root_domain) c FROM assets WHERE root_domain <> ''"
        ).fetchone()["c"]
        country_count = conn.execute(
            "SELECT COUNT(DISTINCT country) c FROM assets WHERE country <> ''"
        ).fetchone()["c"]
        cms_count = conn.execute(
            "SELECT COUNT(DISTINCT cms) c FROM assets WHERE cms <> ''"
        ).fetchone()["c"]
        today = date.today().isoformat()
        today_new = conn.execute(
            "SELECT COUNT(*) c FROM assets WHERE substr(created_at,1,10)=?", (today,)
        ).fetchone()["c"]

        # distributions
        src_rows = conn.execute(
            "SELECT source, COUNT(*) c FROM assets GROUP BY source"
        ).fetchall()
        source_dist = {r["source"]: r["c"] for r in src_rows}

        country_rows = conn.execute(
            "SELECT country, COUNT(*) c FROM assets WHERE country <> '' GROUP BY country ORDER BY c DESC LIMIT 10"
        ).fetchall()
        country_dist = {r["country"]: r["c"] for r in country_rows}

        cms_rows = conn.execute(
            "SELECT cms, COUNT(*) c FROM assets WHERE cms <> '' GROUP BY cms ORDER BY c DESC LIMIT 10"
        ).fetchall()
        cms_dist = {r["cms"]: r["c"] for r in cms_rows}

        # daily trend (7 days)
        trend_rows = conn.execute(
            """SELECT substr(created_at,1,10) d, COUNT(*) c FROM assets
               WHERE created_at >= date('now','-6 days')
               GROUP BY d ORDER BY d"""
        ).fetchall()
        daily_trend = {r["d"]: r["c"] for r in trend_rows}

        # today changelog
        tc = today_changelog_counts()

        return {
            "total": total,
            "root_domains": root_count,
            "countries": country_count,
            "cms_types": cms_count,
            "today_new": today_new,
            "today_added": tc.get("新增", 0),
            "today_changed": tc.get("更新", 0),
            "today_disappeared": tc.get("消失", 0),
            "source_dist": source_dist,
            "country_dist": country_dist,
            "cms_dist": cms_dist,
            "daily_trend": daily_trend,
        }
    finally:
        conn.close()


# ---------- nuclei scan results ----------

SEVERITY_RANK = {"critical": 5, "high": 4, "medium": 3, "low": 2,
                 "info": 1, "unknown": 0}


def insert_nuclei_results(findings, scan_id=""):
    """Bulk-insert parsed Nuclei findings in one transaction.
    Each finding is a dict with keys: asset_id, host, template_id, template_name,
    severity, vuln_type, description, matched_at, extracted_results, curl_command,
    raw_json, created_at. Returns number of rows inserted.

    `scan_id` tags every row with its owning scan generation, enabling the
    atomic swap in finalize_nuclei_scan(). Busy-safe (parallel writers)."""
    findings = list(findings)
    if not findings:
        return 0
    scan_id = str(scan_id or "")

    def _once():
        conn = db.get_conn()
        try:
            conn.executemany(
                """INSERT INTO nuclei_results
                   (asset_id, host, template_id, template_name, severity, vuln_type,
                    description, matched_at, extracted_results, curl_command,
                    raw_json, scan_id, created_at)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                [
                    (
                        f.get("asset_id"),
                        f.get("host") or "",
                        f.get("template_id") or "",
                        f.get("template_name") or "",
                        (f.get("severity") or "info").lower(),
                        f.get("vuln_type") or "",
                        f.get("description") or "",
                        f.get("matched_at") or "",
                        f.get("extracted_results") or "",
                        f.get("curl_command") or "",
                        f.get("raw_json") or "",
                        scan_id,
                        f.get("created_at") or datetime.now().isoformat(timespec="seconds"),
                    )
                    for f in findings
                ],
            )
            conn.commit()
            return len(findings)
        finally:
            conn.close()

    return db.retry_on_busy(_once)


def get_asset_nuclei_results(asset_id, limit=500):
    """All Nuclei findings for one asset, critical-first then newest."""
    conn = db.get_conn()
    try:
        rows = conn.execute(
            "SELECT * FROM nuclei_results WHERE asset_id=? ORDER BY id DESC LIMIT ?",
            (asset_id, limit),
        ).fetchall()
        results = [dict(r) for r in rows]
        results.sort(key=lambda r: (SEVERITY_RANK.get(r.get("severity", "unknown"), 0),
                                    r.get("created_at") or ""), reverse=True)
        return results
    finally:
        conn.close()


def _normalize_asset_ids(asset_ids):
    """Unique sorted int ids (used by the nuclei generation-swap helpers)."""
    return sorted({int(x) for x in (asset_ids or []) if x})


def finalize_nuclei_scan(scan_id, asset_ids):
    """Commit a finished scan: atomically swap to the new generation.

    Old results stay visible while the scan runs and are only removed here, in
    one transaction, once ALL of this scan's findings are already persisted.
    Rows NOT tagged with `scan_id` (previous scans / legacy rows) are deleted;
    this scan's rows survive. A crashed/failed scan therefore never wipes
    stored results. Returns number of superseded rows deleted."""
    ids = _normalize_asset_ids(asset_ids)
    if not ids or not str(scan_id or ""):
        return 0
    scan_id = str(scan_id)

    def _once():
        conn = db.get_conn()
        try:
            deleted = 0
            for i in range(0, len(ids), 500):
                group = ids[i:i + 500]
                ph = ",".join("?" * len(group))
                cur = conn.execute(
                    f"DELETE FROM nuclei_results WHERE asset_id IN ({ph}) AND scan_id != ?",
                    group + [scan_id],
                )
                deleted += cur.rowcount
            conn.commit()
            return deleted
        finally:
            conn.close()

    return db.retry_on_busy(_once)


def abort_nuclei_scan(scan_id, asset_ids):
    """Discard the partial findings of a failed/stopped scan.

    Only rows tagged with `scan_id` are removed, so the pre-scan results stay
    intact for the affected assets. Returns number of rows removed."""
    ids = _normalize_asset_ids(asset_ids)
    if not ids or not str(scan_id or ""):
        return 0
    scan_id = str(scan_id)

    def _once():
        conn = db.get_conn()
        try:
            deleted = 0
            for i in range(0, len(ids), 500):
                group = ids[i:i + 500]
                ph = ",".join("?" * len(group))
                cur = conn.execute(
                    f"DELETE FROM nuclei_results WHERE asset_id IN ({ph}) AND scan_id = ?",
                    group + [scan_id],
                )
                deleted += cur.rowcount
            conn.commit()
            return deleted
        finally:
            conn.close()

    return db.retry_on_busy(_once)


def clear_asset_nuclei_results(asset_id):
    """Remove stored Nuclei findings for one asset (manual "清除结果").
    Returns deleted count. Busy-safe."""
    def _once():
        conn = db.get_conn()
        try:
            cur = conn.execute("DELETE FROM nuclei_results WHERE asset_id=?", (asset_id,))
            conn.commit()
            return cur.rowcount
        finally:
            conn.close()

    return db.retry_on_busy(_once)


def nuclei_severity_summary(asset_id):
    """{severity: count} for one asset (for badge/tab display)."""
    conn = db.get_conn()
    try:
        rows = conn.execute(
            "SELECT severity, COUNT(*) c FROM nuclei_results WHERE asset_id=? "
            "GROUP BY severity",
            (asset_id,),
        ).fetchall()
        return {r["severity"]: r["c"] for r in rows}
    finally:
        conn.close()


# ---------- CSV report export ----------

CSV_HEADER = ["id", "domain", "url", "ip", "port", "title", "country",
              "country_code", "cms", "server", "waf", "owner", "remark",
              "expiration_date", "status_code", "source", "tags",
              "root_domain", "created_at", "updated_at"]


def export_csv(filters=None, max_rows=None):
    """Generate a CSV report of matching assets (sharded keyset scan).

    Returns (filename, csv_text). `max_rows` optionally caps the output
    (used by the AI assistant to keep generated reports bounded).
    """
    out = io.StringIO()
    writer = csv.writer(out)
    writer.writerow(CSV_HEADER)
    rows = 0
    for shard in iter_asset_shards(filters or None, shard_size=2000):
        for a in shard:
            writer.writerow([
                a.get("id"), a.get("domain"), a.get("url"), a.get("ip"),
                a.get("port"), a.get("title"), a.get("country"),
                a.get("country_code"), a.get("cms"), a.get("server"),
                a.get("waf"), a.get("owner"), a.get("remark"),
                a.get("expiration_date"), a.get("status_code"),
                a.get("source"), ",".join(a.get("tags", [])),
                a.get("root_domain"), a.get("created_at"), a.get("updated_at"),
            ])
            rows += 1
            if max_rows and rows >= max_rows:
                break
        if max_rows and rows >= max_rows:
            break
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    return f"assets_report_{ts}.csv", out.getvalue()


# ---------- AI assistant: chat sessions & history ----------

def create_chat_session(title="新对话", model=""):
    """Create a new chat session. Returns the session dict.
    `model` is a canonical 'provider:model' key ('' = global default)."""
    session_id = uuid.uuid4().hex
    model = (model or "").strip()
    now = datetime.now().isoformat(timespec="seconds")
    conn = db.get_conn()
    try:
        conn.execute(
            "INSERT INTO chat_sessions (session_id, title, model, created_at, updated_at) VALUES (?,?,?,?,?)",
            (session_id, title, model, now, now),
        )
        conn.commit()
        return {"session_id": session_id, "title": title, "model": model,
                "created_at": now, "updated_at": now}
    finally:
        conn.close()


def get_chat_session(session_id):
    conn = db.get_conn()
    try:
        r = conn.execute(
            "SELECT * FROM chat_sessions WHERE session_id=?", (session_id,)
        ).fetchone()
        return dict(r) if r else None
    finally:
        conn.close()


def list_chat_sessions(limit=100):
    conn = db.get_conn()
    try:
        rows = conn.execute(
            "SELECT session_id, title, model, created_at, updated_at FROM chat_sessions "
            "ORDER BY updated_at DESC LIMIT ?", (limit,)
        ).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def set_chat_session_model(session_id, model):
    """Set the model ('provider:model' or '') the NEXT turn of this session
    will use. Returns True if the session exists."""
    model = (model or "").strip()
    conn = db.get_conn()
    try:
        cur = conn.execute(
            "UPDATE chat_sessions SET model=?, updated_at=? WHERE session_id=?",
            (model, datetime.now().isoformat(timespec="seconds"), session_id),
        )
        conn.commit()
        return cur.rowcount > 0
    finally:
        conn.close()


def update_chat_session_title(session_id, title):
    """Rename a session (e.g. auto-title from the first user message)."""
    title = (title or "新对话").strip()[:50]
    conn = db.get_conn()
    try:
        conn.execute(
            "UPDATE chat_sessions SET title=?, updated_at=? WHERE session_id=?",
            (title, datetime.now().isoformat(timespec="seconds"), session_id),
        )
        conn.commit()
    finally:
        conn.close()


def touch_chat_session(session_id):
    conn = db.get_conn()
    try:
        conn.execute(
            "UPDATE chat_sessions SET updated_at=? WHERE session_id=?",
            (datetime.now().isoformat(timespec="seconds"), session_id),
        )
        conn.commit()
    finally:
        conn.close()


def delete_chat_session(session_id):
    """Remove a session and all its messages. Returns True if removed."""
    conn = db.get_conn()
    try:
        conn.execute("DELETE FROM chat_history WHERE session_id=?", (session_id,))
        cur = conn.execute("DELETE FROM chat_sessions WHERE session_id=?", (session_id,))
        conn.commit()
        return cur.rowcount > 0
    finally:
        conn.close()


def add_chat_message(session_id, role, content, tool_calls=None, tool_call_id=None,
                     model=None, usage=None):
    """Persist one message. `tool_calls` is a list of dicts (assistant only).
    `model` is the canonical 'provider:model' key that produced the message;
    `usage` is an optional dict {prompt_tokens, completion_tokens, ...}.
    Returns the message id."""
    conn = db.get_conn()
    try:
        cur = conn.execute(
            """INSERT INTO chat_history
               (session_id, role, content, tool_calls, tool_call_id, model, usage_json, created_at)
               VALUES (?,?,?,?,?,?,?,?)""",
            (session_id, role, content or "",
             json.dumps(tool_calls, ensure_ascii=False) if tool_calls else "",
             tool_call_id or "",
             (model or "").strip(),
             json.dumps(usage, ensure_ascii=False) if usage else "",
             datetime.now().isoformat(timespec="seconds")),
        )
        conn.commit()
        return cur.lastrowid
    finally:
        conn.close()


def get_chat_messages(session_id, limit=200):
    """All messages of a session, oldest first, for rebuilding the conversation.
    Each message dict includes `model` ('provider:model' or '') and `usage`
    (parsed token-usage dict or None)."""
    conn = db.get_conn()
    try:
        rows = conn.execute(
            "SELECT * FROM chat_history WHERE session_id=? ORDER BY id ASC LIMIT ?",
            (session_id, limit),
        ).fetchall()
        msgs = []
        for r in rows:
            m = {"role": r["role"], "content": r["content"],
                 "model": r["model"] or ""}
            if r["role"] == "assistant" and r["tool_calls"]:
                try:
                    m["tool_calls"] = json.loads(r["tool_calls"])
                except ValueError:
                    pass
            if r["role"] == "tool":
                m["tool_call_id"] = r["tool_call_id"]
            if r["usage_json"]:
                try:
                    m["usage"] = json.loads(r["usage_json"])
                except ValueError:
                    pass
            msgs.append(m)
        return msgs
    finally:
        conn.close()


# ---------- AI assistant: tool audit log ----------

def log_ai_tool(session_id, tool, arguments, result, status="ok"):
    """Append one entry to the AI tool audit log."""
    conn = db.get_conn()
    try:
        conn.execute(
            """INSERT INTO ai_tool_log (session_id, tool, arguments, result, status, created_at)
               VALUES (?,?,?,?,?,?)""",
            (session_id, tool,
             json.dumps(arguments, ensure_ascii=False) if not isinstance(arguments, str) else arguments,
             str(result)[:2000], status,
             datetime.now().isoformat(timespec="seconds")),
        )
        conn.commit()
    finally:
        conn.close()


def recent_ai_tool_log(limit=50):
    conn = db.get_conn()
    try:
        rows = conn.execute(
            "SELECT * FROM ai_tool_log ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


# ---------- fingerprint / identify task persistence (crash-safe progress) ----------

def create_fingerprint_task(task_id, asset_ids):
    """Record a new fingerprint job. `asset_ids` is the FULL ordered id list;
    `processed` (see update_fingerprint_task) is the durable checkpoint into it."""
    now = datetime.now().isoformat(timespec="seconds")
    conn = db.get_conn()
    try:
        conn.execute(
            """INSERT INTO fingerprint_tasks
               (task_id, status, total, processed, asset_ids, error, created_at, updated_at)
               VALUES (?,?,?,?,?,?,?,?)""",
            (task_id, "running", len(asset_ids), 0,
             json.dumps(asset_ids, ensure_ascii=False), "", now, now),
        )
        conn.commit()
    finally:
        conn.close()


def update_fingerprint_task(task_id, processed=None, status=None, error=None):
    """Persist a progress checkpoint for a fingerprint task (busy-safe)."""
    sets, vals = [], []
    if processed is not None:
        sets.append("processed=?")
        vals.append(int(processed))
    if status is not None:
        sets.append("status=?")
        vals.append(status)
    if error is not None:
        sets.append("error=?")
        vals.append(str(error)[:1000])
    if not sets:
        return
    sets.append("updated_at=?")
    vals.append(datetime.now().isoformat(timespec="seconds"))
    vals.append(task_id)

    def _once():
        conn = db.get_conn()
        try:
            conn.execute(
                f"UPDATE fingerprint_tasks SET {', '.join(sets)} WHERE task_id=?", vals
            )
            conn.commit()
        finally:
            conn.close()

    db.retry_on_busy(_once, attempts=3, base=0.1)


def get_fingerprint_task(task_id):
    conn = db.get_conn()
    try:
        r = conn.execute(
            "SELECT * FROM fingerprint_tasks WHERE task_id=?", (task_id,)
        ).fetchone()
        return dict(r) if r else None
    finally:
        conn.close()


def recover_interrupted_fingerprint_tasks():
    """Startup hook: any task left 'running' belonged to a process that died
    (server restart / crash). Mark it 'interrupted' but KEEP its checkpoint so
    the user can resume from where it stopped (see /api/assets/identify/<id>/resume)."""
    now = datetime.now().isoformat(timespec="seconds")
    conn = db.get_conn()
    try:
        conn.execute(
            "UPDATE fingerprint_tasks SET status='interrupted', updated_at=? WHERE status='running'",
            (now,),
        )
        conn.commit()
    finally:
        conn.close()


# ---------- lightweight port-service identification ----------

def save_port_scan_result(asset_id, mapping, scanned_at=None):
    """Persist a {port: service} scan result on an asset (busy-safe).

    `port` stores the open port list (e.g. "80,443,3306") and `service` the
    JSON port->service map; `ports_scanned_at` records when the probe ran
    (used for the 24h dedup window). Unknown-but-open ports keep an empty
    label in the JSON so the UI can still show them."""
    if isinstance(mapping, dict):
        mapping = json.dumps(mapping, ensure_ascii=False)
    try:
        svc = json.loads(mapping or "{}")
        if not isinstance(svc, dict):
            svc = {}
    except ValueError:
        svc = {}
    try:
        ports_sorted = sorted(svc.keys(), key=lambda p: int(p))
    except (ValueError, TypeError):
        ports_sorted = sorted(svc.keys())
    ports_text = ",".join(ports_sorted)
    scanned_at = scanned_at or datetime.now().isoformat(timespec="seconds")

    def _once():
        conn = db.get_conn()
        try:
            conn.execute(
                "UPDATE assets SET port=?, service=?, ports_scanned_at=? WHERE id=?",
                (ports_text, json.dumps(svc, ensure_ascii=False),
                 scanned_at, int(asset_id)),
            )
            conn.commit()
        finally:
            conn.close()

    db.retry_on_busy(_once)
    _invalidate_asset_cache()


def assets_by_ip(ip):
    """All assets resolving to one IP, with parsed service maps attached.
    Used by the graph IP popup and the "立即扫描" flow."""
    conn = db.get_conn()
    try:
        rows = conn.execute(
            "SELECT * FROM assets WHERE ip=? ORDER BY domain", (str(ip).strip(),)
        ).fetchall()
        ids = [r["id"] for r in rows]
        tags = _bulk_tags(conn, ids)
        out = []
        for r in rows:
            a = dict(r)
            a["tags"] = tags.get(a["id"], [])
            try:
                a["service_map"] = json.loads(a.get("service") or "{}")
            except ValueError:
                a["service_map"] = {}
            out.append(a)
        return out
    finally:
        conn.close()


def graph_data(domain=None, max_nodes=500):
    """Build ECharts-graph payload around root domains.

    Node types: root (red), subdomain (blue), ip (green), service (orange).
    Edges:  root -> subdomain (contains)
            subdomain -> ip (resolves)
            ip -> service (listens)
    `domain` filters to one root domain; without it the Top-10 root domains
    (by asset count) are drawn. Nodes are capped at `max_nodes`.
    """
    conn = db.get_conn()
    try:
        domain = (domain or "").strip().lower().lstrip("*.")
        asset_rows = []
        roots = []
        if domain:
            rows = conn.execute(
                "SELECT id, domain, root_domain, ip, port, service, ports_scanned_at "
                "FROM assets WHERE root_domain=? ORDER BY updated_at DESC LIMIT 3000",
                (domain,),
            ).fetchall()
            roots = [{"root": domain, "count": len(rows)}]
            asset_rows = [dict(r) for r in rows]
        else:
            top = conn.execute(
                "SELECT root_domain, COUNT(*) c FROM assets WHERE root_domain<>'' "
                "GROUP BY root_domain ORDER BY c DESC, root_domain LIMIT 10"
            ).fetchall()
            roots = [{"root": r["root_domain"], "count": r["c"]} for r in top]
            if roots:
                for r in top:
                    rows = conn.execute(
                        "SELECT id, domain, root_domain, ip, port, service, "
                        "ports_scanned_at FROM assets WHERE root_domain=? "
                        "ORDER BY updated_at DESC LIMIT 200",
                        (r["root_domain"],),
                    ).fetchall()
                    asset_rows.extend(dict(x) for x in rows)

        nodes = {}
        edges = []
        truncated = False

        def add_node(nid, node):
            if nid not in nodes:
                nodes[nid] = node

        for r in roots:
            add_node("root:" + r["root"],
                     {"id": "root:" + r["root"], "name": r["root"],
                      "type": "root"})

        ip_svc = {}   # ip -> {port: label}
        for a in asset_rows:
            if len(nodes) >= max_nodes:
                truncated = True
                break
            rname = a.get("root_domain") or ""
            dname = a.get("domain") or ""
            nid = "a:" + dname
            add_node(nid, {"id": nid, "name": dname, "type": "subdomain",
                           "asset_id": a.get("id")})
            if rname:
                edges.append({"source": "root:" + rname, "target": nid})
            ip = (a.get("ip") or "").strip()
            if ip:
                ip_nid = "ip:" + ip
                add_node(ip_nid, {"id": ip_nid, "name": ip, "type": "ip"})
                edges.append({"source": nid, "target": ip_nid})
                try:
                    svc = json.loads(a.get("service") or "{}")
                except ValueError:
                    svc = {}
                if isinstance(svc, dict) and svc:
                    merged = ip_svc.setdefault(ip, {})
                    for p, label in svc.items():
                        merged.setdefault(str(p), label)

        for ip, svc in ip_svc.items():
            for p in sorted(svc, key=lambda x: int(x) if str(x).isdigit() else 0):
                if len(nodes) >= max_nodes:
                    truncated = True
                    break
                label = svc[p] or ""
                nid = f"svc:{ip}:{p}"
                add_node(nid, {"id": nid,
                               "name": f"{p}" + (f":{label}" if label else ""),
                               "type": "service", "port": p, "ip": ip})
                edges.append({"source": "ip:" + ip, "target": nid})

        return {
            "domain": domain or "",
            "roots": roots,
            "asset_count": len(asset_rows),
            "root_total": sum(r["count"] for r in roots),
            "truncated": truncated,
            "nodes": list(nodes.values()),
            "edges": edges,
        }
    finally:
        conn.close()


# ---------- AI assistant: multi-model providers ----------

def _mask_api_key(key):
    """Mask an api key for API responses ('sk-…abcd')."""
    key = (key or "").strip()
    if not key:
        return ""
    if len(key) <= 8:
        return "•" * len(key)
    return key[:4] + "…" + key[-4:]


def list_ai_providers(include_disabled=True):
    """All configured AI providers, ordered enabled/default first.
    api_key is masked (use get_ai_provider() for the real value)."""
    conn = db.get_conn()
    try:
        q = "SELECT * FROM ai_providers"
        if not include_disabled:
            q += " WHERE enabled=1"
        q += " ORDER BY is_default DESC, enabled DESC, display_name, name"
        rows = conn.execute(q).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            d["api_key"] = _mask_api_key(d.get("api_key"))
            try:
                d["models_list"] = json.loads(d.get("models") or "[]")
            except ValueError:
                d["models_list"] = []
            out.append(d)
        return out
    finally:
        conn.close()


def get_ai_provider(name):
    """Full provider row (unmasked api_key) or None. `name` is the canonical
    provider name (e.g. 'deepseek')."""
    conn = db.get_conn()
    try:
        r = conn.execute(
            "SELECT * FROM ai_providers WHERE name=?", (name,)
        ).fetchone()
        if not r:
            return None
        d = dict(r)
        try:
            d["models_list"] = json.loads(d.get("models") or "[]")
        except ValueError:
            d["models_list"] = []
        return d
    finally:
        conn.close()


def save_ai_provider(data):
    """Create or update one AI provider row (busy-safe).

    Semantics:
    - an empty api_key in `data` keeps the stored key (settings UIs treat an
      empty password field as "unchanged")
    - setting is_default=1 clears the default flag on every other row in the
      same transaction (exactly one default exists)
    - toggling a provider on with an empty key is allowed (some endpoints such
      as local Ollama need no key); the chat layer reports the error on use.
    Returns (row, error_message)."""
    name = (data.get("name") or "").strip()
    if not name:
        return None, "缺少 provider name"

    def _once():
        conn = db.get_conn()
        try:
            existing = conn.execute(
                "SELECT * FROM ai_providers WHERE name=?", (name,)
            ).fetchone()
            now = datetime.now().isoformat(timespec="seconds")
            if existing:
                cols, vals = [], []
                text_fields = ("provider_type", "display_name", "base_url", "model",
                               "models", "temperature", "max_tokens", "note")
                for f in text_fields:
                    if f in data:
                        cols.append(f + "=?")
                        vals.append(str(data.get(f) or "").strip())
                for f, cast in (("context_window", int), ("cost_in_per_1m", float),
                                ("cost_out_per_1m", float)):
                    if f in data:
                        try:
                            v = cast(data.get(f) or 0)
                        except (ValueError, TypeError):
                            v = 0
                        cols.append(f + "=?")
                        vals.append(v)
                for f in ("speed_tier",):
                    if f in data:
                        cols.append(f + "=?")
                        vals.append((data.get(f) or "").strip())
                for f in ("enabled", "is_default"):
                    if f in data:
                        cols.append(f + "=?")
                        vals.append(1 if data.get(f) else 0)
                if "api_key" in data and str(data.get("api_key") or "").strip():
                    cols.append("api_key=?")
                    vals.append(str(data.get("api_key")).strip())
                if not cols:
                    conn.rollback()
                    return dict(existing), None
                cols.append("updated_at=?")
                vals.append(now)
                vals.append(name)
                conn.execute(
                    f"UPDATE ai_providers SET {', '.join(cols)} WHERE name=?", vals
                )
            else:
                models_json = data.get("models")
                if isinstance(models_json, (list, tuple)):
                    models_json = json.dumps(list(models_json), ensure_ascii=False)
                conn.execute(
                    """INSERT INTO ai_providers
                       (name, provider_type, display_name, api_key, base_url, model,
                        models, temperature, max_tokens, context_window,
                        cost_in_per_1m, cost_out_per_1m, speed_tier, note,
                        enabled, is_default, created_at, updated_at)
                       VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (name,
                     (data.get("provider_type") or "openai_compat").strip(),
                     str(data.get("display_name") or name),
                     str(data.get("api_key") or "").strip(),
                     str(data.get("base_url") or "").strip(),
                     str(data.get("model") or "").strip(),
                     models_json or "",
                     str(data.get("temperature") or "").strip(),
                     str(data.get("max_tokens") or "").strip(),
                     int(data.get("context_window") or 0),
                     float(data.get("cost_in_per_1m") or 0),
                     float(data.get("cost_out_per_1m") or 0),
                     str(data.get("speed_tier") or "").strip(),
                     str(data.get("note") or "").strip(),
                     1 if data.get("enabled") else 0,
                     1 if data.get("is_default") else 0,
                     now, now),
                )
            if data.get("is_default"):
                conn.execute(
                    "UPDATE ai_providers SET is_default=0 WHERE name<>?", (name,)
                )
            conn.commit()
            row = conn.execute(
                "SELECT * FROM ai_providers WHERE name=?", (name,)
            ).fetchone()
            return dict(row), None
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    return db.retry_on_busy(_once)


def clear_default_ai_provider():
    """If no provider is currently flagged default, promote the first enabled
    one (keeps new conversations usable after a default is disabled)."""
    conn = db.get_conn()
    try:
        r = conn.execute(
            "SELECT COUNT(*) c FROM ai_providers WHERE is_default=1 AND enabled=1"
        ).fetchone()
        if r["c"]:
            return
        n = conn.execute(
            "SELECT COUNT(*) c FROM ai_providers WHERE enabled=1"
        ).fetchone()["c"]
        if not n:
            return
        conn.execute(
            "UPDATE ai_providers SET is_default=0 WHERE is_default=1"
        )
        conn.execute(
            """UPDATE ai_providers SET is_default=1 WHERE id = (
                 SELECT id FROM ai_providers WHERE enabled=1 ORDER BY display_name, name LIMIT 1
               )"""
        )
        conn.commit()
    finally:
        conn.close()


# ---------- AI assistant: upstream call audit log ----------

def log_ai_call(session_id="", provider="", model="", ok=True, error_type="",
                status_code=None, latency_ms=None, prompt_tokens=0,
                completion_tokens=0, cost_est=0.0):
    """Append one entry per upstream LLM call attempt (success OR failure)."""
    conn = db.get_conn()
    try:
        conn.execute(
            """INSERT INTO ai_call_log
               (session_id, provider, model, ok, error_type, status_code,
                latency_ms, prompt_tokens, completion_tokens, cost_est, created_at)
               VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
            (session_id or "", provider or "", model or "",
             1 if ok else 0, error_type or "", status_code,
             int(latency_ms) if latency_ms is not None else None,
             int(prompt_tokens or 0), int(completion_tokens or 0),
             round(float(cost_est or 0), 6),
             datetime.now().isoformat(timespec="seconds")),
        )
        conn.commit()
    finally:
        conn.close()


def recent_ai_call_log(limit=30):
    conn = db.get_conn()
    try:
        rows = conn.execute(
            "SELECT * FROM ai_call_log ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def ai_cost_summary():
    """Aggregated usage by provider for the settings page."""
    conn = db.get_conn()
    try:
        rows = conn.execute(
            """SELECT provider, COUNT(*) calls,
                      SUM(prompt_tokens) prompt_tokens,
                      SUM(completion_tokens) completion_tokens,
                      SUM(cost_est) cost_est
               FROM ai_call_log WHERE ok=1
               GROUP BY provider ORDER BY cost_est DESC"""
        ).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            d["cost_est"] = round(d.get("cost_est") or 0, 6)
            out.append(d)
        return out
    finally:
        conn.close()
