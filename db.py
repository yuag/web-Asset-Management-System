"""SQLite database layer: schema, connection, config table, changelog.

Performance features:
- WAL journal mode + busy_timeout for concurrent reads/writes
- Targeted indexes on hot filter / sort columns
- FTS5 full-text index (assets_fts) with sync triggers; falls back to LIKE
  when the SQLite build has no FTS5 support

Robustness features:
- retry_on_busy(): exponential backoff wrapper for writers racing the
  single SQLite writer (nuclei flushes, parallel scans, imports)
- additive ALTER TABLE migrations (_migrate) so older databases upgrade
  in place when init_db() runs
"""
import os
import random
import sqlite3
import time

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "assets.db")

SCHEMA = """
CREATE TABLE IF NOT EXISTS assets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    domain TEXT NOT NULL UNIQUE,
    url TEXT,
    ip TEXT,
    port TEXT,
    title TEXT,
    country TEXT DEFAULT '',
    country_code TEXT DEFAULT '',
    cms TEXT DEFAULT '',
    server TEXT DEFAULT '',
    waf TEXT DEFAULT '',
    owner TEXT DEFAULT '',
    remark TEXT DEFAULT '',
    expiration_date TEXT DEFAULT '',
    status_code INTEGER,
    source TEXT DEFAULT 'manual',
    root_domain TEXT DEFAULT '',
    service TEXT DEFAULT '{}',
    ports_scanned_at TEXT DEFAULT '',
    created_at TEXT,
    updated_at TEXT
);

CREATE TABLE IF NOT EXISTS tags (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE
);

CREATE TABLE IF NOT EXISTS asset_tags (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    asset_id INTEGER NOT NULL,
    tag_id INTEGER NOT NULL,
    FOREIGN KEY (asset_id) REFERENCES assets(id) ON DELETE CASCADE,
    FOREIGN KEY (tag_id) REFERENCES tags(id) ON DELETE CASCADE,
    UNIQUE(asset_id, tag_id)
);

CREATE TABLE IF NOT EXISTS asset_changelog (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    asset_id INTEGER,
    domain TEXT,
    changed_fields TEXT,
    old_value TEXT,
    new_value TEXT,
    change_type TEXT,
    created_at TEXT
);

CREATE TABLE IF NOT EXISTS config (
    key TEXT PRIMARY KEY,
    value TEXT
);

-- Dictionary options: countries / CMS types / sources (user-extensible)
CREATE TABLE IF NOT EXISTS dict_options (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    dtype TEXT NOT NULL,
    value TEXT NOT NULL,
    UNIQUE(dtype, value)
);

-- AI assistant: chat sessions (model = provider:model for the NEXT turn;
-- '' means the global default provider/model)
CREATE TABLE IF NOT EXISTS chat_sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id TEXT NOT NULL UNIQUE,
    title TEXT DEFAULT '新对话',
    model TEXT DEFAULT '',
    created_at TEXT,
    updated_at TEXT
);

-- AI assistant: message history (user / assistant / tool roles)
-- `model` records which provider:model produced a message ('' = unknown /
-- legacy rows); `usage_json` captures token usage + estimated cost.
CREATE TABLE IF NOT EXISTS chat_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id TEXT NOT NULL,
    role TEXT NOT NULL,
    content TEXT DEFAULT '',
    tool_calls TEXT DEFAULT '',
    tool_call_id TEXT DEFAULT '',
    model TEXT DEFAULT '',
    usage_json TEXT DEFAULT '',
    created_at TEXT
);

-- AI assistant: audit log of every tool invocation
CREATE TABLE IF NOT EXISTS ai_tool_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id TEXT,
    tool TEXT DEFAULT '',
    arguments TEXT DEFAULT '',
    result TEXT DEFAULT '',
    status TEXT DEFAULT 'ok',
    created_at TEXT
);

-- Multi-model AI: one row per provider/endpoint (DeepSeek, OpenAI GPT,
-- Anthropic Claude, Google Gemini, Qwen, Kimi, GLM, Groq, Mistral, Grok,
-- OpenRouter, local Ollama, ...). A row holds the credentials + the default
-- base URL and `models` (JSON list of selectable model ids). `enabled` gates
-- visibility in the chat model picker; exactly one row may be `is_default`
-- (used for brand-new conversations).
CREATE TABLE IF NOT EXISTS ai_providers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    provider_type TEXT DEFAULT 'openai_compat',  -- openai_compat | anthropic
    display_name TEXT DEFAULT '',
    api_key TEXT DEFAULT '',
    base_url TEXT DEFAULT '',
    model TEXT DEFAULT '',           -- default model id for this provider
    models TEXT DEFAULT '',          -- JSON array of selectable model ids
    temperature TEXT DEFAULT '',     -- per-provider default ('' = 0.3)
    max_tokens TEXT DEFAULT '',      -- per-provider default ('' = 2048)
    context_window INTEGER DEFAULT 0,
    cost_in_per_1m REAL DEFAULT 0,
    cost_out_per_1m REAL DEFAULT 0,
    speed_tier TEXT DEFAULT '',      -- fast | balanced | strong (UI hint)
    note TEXT DEFAULT '',
    enabled INTEGER DEFAULT 0,
    is_default INTEGER DEFAULT 0,
    created_at TEXT,
    updated_at TEXT
);

-- AI assistant: audit log of EVERY upstream LLM call attempt (including
-- failed and fallback attempts) - provider, model, ok/error, latency, tokens.
CREATE TABLE IF NOT EXISTS ai_call_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id TEXT DEFAULT '',
    provider TEXT DEFAULT '',
    model TEXT DEFAULT '',
    ok INTEGER DEFAULT 1,
    error_type TEXT DEFAULT '',
    status_code INTEGER,
    latency_ms INTEGER,
    prompt_tokens INTEGER DEFAULT 0,
    completion_tokens INTEGER DEFAULT 0,
    cost_est REAL DEFAULT 0,
    created_at TEXT
);

-- Nuclei scan findings (JSON results parsed and persisted per asset)
CREATE TABLE IF NOT EXISTS nuclei_results (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    asset_id INTEGER,
    host TEXT DEFAULT '',
    template_id TEXT DEFAULT '',
    template_name TEXT DEFAULT '',
    severity TEXT DEFAULT 'info',
    vuln_type TEXT DEFAULT '',
    description TEXT DEFAULT '',
    matched_at TEXT DEFAULT '',
    extracted_results TEXT DEFAULT '',
    curl_command TEXT DEFAULT '',
    raw_json TEXT DEFAULT '',
    scan_id TEXT DEFAULT '',
    created_at TEXT,
    FOREIGN KEY (asset_id) REFERENCES assets(id) ON DELETE CASCADE
);

-- Long-running fingerprint/identify jobs. The task row IS the checkpoint:
-- `asset_ids` keeps the full ordered id list and `processed` remembers how
-- many were completed, so a crashed run can resume from the tail slice.
CREATE TABLE IF NOT EXISTS fingerprint_tasks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    task_id TEXT NOT NULL UNIQUE,
    status TEXT DEFAULT 'running',
    total INTEGER DEFAULT 0,
    processed INTEGER DEFAULT 0,
    asset_ids TEXT DEFAULT '',
    error TEXT DEFAULT '',
    created_at TEXT,
    updated_at TEXT
);

-- Indexes on hot filter / sort / join columns (IF NOT EXISTS = safe upgrade
-- for existing databases created before this schema).
CREATE INDEX IF NOT EXISTS idx_assets_root_domain ON assets(root_domain);
CREATE INDEX IF NOT EXISTS idx_assets_country ON assets(country);
CREATE INDEX IF NOT EXISTS idx_assets_cms ON assets(cms);
CREATE INDEX IF NOT EXISTS idx_assets_source ON assets(source);
CREATE INDEX IF NOT EXISTS idx_assets_status_code ON assets(status_code);
CREATE INDEX IF NOT EXISTS idx_assets_created_at ON assets(created_at);
CREATE INDEX IF NOT EXISTS idx_assets_updated_at ON assets(updated_at);
CREATE INDEX IF NOT EXISTS idx_asset_tags_asset_id ON asset_tags(asset_id);
CREATE INDEX IF NOT EXISTS idx_asset_tags_tag_id ON asset_tags(tag_id);
CREATE INDEX IF NOT EXISTS idx_asset_changelog_created_at ON asset_changelog(created_at);
CREATE INDEX IF NOT EXISTS idx_asset_changelog_asset_id ON asset_changelog(asset_id);
CREATE INDEX IF NOT EXISTS idx_dict_options_dtype ON dict_options(dtype);
CREATE INDEX IF NOT EXISTS idx_nuclei_results_asset_id ON nuclei_results(asset_id);
CREATE INDEX IF NOT EXISTS idx_nuclei_results_severity ON nuclei_results(severity);
CREATE INDEX IF NOT EXISTS idx_chat_sessions_updated ON chat_sessions(updated_at);
CREATE INDEX IF NOT EXISTS idx_chat_history_session ON chat_history(session_id);
CREATE INDEX IF NOT EXISTS idx_ai_tool_log_created ON ai_tool_log(created_at);
CREATE INDEX IF NOT EXISTS idx_fingerprint_tasks_status ON fingerprint_tasks(status);
-- NOTE: idx_nuclei_results_scan_id is created in _migrate(), NOT here. On
-- databases created before the generation-swap upgrade the scan_id column
-- does not exist yet when SCHEMA runs (it is added right after by ALTER
-- TABLE), so indexing it here would abort init_db before the migration.
CREATE INDEX IF NOT EXISTS idx_ai_providers_enabled ON ai_providers(enabled);
CREATE INDEX IF NOT EXISTS idx_ai_call_log_created ON ai_call_log(created_at);
CREATE INDEX IF NOT EXISTS idx_ai_call_log_session ON ai_call_log(session_id);
"""

# FTS5 full-text index over the searchable asset fields, kept in sync with the
# assets table via triggers. Kept separate from SCHEMA so that builds without
# FTS5 support still get the plain indexes above.
FTS_SCHEMA = """
CREATE VIRTUAL TABLE IF NOT EXISTS assets_fts USING fts5(
    domain, url, ip, title, server, cms, waf, owner, remark, country, root_domain,
    content='assets',
    content_rowid='id',
    tokenize='unicode61'
);

CREATE TRIGGER IF NOT EXISTS assets_fts_ai AFTER INSERT ON assets BEGIN
    INSERT INTO assets_fts(rowid, domain, url, ip, title, server, cms, waf, owner, remark, country, root_domain)
    VALUES (new.id, new.domain, new.url, new.ip, new.title, new.server, new.cms, new.waf, new.owner, new.remark, new.country, new.root_domain);
END;

CREATE TRIGGER IF NOT EXISTS assets_fts_ad AFTER DELETE ON assets BEGIN
    INSERT INTO assets_fts(assets_fts, rowid, domain, url, ip, title, server, cms, waf, owner, remark, country, root_domain)
    VALUES ('delete', old.id, old.domain, old.url, old.ip, old.title, old.server, old.cms, old.waf, old.owner, old.remark, old.country, old.root_domain);
END;

CREATE TRIGGER IF NOT EXISTS assets_fts_au AFTER UPDATE ON assets BEGIN
    INSERT INTO assets_fts(assets_fts, rowid, domain, url, ip, title, server, cms, waf, owner, remark, country, root_domain)
    VALUES ('delete', old.id, old.domain, old.url, old.ip, old.title, old.server, old.cms, old.waf, old.owner, old.remark, old.country, old.root_domain);
    INSERT INTO assets_fts(rowid, domain, url, ip, title, server, cms, waf, owner, remark, country, root_domain)
    VALUES (new.id, new.domain, new.url, new.ip, new.title, new.server, new.cms, new.waf, new.owner, new.remark, new.country, new.root_domain);
END;
"""

# Seed values inserted on first init (INSERT OR IGNORE keeps user edits).
DEFAULT_DICT_OPTIONS = {
    "country": ["中国", "美国", "日本", "德国", "英国", "法国", "加拿大",
                "澳大利亚", "印度", "巴西", "俄罗斯", "韩国", "新加坡", "其他"],
    "cms": ["WordPress", "Drupal", "Joomla", "ThinkPHP", "Laravel", "Spring Boot",
            "Nginx", "Apache", "Tomcat", "IIS", "其他"],
    "source": ["fofa", "crt", "crtname", "manual", "txt_import", "both"],
}


def init_dict_options(conn):
    # Only seed if the table is empty (preserves user deletions)
    count = conn.execute("SELECT COUNT(*) c FROM dict_options").fetchone()[0]
    if count > 0:
        return
    for dtype, values in DEFAULT_DICT_OPTIONS.items():
        for v in values:
            conn.execute(
                "INSERT OR IGNORE INTO dict_options (dtype, value) VALUES (?,?)",
                (dtype, v),
            )


def get_conn():
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    conn.execute("PRAGMA busy_timeout = 5000;")
    conn.execute("PRAGMA synchronous = NORMAL;")
    return conn


def retry_on_busy(fn, *args, attempts=5, base=0.15, max_delay=2.0, **kwargs):
    """Run fn(*args, **kwargs), retrying with exponential backoff + jitter when
    SQLite reports the database is busy/locked.

    SQLite allows a single writer; when several threads write at once (nuclei
    result flushes, the 5-thread scan pool, the 20-thread fingerprint pool,
    bulk imports) a writer can exceed busy_timeout and raise
    "database is locked". Instead of losing the batch, each retry re-runs the
    whole operation. fn MUST therefore open its own connection and commit
    inside, so every attempt is a clean transaction.
    """
    last_error = None
    for i in range(attempts):
        try:
            return fn(*args, **kwargs)
        except sqlite3.OperationalError as e:
            msg = str(e).lower()
            if "locked" not in msg and "busy" not in msg:
                raise
            last_error = e
            delay = min(max_delay, base * (2 ** i))
            time.sleep(delay + random.random() * 0.05)
    raise last_error


def _column_names(conn, table):
    return {r[1] for r in conn.execute(f"PRAGMA table_info({table})")}


def _migrate(conn):
    """Additive migrations for databases created by older schema versions.
    Runs after executescript(SCHEMA); CREATE TABLE IF NOT EXISTS is a no-op
    on existing tables, so column additions must be done via ALTER TABLE."""
    try:
        cols = _column_names(conn, "nuclei_results")
        if "scan_id" not in cols:
            conn.execute("ALTER TABLE nuclei_results ADD COLUMN scan_id TEXT DEFAULT ''")
            # Column-dependent indexes live here (after the ALTER) because
            # SCHEMA runs before this migration and would otherwise fail on
            # databases that still lack the column.
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_nuclei_results_scan_id ON nuclei_results(scan_id)"
        )
    except sqlite3.OperationalError:
        pass  # table missing entirely / locked: next init_db() run retries

    # --- multi-model AI (chat_history.model / usage_json, chat_sessions.model) ---
    try:
        cols = _column_names(conn, "chat_history")
        added_model = "model" not in cols
        if added_model:
            conn.execute("ALTER TABLE chat_history ADD COLUMN model TEXT DEFAULT ''")
        if "usage_json" not in cols:
            conn.execute("ALTER TABLE chat_history ADD COLUMN usage_json TEXT DEFAULT ''")
        # Historical rows predate the multi-model upgrade and only DeepSeek
        # existed, so they are labeled with the model configured at migration
        # time ('' usage = unknown). Backfilled exactly once, right after the
        # column is created.
        if added_model:
            legacy = conn.execute(
                "SELECT value FROM config WHERE key='ai_model'"
            ).fetchone()
            legacy_model = (legacy["value"] if legacy else "") or "deepseek-chat"
            conn.execute(
                "UPDATE chat_history SET model=? WHERE model=''",
                (f"deepseek:{legacy_model}",),
            )
    except sqlite3.OperationalError:
        pass

    # --- lightweight port-service identification (assets.service / ports_scanned_at) ---
    try:
        cols = _column_names(conn, "assets")
        if "service" not in cols:
            conn.execute(
                "ALTER TABLE assets ADD COLUMN service TEXT DEFAULT '{}'"
            )
        if "ports_scanned_at" not in cols:
            conn.execute(
                "ALTER TABLE assets ADD COLUMN ports_scanned_at TEXT DEFAULT ''"
            )
    except sqlite3.OperationalError:
        pass

    try:
        cols = _column_names(conn, "chat_sessions")
        if "model" not in cols:
            conn.execute("ALTER TABLE chat_sessions ADD COLUMN model TEXT DEFAULT ''")
    except sqlite3.OperationalError:
        pass


def _fts_supported():
    """True if this SQLite build ships with FTS5 enabled."""
    try:
        conn = sqlite3.connect(":memory:")
        try:
            conn.execute("CREATE VIRTUAL TABLE _t USING fts5(x)")
            return True
        except sqlite3.OperationalError:
            return False
        finally:
            conn.close()
    except Exception:
        return False


FTS_AVAILABLE = _fts_supported()

_wal_configured = False


def _init_fts(conn):
    """Create the FTS5 table + triggers and backfill any missing rows.
    On failure (no FTS5 support) sets FTS_AVAILABLE = False so callers
    fall back to LIKE search."""
    global FTS_AVAILABLE
    if not FTS_AVAILABLE:
        return
    try:
        conn.executescript(FTS_SCHEMA)
        n_assets = conn.execute("SELECT COUNT(*) FROM assets").fetchone()[0]
        n_fts = conn.execute("SELECT COUNT(*) FROM assets_fts").fetchone()[0]
        if n_fts < n_assets:
            # Incremental backfill: only rows newer than the last indexed one.
            conn.execute(
                """INSERT INTO assets_fts(rowid, domain, url, ip, title, server, cms, waf, owner, remark, country, root_domain)
                   SELECT id, domain, url, ip, title, server, cms, waf, owner, remark, country, root_domain
                   FROM assets
                   WHERE id > (SELECT COALESCE(MAX(rowid), 0) FROM assets_fts)"""
            )
    except sqlite3.OperationalError:
        FTS_AVAILABLE = False


def init_db():
    global _wal_configured
    conn = get_conn()
    try:
        # Switch to WAL before any transaction is opened (journal mode cannot
        # change inside a transaction). Executescript below commits first anyway.
        if not _wal_configured:
            try:
                conn.execute("PRAGMA journal_mode = WAL;")
                _wal_configured = True
            except sqlite3.OperationalError:
                pass
        conn.executescript(SCHEMA)
        _migrate(conn)
        init_dict_options(conn)
        _init_fts(conn)
        conn.commit()
    finally:
        conn.close()


# ---------- config table ----------

def get_all_config():
    conn = get_conn()
    try:
        rows = conn.execute("SELECT key, value FROM config").fetchall()
        return {r["key"]: r["value"] for r in rows}
    finally:
        conn.close()


def get_config(key):
    conn = get_conn()
    try:
        r = conn.execute("SELECT value FROM config WHERE key=?", (key,)).fetchone()
        return r["value"] if r else None
    finally:
        conn.close()


def set_config(key, value):
    conn = get_conn()
    try:
        conn.execute(
            "INSERT INTO config (key, value) VALUES (?,?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (key, str(value)),
        )
        conn.commit()
    finally:
        conn.close()
