"""AI assistant: multi-model function-calling chat over the asset database.

Flow (one user turn):
1. user message is persisted to chat_history (tagged with the chosen model)
2. loop: rebuild canonical OpenAI-style messages -> call the session's model
   via ai_providers (OpenAI-compatible or Anthropic adapter) with tools
3. tool_calls -> execute (safe tools) or pause for user confirmation (dangerous
   tools like tagging / deletion), append tool results, loop again
4. final assistant answer -> streamed to the client as SSE text deltas
   (typewriter effect)

Every tool invocation is written to ai_tool_log and every upstream LLM call
(including failures and fallbacks) to ai_call_log for audit.
"""
import json
import os
import re
import time
import uuid
import threading

import models
import scanner
import nvd
import ai_providers

from ai_providers import AIError

MAX_ITERATIONS = 8
AI_TIMEOUT = 180
AI_TEXT_CHUNK = 12        # chars per SSE text delta
AI_TEXT_SLEEP = 0.01      # seconds between deltas (light typewriter pacing)

SYSTEM_PROMPT = """你是一个运行在「Web 资产管理系统」中的 AI 助手，帮助用户查询、扫描和管理网络资产。

可用工具：
- query_assets：查询资产库（按域名/IP/CMS/国家/标签/来源筛选）
- scan_domain：对根域执行子域名发现（crt.sh + crt.name + FOFA），会写入资产库
- get_dashboard_stats：查看仪表盘统计（总数、今日新增、分布等）
- get_cve_info：查询 CVE 漏洞信息（NVD 数据源）
- export_assets_report：导出资产报告 CSV，返回下载链接
- apply_asset_tags：批量给资产添加标签（会修改数据，系统会自动向用户二次确认）
- delete_assets：批量删除资产（不可恢复，系统会自动向用户二次确认）

规则：
1. 涉及“删除 / 修改 / 打标签 / 批量操作”时直接调用对应工具即可，系统会自动向用户确认；不要在确认前假设已执行。
2. 一次只调用一个工具，等待结果返回后再决定下一步。
3. 查询类问题必须先用工具取得真实数据，再整理成简洁的中文回答（尽量用表格展示）。
4. 扫描域名时调用 scan_domain 并汇报发现的子域名数量和新增数量。
5. 不确定用户意图时先调用 query_assets 试探，或请用户补充筛选条件。
6. 始终使用中文回答。"""

# ---------------- tool implementations ----------------

def _cell(v):
    """Sanitize a table cell (escape pipes / newlines)."""
    s = str(v) if v is not None and v != "" else "-"
    return s.replace("|", "\\|").replace("\n", " ")


def _dist(d, top=8):
    items = list((d or {}).items())[:top]
    return "\n".join(f"- {k}：{v}" for k, v in items) or "- 暂无数据"


def _filters_from(args):
    """Extract a filter dict from tool args (accepts a 'filters' key or flat keys)."""
    f = args.get("filters") if isinstance(args.get("filters"), dict) else {}
    flat = {k: args.get(k) for k in ("search", "country", "cms", "tag", "source")
            if args.get(k)}
    f.update(flat)
    clean = {}
    for k, v in f.items():
        if k in ("search", "country", "cms", "tag", "source"):
            v = str(v).strip()
            if v:
                clean[k] = v
    return clean


def _tool_query_assets(args):
    limit = min(int(args.get("limit") or 20), 50)
    filters = _filters_from(args)
    assets, total = models.list_assets(filters, page=1, per_page=limit)
    if not assets:
        return {"ok": True, "text": "没有找到符合条件的资产。", "summary": "0 条", "total": 0}
    lines = ["| 域名 | IP | 端口 | CMS | 国家 | 标签 | 状态码 |",
             "|---|---|---|---|---|---|---|"]
    for a in assets:
        lines.append("| {} | {} | {} | {} | {} | {} | {} |".format(
            _cell(a.get("domain")), _cell(a.get("ip")), _cell(a.get("port")),
            _cell(a.get("cms")), _cell(a.get("country")),
            _cell(",".join(a.get("tags") or [])),
            _cell(a.get("status_code") if a.get("status_code") is not None else "")))
    text = f"共找到 {total} 条匹配资产，以下为前 {len(assets)} 条：\n\n" + "\n".join(lines)
    if total > len(assets):
        text += f"\n\n（还有 {total - len(assets)} 条未列出，可缩小筛选范围）"
    return {"ok": True, "text": text, "summary": f"{len(assets)}/{total} 条", "total": total}


def _tool_scan_domain(args):
    domain = (args.get("domain") or "").strip().lower().lstrip("*.")
    if not domain:
        return {"ok": False, "text": "缺少要扫描的根域（domain 参数为空）。"}
    tags = args.get("tags")
    if isinstance(tags, list):
        tags = ",".join(str(t) for t in tags if str(t).strip())
    summary, discovered = scanner.scan_root_domain(domain, tags=tags, auto_fingerprint=False)
    if isinstance(summary, dict) and summary.get("error"):
        return {"ok": False, "text": f"扫描失败：{summary['error']}"}
    lines = [f"对根域 {domain} 的扫描完成：", "",
             f"- crt.sh {summary.get('crtsh_count', 0)} 条，crt.name {summary.get('crtname_count', 0)} 条，FOFA {summary.get('fofa_count', 0)} 条",
             f"- 本次新增 {summary.get('new_count', 0)} 条，其余为更新/无变化"]
    if summary.get("tags"):
        lines.append(f"- 附加标签：{', '.join(summary['tags'])}")
    if summary.get("errors"):
        lines.append(f"- 部分数据源出错：{'；'.join(summary['errors'])}")
    lines += ["", "发现的子域名：", "| 域名 | IP | 端口 | CMS |", "|---|---|---|---|"]
    for d in discovered[:40]:
        lines.append(f"| {_cell(d.get('domain'))} | {_cell(d.get('ip'))} | "
                     f"{_cell(d.get('port'))} | {_cell(d.get('cms'))} |")
    if len(discovered) > 40:
        lines.append(f"\n（共 {len(discovered)} 条，仅列出前 40 条）")
    return {"ok": True, "text": "\n".join(lines),
            "summary": f"新增 {summary.get('new_count', 0)} / 共 {len(discovered)} 条"}


def _tool_get_dashboard_stats(args):
    s = models.dashboard_stats()
    text = (
        "当前资产统计：\n\n"
        f"- 总资产数：{s['total']}\n"
        f"- 唯一根域：{s['root_domains']}\n"
        f"- 涉及国家：{s['countries']}\n"
        f"- CMS 类型数：{s['cms_types']}\n"
        f"- 今日新增：{s['today_new']}\n"
        f"- 今日变更：新增 {s['today_added']} / 更新 {s['today_changed']} / 消失 {s['today_disappeared']}\n\n"
        "国家分布 Top10：\n" + _dist(s.get("country_dist")) +
        "\n\nCMS 分布 Top10：\n" + _dist(s.get("cms_dist"))
    )
    return {"ok": True, "text": text,
            "summary": f"总资产 {s['total']}，今日新增 {s['today_new']}"}


def _tool_get_cve_info(args):
    target = (args.get("keyword") or args.get("domain") or "").strip()
    if not target:
        return {"ok": False, "text": "缺少查询关键词（keyword / domain 参数为空）。"}
    asset = models.get_asset_by_domain(target)
    server = cms = ""
    if asset:
        server = asset.get("server") or ""
        cms = asset.get("cms") or ""
        if not server and not cms:
            return {"ok": False,
                    "text": f"资产 {target} 尚未完善指纹信息（server / cms 为空），无法查询 CVE。"
                            "请先用指纹识别或手动补充指纹后再查询。"}
    else:
        server = target
    cves, keywords = nvd.lookup_cves(server, cms)
    if not cves:
        return {"ok": True,
                "text": f"未查询到与「{'、'.join(keywords) or target}」相关的 CVE 记录（数据源：NVD）。"}
    lines = [f"查询关键词：{'、'.join(keywords)}", "",
             "| CVE ID | CVSS 评分 | 发布时间 | 描述 |", "|---|---|---|---|"]
    for c in cves[:15]:
        desc = (c.get("description") or "")[:100]
        lines.append(f"| {_cell(c['id'])} | {_cell(c.get('cvss'))} | "
                     f"{_cell(c.get('published'))} | {_cell(desc)} |")
    if len(cves) > 15:
        lines.append(f"\n（共 {len(cves)} 条，仅列出前 15 条）")
    return {"ok": True, "text": "\n".join(lines), "summary": f"{len(cves)} 条 CVE"}


def _tool_export_assets_report(args):
    filters = _filters_from(args)
    filename, csv_text = models.export_csv(filters, max_rows=10000)
    reports_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "reports")
    os.makedirs(reports_dir, exist_ok=True)
    with open(os.path.join(reports_dir, filename), "w", encoding="utf-8-sig", newline="") as f:
        f.write(csv_text)
    rows = csv_text.count("\n") - 1
    url = "/reports/" + filename
    return {"ok": True,
            "text": f"资产报告已生成：共 {rows} 条记录。\n下载地址：{url}",
            "summary": f"{rows} 条", "url": url}


# ---------------- dangerous tools (require user confirmation) ----------------

def _resolve_assets_for_args(args):
    """Resolve asset dicts from a domains list or from filters (capped)."""
    domains = args.get("domains") or []
    if isinstance(domains, str):
        domains = [d.strip() for d in re.split(r"[,，、\s]+", domains) if d.strip()]
    if domains:
        out = []
        for d in domains:
            a = models.get_asset_by_domain(d)
            if a:
                out.append(a)
        return out
    filters = _filters_from(args)
    assets = []
    for shard in models.iter_asset_shards(filters, shard_size=1000, max_shards=10):
        assets.extend(shard)
        if len(assets) >= 3000:
            break
    return assets


def _split_tags(tags):
    if isinstance(tags, str):
        return [t.strip() for t in re.split(r"[,，、]", tags) if t.strip()]
    return [str(t).strip() for t in (tags or []) if str(t).strip()]


def _preview_apply_asset_tags(args):
    """Return (normalized_args, preview_text). Empty result cancels the op."""
    assets = _resolve_assets_for_args(args)
    tags = _split_tags(args.get("tags"))
    if not tags:
        return None, "缺少要添加的标签（tags 参数为空），操作已取消。"
    if not assets:
        return None, "没有匹配到任何资产，操作已取消。"
    preview = (f"将为 {len(assets)} 个资产添加标签「{'、'.join(tags)}」：\n"
               + "\n".join("· " + a["domain"] for a in assets[:10]))
    if len(assets) > 10:
        preview += f"\n…等共 {len(assets)} 个"
    return {"domains": [a["domain"] for a in assets], "tags": tags}, preview


def _execute_apply_asset_tags(args):
    domains = args.get("domains") or []
    tags = args.get("tags") or []
    done = 0
    for d in domains:
        if not models.get_asset_by_domain(d):
            continue
        models.upsert_asset({"domain": d, "tags": tags})  # merges with existing tags
        done += 1
    return {"ok": True,
            "text": f"已为 {done} 个资产添加标签「{'、'.join(tags)}」。",
            "summary": f"{done} 个资产已更新"}


def _preview_delete_assets(args):
    assets = _resolve_assets_for_args(args)
    if not assets:
        return None, "没有匹配到任何资产，操作已取消。"
    preview = (f"将删除 {len(assets)} 个资产（删除后不可恢复）：\n"
               + "\n".join("· " + a["domain"] for a in assets[:10]))
    if len(assets) > 10:
        preview += f"\n…等共 {len(assets)} 个"
    return {"ids": [a["id"] for a in assets]}, preview


def _execute_delete_assets(args):
    ids = args.get("ids") or []
    models.delete_assets(ids)
    return {"ok": True, "text": f"已删除 {len(ids)} 个资产。", "summary": f"{len(ids)} 个资产已删除"}


DANGEROUS_TOOLS = {
    "apply_asset_tags": {"preview": _preview_apply_asset_tags, "execute": _execute_apply_asset_tags},
    "delete_assets": {"preview": _preview_delete_assets, "execute": _execute_delete_assets},
}

SAFE_TOOLS = {
    "query_assets": _tool_query_assets,
    "scan_domain": _tool_scan_domain,
    "get_dashboard_stats": _tool_get_dashboard_stats,
    "get_cve_info": _tool_get_cve_info,
    "export_assets_report": _tool_export_assets_report,
}


def _fn(name, desc, props, required=()):
    return {"type": "function",
            "function": {"name": name, "description": desc,
                         "parameters": {"type": "object", "properties": props,
                                        "required": list(required)}}}


TOOLS = [
    _fn("query_assets", "查询资产库中的资产。支持按域名/IP 关键词、CMS、国家/地区、标签、来源筛选，返回匹配资产的表格与总数。",
        {"search": {"type": "string", "description": "全文关键词（域名、IP、标题、Server、CMS 等）"},
         "country": {"type": "string", "description": "国家/地区，如 中国、美国"},
         "cms": {"type": "string", "description": "CMS/中间件类型，如 WordPress、Nginx、Tomcat"},
         "tag": {"type": "string", "description": "标签，如 核心资产、已失效"},
         "source": {"type": "string", "description": "来源，如 crt、fofa、manual、txt_import"},
         "limit": {"type": "integer", "description": "最多返回条数（默认 20，最大 50）"}}),
    _fn("scan_domain", "对根域执行子域名发现扫描（crt.sh + crt.name + FOFA），结果会写入资产库。",
        {"domain": {"type": "string", "description": "要扫描的根域，如 example.com"},
         "tags": {"type": "array", "items": {"type": "string"},
                  "description": "附加到发现资产的标签，可选"}},
        required=["domain"]),
    _fn("get_dashboard_stats", "查看仪表盘统计：总资产数、唯一根域、涉及国家、CMS 类型数、今日新增、今日变更、国家/CMS 分布。",
        {}),
    _fn("get_cve_info", "查询 CVE 漏洞信息（NVD 数据源）。传入资产域名会自动使用其指纹（server/cms），也可直接传软件名关键词如 nginx、wordpress。",
        {"keyword": {"type": "string", "description": "资产域名或软件关键词"},
         "domain": {"type": "string", "description": "资产域名（与 keyword 二选一）"}}),
    _fn("export_assets_report", "将资产导出为 CSV 报告文件，返回下载链接。可通过筛选条件限定范围。",
        {"search": {"type": "string"}, "country": {"type": "string"},
         "cms": {"type": "string"}, "tag": {"type": "string"},
         "source": {"type": "string"}}),
    _fn("apply_asset_tags", "给匹配的资产批量添加标签（会修改资产数据，系统将先向用户二次确认）。domains 传域名列表，或用 filters / search / country / cms / tag 指定筛选范围。",
        {"domains": {"type": "array", "items": {"type": "string"}, "description": "资产域名列表"},
         "filters": {"type": "object", "description": "筛选条件 {search, country, cms, tag, source}"},
         "tags": {"type": "array", "items": {"type": "string"}, "description": "要添加的标签列表"},
         "search": {"type": "string"}, "country": {"type": "string"},
         "cms": {"type": "string"}, "tag": {"type": "string"}},
        required=["tags"]),
    _fn("delete_assets", "批量删除资产（不可恢复，系统将先向用户二次确认）。domains 传域名列表，或用 filters / search / country / cms / tag 指定筛选范围。",
        {"domains": {"type": "array", "items": {"type": "string"}, "description": "资产域名列表"},
         "filters": {"type": "object", "description": "筛选条件 {search, country, cms, tag, source}"},
         "search": {"type": "string"}, "country": {"type": "string"},
         "cms": {"type": "string"}, "tag": {"type": "string"}}),
]


# ---------------- provider client (multi-model) ----------------
# The session resolves to one canonical 'provider:model' key (stored on the
# session and on every message) and ai_providers.call_model() does the actual
# HTTP call against the matching adapter (OpenAI-compatible or Anthropic),
# including the optional automatic fallback and the ai_call_log audit trail.


def _provider_call(model_key, session_id, messages):
    """One audited upstream call. Returns (reply, used_model_key)."""
    return ai_providers.call_model(model_key, messages, tools=TOOLS,
                                   session_id=session_id, timeout=AI_TIMEOUT)


def _resolve_model_key(session_id):
    """Canonical 'provider:model' key for a session ('' if not resolvable)."""
    try:
        _row, _mid, key = ai_providers.resolve(session_id)
        return key
    except AIError:
        return ""


# ---------------- message history helpers ----------------

def load_openai_messages(session_id, max_messages=40):
    """Rebuild OpenAI-format messages from DB history.

    Also sanitizes dangling tool_calls (e.g. a confirmation was abandoned or
    the server restarted) so the history always stays valid for the API.
    """
    raw = models.get_chat_messages(session_id)
    msgs = []
    for m in raw:
        if m["role"] == "user":
            msgs.append({"role": "user", "content": m["content"] or ""})
        elif m["role"] == "assistant":
            entry = {"role": "assistant"}
            if m.get("tool_calls"):
                entry["tool_calls"] = m["tool_calls"]
                if m.get("content"):
                    entry["content"] = m["content"]
            else:
                entry["content"] = m["content"] or ""
            msgs.append(entry)
        elif m["role"] == "tool":
            msgs.append({"role": "tool", "tool_call_id": m.get("tool_call_id") or "",
                         "content": m.get("content") or ""})

    out = []
    pending_ids = set()
    for m in msgs:
        if m["role"] == "assistant" and m.get("tool_calls"):
            out.append(m)
            pending_ids = {tc["id"] for tc in m["tool_calls"]}
            continue
        if m["role"] == "tool" and m.get("tool_call_id") in pending_ids:
            out.append(m)
            pending_ids.discard(m["tool_call_id"])
            continue
        if pending_ids:
            for tid in pending_ids:
                out.append({"role": "tool", "tool_call_id": tid,
                            "content": "（该工具调用未执行或被取消）"})
            pending_ids = set()
        out.append(m)
    for tid in pending_ids:
        out.append({"role": "tool", "tool_call_id": tid,
                    "content": "（该工具调用未执行或被取消）"})
    if len(out) > max_messages:
        out = out[-max_messages:]
    return out


def session_exists(session_id):
    return models.get_chat_session(session_id) is not None


# ---------------- confirmation registry ----------------

pending_confirms = {}          # session_id -> {confirm_id, tool, args, remaining, tc_id}
_pending_lock = threading.Lock()


def _clear_pending(session_id):
    with _pending_lock:
        pending_confirms.pop(session_id, None)


# ---------------- the chat loop ----------------

def _run_safe_tool(name, args):
    fn = SAFE_TOOLS.get(name)
    if not fn:
        return {"ok": False, "text": f"未知工具：{name}"}
    try:
        return fn(args)
    except Exception as e:
        return {"ok": False, "text": f"工具 {name} 执行出错：{e}"}


def _stream_text(text):
    """Yield SSE text_delta events for the typewriter effect (line-aware)."""
    lines = text.split("\n")
    for idx, line in enumerate(lines):
        if not line:
            if idx < len(lines) - 1:
                yield {"type": "text_delta", "delta": "\n"}
            continue
        for i in range(0, len(line), AI_TEXT_CHUNK):
            yield {"type": "text_delta", "delta": line[i:i + AI_TEXT_CHUNK]}
        if idx < len(lines) - 1:
            yield {"type": "text_delta", "delta": "\n"}
        time.sleep(AI_TEXT_SLEEP)


def _run_loop(session_id, model_key=None):
    """Iterative provider <-> tool round-trips until the model replies in text.
    `model_key` is the canonical 'provider:model' resolved at turn start; if
    empty it is resolved from the session on the first iteration."""
    for iteration in range(MAX_ITERATIONS):
        if not model_key:
            model_key = _resolve_model_key(session_id)
            if not model_key:
                try:
                    ai_providers.resolve(session_id)
                except AIError as e:
                    models.add_chat_message(session_id, "assistant", f"⚠️ {e}",
                                            model="")
                    yield {"type": "error", "message": str(e)}
                    return
        messages = load_openai_messages(session_id)
        full = [{"role": "system", "content": SYSTEM_PROMPT}] + messages
        yield {"type": "thinking",
               "note": "正在分析你的问题…" if iteration == 0 else f"正在继续处理（第 {iteration + 1} 轮）…"}
        try:
            reply, model_key = _provider_call(model_key, session_id, full)
        except AIError as e:
            models.add_chat_message(session_id, "assistant", f"⚠️ {e}",
                                    model=model_key)
            yield {"type": "error", "message": str(e)}
            return

        usage = reply.usage
        tool_calls = reply.tool_calls or []
        content = reply.content or ""
        if tool_calls:
            models.add_chat_message(session_id, "assistant", content,
                                    tool_calls=tool_calls, model=model_key,
                                    usage=usage)
            for idx_tc, tc in enumerate(tool_calls):
                name = (tc.get("function") or {}).get("name", "")
                try:
                    args = json.loads((tc.get("function") or {}).get("arguments") or "{}")
                    if not isinstance(args, dict):
                        args = {}
                except ValueError:
                    args = {}
                if name in DANGEROUS_TOOLS:
                    norm_args, preview = DANGEROUS_TOOLS[name]["preview"](args)
                    confirm_id = uuid.uuid4().hex
                    with _pending_lock:
                        pending_confirms[session_id] = {
                            "confirm_id": confirm_id,
                            "tool": name,
                            "args": norm_args or {},
                            "tc_id": tc.get("id", ""),
                            "remaining": tool_calls[idx_tc + 1:],
                        }
                    models.log_ai_tool(session_id, name, args, preview,
                                       status="awaiting_confirmation")
                    yield {"type": "needs_confirmation", "confirm_id": confirm_id,
                           "tool": name, "preview": preview or "无匹配数据，操作已取消。"}
                    return
                yield {"type": "tool_start", "tool": name,
                       "summary": "正在调用「%s」…" % name}
                result = _run_safe_tool(name, args)
                models.log_ai_tool(session_id, name, args, result["text"],
                                   "ok" if result["ok"] else "error")
                models.add_chat_message(session_id, "tool", result["text"],
                                        tool_call_id=tc.get("id", ""))
                yield {"type": "tool_result", "tool": name,
                       "summary": result.get("summary") or result["text"][:80],
                       "ok": result["ok"]}
            continue

        # final text answer
        models.add_chat_message(session_id, "assistant", content, model=model_key,
                                usage=usage)
        if content:
            yield from _stream_text(content)
        yield {"type": "done"}
        return

    models.add_chat_message(session_id, "assistant",
                            "抱歉，本轮对话处理步骤过多，已停止。请简化问题后重试。",
                            model=model_key)
    yield {"type": "done"}


def _chat_events_unlocked(session_id, first_user_message=None):
    """SSE event generator for one user turn (caller holds the session lock)."""
    model_key = ""
    if first_user_message:
        model_key = _resolve_model_key(session_id)
        models.add_chat_message(session_id, "user", first_user_message, model=model_key)
        sess = models.get_chat_session(session_id)
        if sess and (sess.get("title") or "") == "新对话":
            models.update_chat_session_title(session_id, first_user_message[:20])
        _clear_pending(session_id)
        models.touch_chat_session(session_id)
    yield from _run_loop(session_id, model_key)


# ---------------------------------------------------------------------------
# Per-session turn serialization
# ---------------------------------------------------------------------------
# The public entry points (chat_events / resume_after_confirm) serialize all
# work for ONE session through a per-session lock, so two concurrent requests
# (double-Enter, two tabs, or a chat racing a confirm) can no longer interleave
# history writes or run the same tool twice on overlapping message state.
# Locks are keyed by session and created on demand.

_session_turn_locks = {}
_session_locks_guard = threading.Lock()
# How long a queued turn waits behind the active one before telling the user
# the session is busy (protects request threads from piling up forever).
_SESSION_TURN_WAIT = 180


def _session_turn_lock(session_id):
    with _session_locks_guard:
        lock = _session_turn_locks.setdefault(session_id, threading.Lock())
    return lock


def _locked_stream(session_id, gen_fn):
    """Return a generator that runs gen_fn(session_id, ...) while holding the
    per-session lock. The lock is released when the stream finishes OR when the
    client disconnects mid-stream (GeneratorExit -> finally)."""
    def _run(*args, **kwargs):
        lock = _session_turn_lock(session_id)
        if not lock.acquire(timeout=_SESSION_TURN_WAIT):
            yield {"type": "error", "message": "该会话正在处理上一条消息，请稍候再发送。"}
            return
        try:
            yield from gen_fn(session_id, *args, **kwargs)
        finally:
            lock.release()
    return _run


def chat_events(session_id, first_user_message=None):
    """SSE event generator for one user turn (serialized per session)."""
    return _locked_stream(session_id, _chat_events_unlocked)(first_user_message)


def resume_after_confirm(session_id, confirm_id, approve=True):
    """Continue a conversation after the user decides on a dangerous tool
    (serialized per session - a second confirm/chat cannot race this one)."""
    return _locked_stream(session_id, _resume_after_confirm_unlocked)(confirm_id, approve)


def _resume_after_confirm_unlocked(session_id, confirm_id, approve=True):
    """Continue a conversation after the user decides on a dangerous tool
    (caller holds the session lock)."""
    with _pending_lock:
        pending = pending_confirms.get(session_id)
        if not pending or pending["confirm_id"] != confirm_id:
            yield {"type": "error", "message": "确认已失效，请重新发送消息。"}
            return
        del pending_confirms[session_id]

    tool = pending["tool"]
    args = pending["args"]
    tc_id = pending.get("tc_id") or ("confirm_" + confirm_id)
    remaining = pending.get("remaining") or []

    if approve:
        yield {"type": "tool_start", "tool": tool, "summary": "正在执行「%s」…" % tool}
        result = DANGEROUS_TOOLS[tool]["execute"](args)
        models.log_ai_tool(session_id, tool, args, result["text"],
                           "ok" if result["ok"] else "error")
        yield {"type": "tool_result", "tool": tool,
               "summary": result.get("summary") or result["text"][:80],
               "ok": result["ok"]}
        models.add_chat_message(session_id, "tool", result["text"], tool_call_id=tc_id)
    else:
        models.log_ai_tool(session_id, tool, args, "用户拒绝执行", "rejected")
        yield {"type": "tool_result", "tool": tool, "summary": "用户拒绝执行", "ok": False}
        models.add_chat_message(session_id, "tool", "用户拒绝执行该操作，已取消。",
                                tool_call_id=tc_id)

    # execute any remaining tool calls of the same assistant message
    for tc in remaining:
        name = (tc.get("function") or {}).get("name", "")
        try:
            cargs = json.loads((tc.get("function") or {}).get("arguments") or "{}")
            if not isinstance(cargs, dict):
                cargs = {}
        except ValueError:
            cargs = {}
        if name in DANGEROUS_TOOLS:
            norm_args, preview = DANGEROUS_TOOLS[name]["preview"](cargs)
            new_cid = uuid.uuid4().hex
            with _pending_lock:
                pending_confirms[session_id] = {
                    "confirm_id": new_cid, "tool": name, "args": norm_args or {},
                    "tc_id": tc.get("id", ""), "remaining": [],
                }
            models.log_ai_tool(session_id, name, cargs, preview,
                               status="awaiting_confirmation")
            yield {"type": "needs_confirmation", "confirm_id": new_cid,
                   "tool": name, "preview": preview or "无匹配数据，操作已取消。"}
            return
        yield {"type": "tool_start", "tool": name, "summary": "正在调用「%s」…" % name}
        result = _run_safe_tool(name, cargs)
        models.log_ai_tool(session_id, name, cargs, result["text"],
                           "ok" if result["ok"] else "error")
        models.add_chat_message(session_id, "tool", result["text"],
                                tool_call_id=tc.get("id", ""))
        yield {"type": "tool_result", "tool": name,
               "summary": result.get("summary") or result["text"][:80],
               "ok": result["ok"]}

    models.touch_chat_session(session_id)
    # continue with whatever model the session now selects (may differ from
    # the one that requested the confirmation - logged per message anyway)
    yield from _run_loop(session_id, _resolve_model_key(session_id))