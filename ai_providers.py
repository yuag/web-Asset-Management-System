"""Multi-model AI providers for the AI assistant.

One canonical, provider-agnostic message format is used everywhere inside the
app (OpenAI-style: system/user/assistant/tool roles, tool calls with JSON-string
`arguments`). Every provider adapter translates to/from its own wire format at
the API boundary only - the DB and the chat loop never see vendor shapes.

Supported adapter types:
- openai_compat : OpenAI, DeepSeek, Gemini (OpenAI-compat endpoint), Qwen,
  Kimi/Moonshot, GLM/Zhipu, Groq, Mistral, Grok/xAI, OpenRouter, SiliconFlow,
  local Ollama, and any custom OpenAI-compatible gateway
- anthropic     : Anthropic Claude native Messages API (/v1/messages)

A model is referenced as a canonical key "provider:model", e.g.
"deepseek:deepseek-chat" or "anthropic:claude-sonnet-4-20250514".
"""
import json
import time

import requests

import config
import models


class AIError(Exception):
    """Provider call failed. `error_type` drives fallback decisions:
    - auth / invalid_request: configuration problem, never auto-fallback
    - timeout / rate_limit / server / context_length / network: transient,
      auto-fallback is allowed when the user enabled it
    """

    def __init__(self, message, error_type="unknown", status_code=None,
                 fallbackable=True):
        super().__init__(message)
        self.message = str(message)
        self.error_type = error_type
        self.status_code = status_code
        self.fallbackable = bool(fallbackable)


# ---------------------------------------------------------------------------
# Builtin provider registry. Seeded once into ai_providers (INSERT OR IGNORE -
# user edits are never overwritten). Prices are rough list prices per 1M
# tokens (USD) used ONLY for the estimated-cost display; edit in settings.
# ---------------------------------------------------------------------------

def _entry(name, ptype, display, base, models, tier="balanced",
           cost_in=0.0, cost_out=0.0, ctx=0, note=""):
    return {
        "name": name, "provider_type": ptype, "display_name": display,
        "base_url": base, "model": models[0], "models": models,
        "speed_tier": tier, "cost_in_per_1m": cost_in,
        "cost_out_per_1m": cost_out, "context_window": ctx, "note": note,
        "enabled": 0, "is_default": 0, "api_key": "",
    }


BUILTIN_PROVIDERS = [
    _entry("deepseek", "openai_compat", "DeepSeek",
           "https://api.deepseek.com", ["deepseek-chat", "deepseek-reasoner"],
           tier="fast", cost_in=0.27, cost_out=1.10, ctx=131072,
           note="深度求索。deepseek-chat 通用对话 / deepseek-reasoner 深度推理"),
    _entry("openai", "openai_compat", "OpenAI GPT",
           "https://api.openai.com/v1",
           ["gpt-4o", "gpt-4o-mini", "gpt-4.1", "o3-mini"],
           tier="strong", cost_in=2.50, cost_out=10.00, ctx=131072,
           note="GPT-4o 系列；o3-mini 为推理模型（参数自动适配）"),
    _entry("anthropic", "anthropic", "Anthropic Claude",
           "https://api.anthropic.com",
           ["claude-sonnet-4-20250514", "claude-3-5-haiku-20241022"],
           tier="strong", cost_in=3.00, cost_out=15.00, ctx=200000,
           note="原生 Messages API。模型 ID 如有更新请在设置中修改"),
    _entry("gemini", "openai_compat", "Google Gemini",
           "https://generativelanguage.googleapis.com/v1beta/openai/",
           ["gemini-2.5-pro", "gemini-2.5-flash"],
           tier="balanced", cost_in=1.25, cost_out=10.00, ctx=1048576,
           note="通过官方 OpenAI 兼容端点接入，API Key 即 Google AI Studio Key"),
    _entry("qwen", "openai_compat", "通义千问 Qwen",
           "https://dashscope.aliyuncs.com/compatible-mode/v1",
           ["qwen-plus", "qwen-max", "qwen-turbo"],
           tier="balanced", ctx=131072,
           note="阿里云百炼 DashScope 兼容端点"),
    _entry("moonshot", "openai_compat", "月之暗面 Kimi",
           "https://api.moonshot.cn/v1",
           ["kimi-k2-0711-preview", "moonshot-v1-32k"],
           tier="strong", ctx=131072,
           note="Kimi K2 支持工具调用与超长上下文"),
    _entry("zhipu", "openai_compat", "智谱 GLM",
           "https://open.bigmodel.cn/api/paas/v4",
           ["glm-4-plus", "glm-4-flash", "glm-4-air"],
           tier="balanced", ctx=131072,
           note="智谱 AI，glm-4-flash 提供免费额度"),
    _entry("groq", "openai_compat", "Groq",
           "https://api.groq.com/openai/v1",
           ["llama-3.3-70b-versatile", "llama-3.1-8b-instant",
            "deepseek-r1-distill-llama-70b"],
           tier="fast", cost_in=0.59, cost_out=0.79, ctx=131072,
           note="极速推理托管（Llama / DeepSeek 蒸馏等开源模型）"),
    _entry("mistral", "openai_compat", "Mistral",
           "https://api.mistral.ai/v1",
           ["mistral-small-latest", "mistral-large-latest"],
           tier="fast", cost_in=0.20, cost_out=0.60, ctx=131072,
           note="Mistral 官方 API"),
    _entry("xai", "openai_compat", "xAI Grok",
           "https://api.x.ai/v1", ["grok-2-latest"],
           tier="balanced", cost_in=2.00, cost_out=10.00, ctx=131072,
           note="xAI Grok API"),
    _entry("openrouter", "openai_compat", "OpenRouter（聚合）",
           "https://openrouter.ai/api/v1",
           ["openai/gpt-4o", "anthropic/claude-sonnet-4-20250514",
            "google/gemini-2.5-pro", "deepseek/deepseek-chat"],
           tier="balanced", ctx=200000,
           note="一个 Key 接入全市场模型（模型 ID 形如 厂商/模型）"),
    _entry("siliconflow", "openai_compat", "硅基流动 SiliconFlow",
           "https://api.siliconflow.cn/v1",
           ["Qwen/Qwen2.5-72B-Instruct", "deepseek-ai/DeepSeek-V3"],
           tier="fast", ctx=131072,
           note="国内开源模型托管，多数模型免费用（登录即送额度）"),
    _entry("ollama", "openai_compat", "Ollama（本地）",
           "http://127.0.0.1:11434/v1",
           ["qwen2.5:7b-instruct", "llama3.1:8b"],
           tier="fast", ctx=32768,
           note="本地模型，无需 API Key，需先在本机运行 ollama serve"),
]

_seed_lock = __import__("threading").Lock()
_seeded = False


def ensure_seeded():
    """Seed builtin providers (never overwrites user edits) and adopt the
    legacy flat DeepSeek config keys exactly once."""
    global _seeded
    if _seeded:
        return
    with _seed_lock:
        if _seeded:
            return
        now = time.strftime("%Y-%m-%dT%H:%M:%S")
        conn = models.db.get_conn()
        try:
            for b in BUILTIN_PROVIDERS:
                conn.execute(
                    """INSERT OR IGNORE INTO ai_providers
                       (name, provider_type, display_name, api_key, base_url,
                        model, models, cost_in_per_1m, cost_out_per_1m,
                        speed_tier, context_window, note, enabled, is_default,
                        created_at, updated_at)
                       VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (b["name"], b["provider_type"], b["display_name"],
                     b["api_key"], b["base_url"], b["model"],
                     json.dumps(b["models"], ensure_ascii=False),
                     b["cost_in_per_1m"], b["cost_out_per_1m"],
                     b["speed_tier"], b["context_window"], b["note"],
                     b["enabled"], b["is_default"], now, now),
                )
            # one-time legacy adoption: ai_api_key / ai_base_url / ai_model
            row = conn.execute(
                "SELECT api_key FROM ai_providers WHERE name='deepseek'"
            ).fetchone()
            if row and not (row["api_key"] or "").strip():
                legacy_key = conn.execute(
                    "SELECT value FROM config WHERE key='ai_api_key'"
                ).fetchone()
                if legacy_key and (legacy_key["value"] or "").strip():
                    legacy_base = conn.execute(
                        "SELECT value FROM config WHERE key='ai_base_url'"
                    ).fetchone()
                    legacy_model = conn.execute(
                        "SELECT value FROM config WHERE key='ai_model'"
                    ).fetchone()
                    base = (legacy_base["value"] if legacy_base else "") or \
                        "https://api.deepseek.com"
                    model = (legacy_model["value"] if legacy_model else "") or \
                        "deepseek-chat"
                    conn.execute(
                        """UPDATE ai_providers
                           SET api_key=?, base_url=?, model=?, enabled=1,
                               is_default=1, updated_at=?
                           WHERE name='deepseek'""",
                        (legacy_key["value"].strip(), base, model, now),
                    )
                    conn.execute(
                        "UPDATE ai_providers SET is_default=0 WHERE name<>'deepseek'"
                    )
            conn.commit()
        finally:
            conn.close()
        _seeded = True


# ---------------------------------------------------------------------------
# Key resolution
# ---------------------------------------------------------------------------

def split_model_key(model_key):
    """'provider:model' -> (provider_name, model_id); bad input -> (None, None)."""
    mk = (model_key or "").strip()
    if not mk or ":" not in mk:
        return None, None
    name, model = mk.split(":", 1)
    return name.strip(), model.strip()


def find_default_key():
    """Canonical key of the default enabled provider's default model (''
    when nothing is enabled)."""
    ensure_seeded()
    conn = models.db.get_conn()
    try:
        row = conn.execute(
            """SELECT name, model, models FROM ai_providers
               WHERE enabled=1 ORDER BY is_default DESC, display_name, name
               LIMIT 1"""
        ).fetchone()
        if not row:
            return ""
        name = row["name"]
        model = (row["model"] or "").strip()
        if not model:
            try:
                lst = json.loads(row["models"] or "[]")
            except ValueError:
                lst = []
            model = lst[0] if lst else ""
        return f"{name}:{model}" if model else ""
    finally:
        conn.close()


def resolve(session_id=None):
    """Resolve the provider+model a turn should use.

    Priority: the session's stored model key (if it still exists and is
    enabled) -> the global default provider -> the first enabled provider.
    Returns (provider_row_with_real_key, model_id, model_key).
    Raises AIError when no usable model is configured."""
    ensure_seeded()
    if session_id:
        sess = models.get_chat_session(session_id)
        mk = (sess or {}).get("model") or ""
        pname, pmodel = split_model_key(mk)
        if pname:
            prow = models.get_ai_provider(pname)
            if prow and prow.get("enabled"):
                model = pmodel if pmodel in (prow.get("models_list") or []) \
                    else (prow.get("model") or "")
                if model:
                    return prow, model, f"{pname}:{model}"
    for prow in models.list_ai_providers(include_disabled=False):
        full = models.get_ai_provider(prow["name"])
        if not full or not full.get("enabled"):
            continue
        model = (full.get("model") or "").strip()
        if not model:
            lst = full.get("models_list") or []
            model = lst[0] if lst else ""
        if model:
            return full, model, f"{full['name']}:{model}"
    raise AIError(
        "未启用任何可用的 AI 模型。请到「系统设置 → AI 模型配置」中至少为一家"
        "服务商填写 API Key 并勾选启用（例如 DeepSeek、OpenAI、Gemini）。",
        error_type="not_configured", fallbackable=False,
    )


def list_picker_models():
    """Enabled providers + models for the chat model picker + default key."""
    ensure_seeded()
    out = []
    for prow in models.list_ai_providers(include_disabled=False):
        full = models.get_ai_provider(prow["name"])
        lst = (full or {}).get("models_list") or []
        if not lst:
            continue
        out.append({
            "name": prow["name"],
            "provider_type": prow["provider_type"],
            "display_name": prow["display_name"],
            "model": (full or {}).get("model") or lst[0],
            "models": lst,
            "speed_tier": prow.get("speed_tier") or "",
            "context_window": prow.get("context_window") or 0,
            "note": prow.get("note") or "",
        })
    return out, find_default_key()


# ---------------------------------------------------------------------------
# Adapters
# ---------------------------------------------------------------------------

def _classify_error(status_code, body_text):
    body_text = (body_text or "").lower()
    if status_code in (401, 403):
        return "auth", False
    if status_code == 429:
        return "rate_limit", True
    if status_code >= 500:
        return "server", True
    # 400 etc. - context-length overflows are worth falling back from
    for kw in ("context_length", "maximum context", "too many tokens",
               "token limit", "context window"):
        if kw in body_text:
            return "context_length", True
    return "invalid_request", False


def _err_message(prefix, status_code, body_text, provider_name):
    try:
        data = json.loads(body_text or "{}")
        msg = (data.get("error") or {}).get("message") if isinstance(
            data.get("error"), dict) else None
        if not msg and isinstance(data.get("error"), str):
            msg = data["error"]
    except ValueError:
        msg = (body_text or "")[:300]
    detail = msg or body_text[:300] if body_text else "无详细信息"
    return f"{prefix}（HTTP {status_code}，{provider_name}）：{detail}"


class ProviderReply:
    """Normalized response of one LLM call."""
    __slots__ = ("content", "tool_calls", "usage", "model_echo")

    def __init__(self, content=None, tool_calls=None, usage=None, model_echo=""):
        self.content = content          # str or None (tool-only turns)
        self.tool_calls = tool_calls    # canonical OpenAI-shape list or None
        self.usage = usage or {}        # {prompt_tokens, completion_tokens}
        self.model_echo = model_echo or ""


class BaseAIProvider:
    provider_type = ""

    def __init__(self, row):
        self.row = dict(row)
        self.name = self.row.get("name") or ""
        self.api_key = (self.row.get("api_key") or "").strip()
        self.base_url = (self.row.get("base_url") or "").strip().rstrip("/")
        self.model_id = ""
        self.temperature = 0.3
        self.max_tokens = 2048
        self.timeout = 180

    def configure(self, model_id, temperature=None, max_tokens=None, timeout=180):
        self.model_id = model_id or self.row.get("model") or ""
        if temperature is not None:
            self.temperature = float(temperature)
        if max_tokens is not None:
            self.max_tokens = int(max_tokens)
        if timeout is not None:
            self.timeout = float(timeout)
        return self

    def _proxies(self):
        return config.proxy_dict()

    def chat(self, messages, tools=None):
        """Run one non-streaming call. `messages` and `tools` are canonical
        OpenAI-style. Returns ProviderReply or raises AIError."""
        raise NotImplementedError


class OpenAICompatProvider(BaseAIProvider):
    """DeepSeek / OpenAI / Gemini-compat / Qwen / Kimi / GLM / Groq / Mistral /
    Grok / OpenRouter / SiliconFlow / Ollama / any OpenAI-compatible gateway."""

    def chat(self, messages, tools=None):
        payload = {"model": self.model_id, "messages": messages}
        if tools:
            payload["tools"] = tools
        model_id = self.model_id.lower()
        reasoning = model_id.startswith(("o1", "o3", "o4", "gpt-5"))
        if reasoning:
            # OpenAI reasoning models reject temperature/top_p/max_tokens
            payload["max_completion_tokens"] = self.max_tokens
        else:
            payload["temperature"] = max(0.0, min(2.0, self.temperature))
            payload["max_tokens"] = self.max_tokens
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        url = f"{self.base_url}/chat/completions"
        started = time.time()
        try:
            resp = requests.post(url, json=payload, headers=headers,
                                 timeout=self.timeout, proxies=self._proxies())
        except requests.exceptions.Timeout:
            raise AIError(f"AI 请求超时（>{self.timeout}s）：{self.name}",
                          error_type="timeout")
        except requests.exceptions.RequestException as e:
            raise AIError(f"无法连接 AI 服务（{self.name}）：{e}",
                          error_type="network")
        latency = int((time.time() - started) * 1000)
        if resp.status_code != 200:
            etype, _ = _classify_error(resp.status_code, resp.text)
            raise AIError(
                _err_message("AI 服务返回错误", resp.status_code, resp.text, self.name),
                error_type=etype, status_code=resp.status_code,
                fallbackable=etype not in ("auth", "invalid_request"),
            )
        try:
            data = resp.json()
            msg = data["choices"][0].get("message") or {}
        except (KeyError, IndexError, ValueError) as e:
            raise AIError(f"AI 服务响应解析失败（{self.name}）：{e}",
                          error_type="parse", fallbackable=False)
        tool_calls = None
        raw_tcs = msg.get("tool_calls") or []
        if raw_tcs:
            tool_calls = []
            for tc in raw_tcs:
                fn = tc.get("function") or {}
                tool_calls.append({
                    "id": tc.get("id") or "",
                    "type": "function",
                    "function": {"name": fn.get("name") or "",
                                 "arguments": fn.get("arguments") or "{}"},
                })
        usage = data.get("usage") or {}
        return ProviderReply(
            content=msg.get("content"),
            tool_calls=tool_calls,
            usage={"prompt_tokens": usage.get("prompt_tokens") or 0,
                   "completion_tokens": usage.get("completion_tokens") or 0},
            model_echo=data.get("model") or self.model_id,
        )


class AnthropicProvider(BaseAIProvider):
    """Anthropic Claude native Messages API. Canonical OpenAI-style messages
    are translated here; the rest of the app stays vendor-agnostic."""

    # ------------------------------------------------------------------
    # canonical -> Claude wire format
    # ------------------------------------------------------------------
    def _to_tools(self, tools):
        out = []
        for t in tools or []:
            fn = t.get("function") or {}
            out.append({
                "name": fn.get("name") or "",
                "description": fn.get("description") or "",
                "input_schema": (fn.get("parameters") or
                                 {"type": "object", "properties": {}}),
            })
        return [t for t in out if t["name"]]

    def _to_messages(self, messages):
        """Returns ([claude_messages], system_text).

        Claude rules enforced here: system prompt is a top-level field; roles
        strictly alternate user/assistant; the first message must be user;
        tool results are user-message content blocks paired with tool_use ids.
        """
        system_parts = []
        cm = []          # list of dicts {role, content}
        for m in messages or []:
            role = m.get("role")
            if role == "system":
                system_parts.append(m.get("content") or "")
                continue
            if role == "user":
                text = m.get("content") or ""
                if text.strip():
                    cm.append({"role": "user", "content": text})
                continue
            if role == "assistant":
                blocks = []
                if (m.get("content") or "").strip():
                    blocks.append({"type": "text", "text": m["content"]})
                for tc in m.get("tool_calls") or []:
                    fn = tc.get("function") or {}
                    try:
                        inp = json.loads(fn.get("arguments") or "{}")
                    except ValueError:
                        inp = {}
                    blocks.append({"type": "tool_use",
                                   "id": tc.get("id") or "",
                                   "name": fn.get("name") or "",
                                   "input": inp})
                if blocks:
                    cm.append({"role": "assistant", "content": blocks})
                continue
            if role == "tool":
                # tool_result must live in a user message right after the
                # assistant tool_use message
                block = {"type": "tool_result",
                         "tool_use_id": m.get("tool_call_id") or "",
                         "content": m.get("content") or ""}
                if cm and cm[-1]["role"] == "user":
                    prev = cm[-1]["content"]
                    if isinstance(prev, str):
                        cm[-1]["content"] = [{"type": "text", "text": prev}, block]
                    else:
                        prev.append(block)
                else:
                    cm.append({"role": "user", "content": [block]})

        # merge consecutive same-role messages (OpenAI allows, Claude does not)
        merged = []
        for m in cm:
            if merged and merged[-1]["role"] == m["role"]:
                a, b = merged[-1]["content"], m["content"]
                if isinstance(a, str) and isinstance(b, str):
                    merged[-1]["content"] = a + "\n\n" + b
                elif isinstance(a, str):
                    merged[-1]["content"] = [{"type": "text", "text": a}] + b
                elif isinstance(b, str):
                    merged[-1]["content"] = a + [{"type": "text", "text": b}]
                else:
                    merged[-1]["content"] = a + b
            else:
                merged.append(m)
        # Claude requires the conversation to open with a user turn
        if merged and merged[0]["role"] != "user":
            merged.insert(0, {"role": "user", "content": "请继续。"})
        return merged, "\n\n".join(p for p in system_parts if p)

    def chat(self, messages, tools=None):
        claude_msgs, system_text = self._to_messages(messages)
        payload = {
            "model": self.model_id,
            "max_tokens": self.max_tokens,          # required by Claude
            "messages": claude_msgs,
            "temperature": max(0.0, min(1.0, self.temperature)),
        }
        if system_text:
            payload["system"] = system_text
        if tools:
            payload["tools"] = self._to_tools(tools)
        headers = {
            "Content-Type": "application/json",
            "x-api-key": self.api_key,
            "anthropic-version": "2023-06-01",
        }
        url = f"{self.base_url}/v1/messages"
        started = time.time()
        try:
            resp = requests.post(url, json=payload, headers=headers,
                                 timeout=self.timeout, proxies=self._proxies())
        except requests.exceptions.Timeout:
            raise AIError(f"AI 请求超时（>{self.timeout}s）：{self.name}",
                          error_type="timeout")
        except requests.exceptions.RequestException as e:
            raise AIError(f"无法连接 AI 服务（{self.name}）：{e}",
                          error_type="network")
        latency = int((time.time() - started) * 1000)
        if resp.status_code != 200:
            etype, _ = _classify_error(resp.status_code, resp.text)
            raise AIError(
                _err_message("AI 服务返回错误", resp.status_code, resp.text, self.name),
                error_type=etype, status_code=resp.status_code,
                fallbackable=etype not in ("auth", "invalid_request"),
            )
        try:
            data = resp.json()
        except ValueError as e:
            raise AIError(f"AI 服务响应解析失败（{self.name}）：{e}",
                          error_type="parse", fallbackable=False)
        content_parts = []
        tool_calls = None
        for block in data.get("content") or []:
            if block.get("type") == "text":
                content_parts.append(block.get("text") or "")
            elif block.get("type") == "tool_use":
                if tool_calls is None:
                    tool_calls = []
                tool_calls.append({
                    "id": block.get("id") or "",
                    "type": "function",
                    "function": {
                        "name": block.get("name") or "",
                        "arguments": json.dumps(block.get("input") or {},
                                                ensure_ascii=False),
                    },
                })
        usage = data.get("usage") or {}
        return ProviderReply(
            content="\n".join(p for p in content_parts if p) or None,
            tool_calls=tool_calls,
            usage={"prompt_tokens": usage.get("input_tokens") or 0,
                   "completion_tokens": usage.get("output_tokens") or 0},
            model_echo=data.get("model") or self.model_id,
        )


# ---------------------------------------------------------------------------
# Factory
# ---------------------------------------------------------------------------

def _sval(row, key):
    v = row.get(key)
    return str(v).strip() if v not in (None, "") else ""


def build_provider(row, model_id=None, temperature=None, max_tokens=None,
                   timeout=None):
    """Instantiate the right adapter for a provider row (full/unmasked)."""
    ptype = _sval(row, "provider_type").lower() or "openai_compat"
    if ptype == "anthropic":
        cls = AnthropicProvider
    else:
        cls = OpenAICompatProvider
    inst = cls(row)
    if _sval(row, "temperature") and temperature is None:
        temperature = _sval(row, "temperature")
    if _sval(row, "max_tokens") and max_tokens is None:
        max_tokens = _sval(row, "max_tokens")
    return inst.configure(model_id, temperature=temperature,
                          max_tokens=max_tokens, timeout=timeout)


def call_model(model_key, messages, tools=None, session_id="",
               temperature=None, max_tokens=None, timeout=None):
    """One upstream call for `model_key`, audited in ai_call_log.

    Returns (ProviderReply, used_model_key). Respects the global
    ai_fallback_enabled switch: transient errors (timeout/429/5xx/context)
    retry once on the first other enabled provider, and the fallback choice is
    recorded in the audit log so cost attribution stays honest.
    """
    ensure_seeded()
    provider, model_id, _ = _resolve_row(model_key)
    return _call_once(provider, model_id, model_key, messages, tools, session_id,
                      temperature, max_tokens, timeout)


def _resolve_row(model_key):
    pname, pmodel = split_model_key(model_key)
    row = models.get_ai_provider(pname) if pname else None
    if not row or not row.get("enabled"):
        # fall back to the default/first enabled provider
        row, pmodel, model_key = _default_row()
    return row, pmodel, model_key


def _default_row():
    row, model, mk = None, "", ""
    for prow in models.list_ai_providers(include_disabled=False):
        full = models.get_ai_provider(prow["name"])
        if not full or not full.get("enabled"):
            continue
        model = (full.get("model") or "").strip()
        if not model and (full.get("models_list") or []):
            model = full["models_list"][0]
        if model:
            row, mk = full, f"{full['name']}:{model}"
            break
    if not row:
        raise AIError("未启用任何可用的 AI 模型，请先在系统设置中启用并配置。",
                      error_type="not_configured", fallbackable=False)
    return row, model, mk


def _fallback_key(provider_name):
    for prow in models.list_ai_providers(include_disabled=False):
        if prow["name"] == provider_name:
            continue
        full = models.get_ai_provider(prow["name"])
        if not full or not full.get("enabled"):
            continue
        model = (full.get("model") or "").strip()
        if not model and (full.get("models_list") or []):
            model = full["models_list"][0]
        if model:
            return full, model, f"{full['name']}:{model}"
    return None


def _cost_est(row, usage):
    return ((usage.get("prompt_tokens") or 0) / 1e6 *
            float(row.get("cost_in_per_1m") or 0) +
            (usage.get("completion_tokens") or 0) / 1e6 *
            float(row.get("cost_out_per_1m") or 0))


def _call_once(provider, model_id, model_key, messages, tools, session_id,
               temperature, max_tokens, timeout):
    started = time.time()
    try:
        inst = build_provider(provider, model_id, temperature, max_tokens, timeout)
        reply = inst.chat(messages, tools)
        latency = int((time.time() - started) * 1000)
        models.log_ai_call(session_id=session_id, provider=provider["name"],
                           model=model_id, ok=True, latency_ms=latency,
                           prompt_tokens=reply.usage.get("prompt_tokens"),
                           completion_tokens=reply.usage.get("completion_tokens"),
                           cost_est=_cost_est(provider, reply.usage))
        return reply, model_key
    except AIError as e:
        latency = int((time.time() - started) * 1000)
        models.log_ai_call(session_id=session_id, provider=provider["name"],
                           model=model_id, ok=False, error_type=e.error_type,
                           status_code=e.status_code, latency_ms=latency)
        if e.fallbackable and config.get_bool("ai_fallback_enabled"):
            alt = _fallback_key(provider["name"])
            if alt:
                alt_row, alt_model, alt_key = alt
                alt_started = time.time()
                try:
                    inst = build_provider(alt_row, alt_model, temperature,
                                          max_tokens, timeout)
                    reply = inst.chat(messages, tools)
                    latency = int((time.time() - alt_started) * 1000)
                    models.log_ai_call(
                        session_id=session_id, provider=alt_row["name"],
                        model=alt_model, ok=True, latency_ms=latency,
                        prompt_tokens=reply.usage.get("prompt_tokens"),
                        completion_tokens=reply.usage.get("completion_tokens"),
                        cost_est=_cost_est(alt_row, reply.usage))
                    return reply, alt_key
                except AIError:
                    models.log_ai_call(session_id=session_id,
                                       provider=alt_row["name"], model=alt_model,
                                       ok=False, error_type="fallback_failed",
                                       latency_ms=int((time.time() - alt_started) * 1000))
        raise e


def test_connection(overrides=None, timeout=25):
    """Quick connectivity probe with (optionally unsaved) credentials.
    Returns a plain dict for the settings-page test buttons."""
    ensure_seeded()
    data = overrides or {}
    name = (data.get("name") or "").strip()
    row = models.get_ai_provider(name) if name else None
    if not row:
        row = dict(data)
        row.setdefault("provider_type", "openai_compat")
        row.setdefault("models", json.dumps([data.get("model") or "test"]))
    # apply unsaved form values on top of the stored row
    for k in ("provider_type", "display_name", "base_url", "model", "api_key"):
        if data.get(k) is not None:
            row[k] = str(data.get(k)).strip()
    if not row.get("api_key"):
        return {"ok": False, "error": "未填写 API Key", "checks": [
            {"level": "err", "text": "请先填写该服务的 API Key 再测试。"}]}
    base = row.get("base_url") or ""
    if not base:
        return {"ok": False, "error": "未填写 API 地址", "checks": [
            {"level": "err", "text": "请填写 API 地址（base_url）。"}]}
    model_id = row.get("model") or (data.get("models") or [""])[0]
    if not model_id:
        return {"ok": False, "error": "未填写模型名称", "checks": [
            {"level": "err", "text": "请填写默认模型名称后再测试。"}]}
    started = time.time()
    try:
        inst = build_provider(row, model_id, temperature=0, max_tokens=16,
                              timeout=timeout)
        reply = inst.chat([{"role": "user", "content": "ping"}])
        latency = int((time.time() - started) * 1000)
        return {"ok": True, "latency_ms": latency,
                "reply": (reply.content or "")[:120],
                "checks": [{"level": "ok",
                            "text": f"✅ 连接正常（{latency}ms），模型 {model_id} 返回："
                                    f"{(reply.content or '').strip()[:60] or '（无文本）'}"}]}
    except AIError as e:
        return {"ok": False, "error": e.message, "latency_ms":
                int((time.time() - started) * 1000),
                "checks": [{"level": "err", "text": f"❌ {e.message}"}]}
    except Exception as e:  # noqa: BLE001 - surface anything to the UI
        return {"ok": False, "error": str(e),
                "checks": [{"level": "err", "text": f"❌ {e}"}]}
