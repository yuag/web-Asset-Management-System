# Web 资产管理系统 (Flask + SQLite + ECharts)

自动化 Web 资产管理系统：根域扫描、子域名发现、指纹识别、CVE 预警、定时扫描、钉钉告警。

## 功能一览

### 核心功能
- **根域资产扫描**：输入根域，调用 crt.sh + crt.name + FOFA 发现子域名，智能合并去重，自动打标签（crt / crtname / fofa / both）；扫描前可填标签，扫描出的全部资产自动追加该标签（已有资产不覆盖原有标签）。
- **子域名展示与批量导入**：扫描结果列表带复选框，支持【一键导入选中】和【全部导入】。
- **TXT 批量导入**：上传 txt 文件，解析后手动补充国家、CMS、标签，支持批量设置、一键【批量应用标签】到勾选行，勾选导入；国家/CMS 选项可手动添加，标签输入框带已有标签自动补全。
- **资产库高级搜索**：关键词 + 国家 + CMS + 来源 + 标签多选组合筛选，表格排序，分页（每页20条），导出 CSV。
- **可视化仪表盘**：总资产/根域/国家/CMS/今日新增 KPI，今日变更统计（新增/变更/消失），国家/CMS/来源饼图，每日新增趋势柱状图，最近变更动态时间线。
- **左侧标签筛选**：点击标签同步过滤资产列表和搜索栏。
- **全局搜索独立页面**：顶部导航「🔍 全局搜索」进入独立检索页，大搜索框支持域名/IP/URL/标题/Server/CMS 全文模糊搜索，匹配关键词高亮（标黄），可组合国家/CMS/标签（多选）/来源筛选，分页 20 条/页 + 导出 CSV；点结果域名跳转资产库自动打开编辑弹窗（`/assets?open=<id>`）。
- **全站右上角快速搜索**：任意页面顶部导航右侧搜索框输入关键词回车，自动跳转全局搜索页并展示结果。
- **手动添加/编辑资产**：弹窗表单含域名、URL、IP、端口、标题、国家、CMS、Server、WAF、负责人、到期时间、标签、备注。
- **批量删除**：勾选多行，二次确认后删除。
- **资产详情弹窗**：含「资产信息」「关联漏洞」（NVD 情报联动）「Nuclei 漏洞」（被动扫描结果）三个选项卡。

### 字典选项管理（国家 / CMS / 来源）
- **选项库 (dict_options 表)**：国家/地区、CMS类型、来源三类下拉选项统一存储，支持手动添加和删除。
- **选项管理弹窗**：资产库「⚙️ 选项管理」按钮可批量增删三类选项。
- **快速添加**：新增/编辑资产弹窗、TXT导入页的国家/CMS 下拉框旁有「＋」按钮，可即时添加新选项。
- **自动注册**：导入或编辑资产时，新出现的国家/CMS/来源值会自动加入选项库，无需手动维护。
- **TXT导入批量设置**：解析结果支持按勾选行批量设置国家/CMS/标签。
- **自定义标签管理**：资产库「🏷️ 标签管理」（或左侧「＋ 新建标签」）可手动新增/删除自定义标签（如 项目A、核心资产），标签会出现在筛选下拉、标签云与输入自动补全中；扫描、TXT导入、编辑资产时输入的新标签也会自动创建。

### Nuclei 被动漏洞扫描
- **扫描前环境预检（强制）**：点击【开始扫描】前自动检测：①读取系统代理配置，通过代理访问 `https://httpbin.org/ip`（失败时给出「代理连接超时」等明确警告）；②无论是否使用代理都探测并展示当前扫描出口的公网 IP；③检测 nuclei 可执行文件。预检结果绿/红颜色区分展示。
- **安全限制**：若已启用代理但代理不可用，服务端**禁止执行扫描**（前端提示先修复网络配置）；若未配置代理，允许扫描但在弹窗中明确提示「出口为服务器公网 IP」；nuclei 命令一律以 argv 逐词执行（不经 shell），`-u 目标` / `-json` / `-proxy` 由系统强制附加，手动参数无法覆盖或注入。
- **被动扫描**：默认以 `-passive` 模式运行（Nuclei v3.2+，仅无攻击性探测模板），结果以 JSON 流式解析入库 `nuclei_results`，资产详情弹窗新增「Nuclei 漏洞」选项卡展示（severity 彩色标签 + 命中位置 + 提取内容 + 复现命令），可随时重扫 / 清除结果。
- **可视化 / 高级双模式**：资产库「🛡️ Nuclei 扫描」弹窗支持【🎛️ 可视化模式】（被动开关、严重级别、tags、自定义模板路径）与【⌨️ 高级模式】（直接输入 Nuclei 参数，如 `-id log4shell -severity critical`）；系统自动补全 `-u {target}` 与 `-json`、自动带上 `-proxy`，禁止 `-u/-l/-json/-o/-proxy` 等覆盖性参数。
- **扫描范围**：勾选资产、当前页资产、或筛选条件下的全部资产（上限 1000 目标，防止误扫超量）；支持中途停止，已发现结果实时保存。
- **代理测试按钮**：系统设置 → 代理配置增加「🧪 测试代理连接」（无需先保存即可测试当前表单值），并有独立的「🔧 检测 Nuclei / 扫描环境」；`nuclei_path` 可配置（留空自动查找 PATH）。

### 资产图谱（ECharts 关系图）
- **入口**：导航「📊 资产图谱」（位于 TXT导入 与 AI助手 之间），页面基于 ECharts 力引导布局渲染根域拓扑。
- **结构**：`GET /api/assets/graph` 按 root_domain 查询 assets 构建图谱——节点含 根域（红）、子域名（蓝）、IP（绿）、服务/端口（橙，来自端口扫描结果）；边含 root→subdomain（包含）、subdomain→ip（解析）、ip→service（监听）。未传 domain 时展示 Top 10 根域（按资产数），单根域超过 500 个节点时截断并在页面提示，防止前端卡死。
- **交互**：搜索框可输入任意根域；悬停显示节点名与类型；点击子域名跳转资产库编辑弹窗（`/assets?open=<id>`）；点击 IP / 服务节点弹出该 IP 的端口服务明细，若尚未扫描可一键「立即扫描」。

### 轻量端口服务识别（纯 Python socket）
- **实现**：新增 `port_scanner.py`——仅 TCP connect + `recv(1024)` 读取 banner，正则匹配识别 SSH / MySQL / Redis / PostgreSQL / HTTP / HTTPS（TLS 端口按默认归类）等服务，纯标准库（socket + concurrent.futures），无新增依赖，不发送任何攻击载荷。
- **配置**：系统设置新增「端口扫描配置」——端口列表（默认 `21,22,23,25,80,443,3306,6379,8080,8443`）、连接超时（默认 3s）、并发数（默认 20）、以及「域名探索完成后自动扫描新资产端口」开关。
- **触发**：① 域名探索发现的新资产若带 IP，自动在后台线程执行（不阻塞扫描流程）；② 资产库工具栏「🔌 扫描端口」手动勾选批量扫描（未勾选时可确认扫描当前页）；③ 资产详情弹窗新增「端口服务」选项卡 + 图谱 IP 弹窗均可对单个资产/IP 强制重扫。
- **去重**：结果写入 `assets.port`（逗号分隔列表）与 `assets.service`（`{"443":"HTTPS",...}` JSON），`ports_scanned_at` 记录扫描时间——同一资产 24 小时内自动跳过，手动触发（force）忽略时间限制。

### 指纹与情报
- **中间件 + WAF 识别**：从 FOFA Banner/Server 字段自动提取中间件名称和版本，识别 WAF 类型（Cloudflare、阿里云WAF、AWS WAF 等）。
- **CVE 预警（外部情报联动）**：在资产详情弹窗「关联漏洞」选项卡中，根据资产的 Server/CMS 字段（如 nginx/1.18.0、WordPress 5.9）自动调用 NVD API（`https://services.nvd.nist.gov/rest/json/cves/2.0`，`keywordSearch` 参数）查询相关 CVE，展示 CVE 编号、描述、CVSS 评分、发布时间，按 CVSS 降序去重排序；打开详情时可自动查询。若 Server/CMS 均为空则提示「请先完善资产指纹信息」。仅展示公开情报，不执行任何攻击性扫描，完全合规。
- **Whois 到期查询**：在资产详情中查询域名到期时间。

### AI 助手（自然语言操作资产库，多模型）
- **对话式操作**：菜单栏「🤖 AI助手」进入 ChatGPT 风格界面——左侧会话列表（可新建/删除会话，自动以首条消息命名），右侧对话区；支持回车发送（Shift+Enter 换行）、逐字打字机效果、输入框上方快捷指令（查资产 / 扫域名 / 看统计 / 查漏洞 / 导出报告）。
- **多模型切换**：对话区顶部模型下拉框可按会话选择模型（每会话独立记忆，新会话跟随全局默认）。已内置 DeepSeek / OpenAI GPT / Anthropic Claude / Google Gemini / 通义千问 Qwen / Kimi / 智谱 GLM / Groq / Mistral / xAI Grok / OpenRouter（聚合）/ SiliconFlow / 本地 Ollama 等主流服务，均支持函数调用；任选其一填 Key 启用即可。Claude 走原生 Messages API，其余走 OpenAI 兼容端点；所有厂商差异（system 位置、tool schema、参数映射）由 `ai_providers.py` 的适配层统一翻译，核心循环与数据格式完全一致。
- **Function Calling**：大模型通过函数调用执行后端工具：`query_assets`（按域名/IP/CMS/标签/国家等查询）、`scan_domain`（调用 crt.sh + crt.name + FOFA 扫描根域并入库）、`get_dashboard_stats`（总资产/今日新增/分布）、`get_cve_info`（NVD 查询）、`export_assets_report`（生成 CSV 报告并返回下载链接）。
- **安全限制**：`apply_asset_tags`（批量打标签）、`delete_assets`（批量删除）属危险操作——模型调用后**先暂停并向用户展示影响范围（二次确认弹窗）**，用户确认或拒绝后才会真正执行；未确认绝不写入。
- **审计日志**：工具调用（参数、结果、状态）写入 `ai_tool_log`；每次上游 LLM 请求（含失败与兜底尝试：厂商、模型、耗时、token、估算费用）另写 `ai_call_log`。系统设置 → AI 模型配置卡片可查看「最近工具调用记录」与「模型调用统计 / 上游请求日志」。
- **配置与连接测试**：系统设置 → 「AI 模型配置」列出全部内置服务，每家可填 API Key（留空表示保持原值）、API 地址、默认/可选模型、启用、设为默认，并有「🧪 测试连接」（无需先保存）。旧版 `ai_api_key / ai_base_url / ai_model` 配置在首次启动时自动迁移进 `deepseek` 服务条目；历史对话按当时模型标记为 `deepseek:<模型>`。
- **可选自动兜底**：开启 `ai_fallback_enabled` 后，若所选模型遇到超时 / 限流 / 5xx / 超长上下文等临时错误，会自动改用下一个已启用模型重试一次（认证与参数错误绝不兜底），实际作答模型记录到每条消息与审计日志中。

### 自动化与通知
- **定时自动扫描**：APScheduler 定时遍历所有根域自动扫描，自动记录变更日志（新增/更新/消失）。
- **钉钉通知**：扫描完成或检测到 CVSS ≥ 7.0 高危 CVE 时，发送 Markdown 格式钉钉消息。
- **代理配置**：支持 HTTP/HTTPS/SOCKS5 代理，所有外部请求统一走代理。

### 数据库
- **资产表 (assets)**：domain（唯一约束）、url、ip、port、title、country、country_code、cms、server、waf、owner、remark、expiration_date、status_code、source、tags（多对多）、root_domain、service（端口→服务 JSON）、ports_scanned_at（端口扫描时间）。
- **标签表 (tags)** + **资产-标签关联表 (asset_tags)**：多对多关系。
- **字典选项表 (dict_options)**：国家/CMS/来源下拉选项，UNIQUE(dtype, value)，随资产导入自动扩充。
- **变更日志表 (asset_changelog)**：记录资产新增/更新/消失，含变更字段、旧值、新值。
- **配置表 (config)**：key-value 结构存储所有配置（含 nuclei_path）。
- **Nuclei 结果表 (nuclei_results)**：存储 Nuclei 被动扫描解析出的漏洞（template-id/名称、severity、命中位置、提取内容、复现命令、原始 JSON），按资产关联，删除资产时级联清理。
- **AI 会话表 (chat_sessions / chat_history)**：AI 助手多会话存储，每条消息含 role（user/assistant/tool）、tool_calls、tool_call_id、`model`（'provider:model'，如 `deepseek:deepseek-chat`）、usage_json（token 用量与估算费用），删除会话级联清理历史。
- **AI 多模型配置表 (ai_providers)**：每家服务商一行（type/display/Key/地址/默认与可选模型/上下文/单价/速度档位/启用/是否默认），旧 DeepSeek 单模型配置自动迁移。
- **AI 工具审计表 (ai_tool_log)**：记录每次工具调用的会话、工具名、参数、结果与状态（ok/error/rejected/awaiting_confirmation）。
- **AI 请求审计表 (ai_call_log)**：记录每次上游 LLM 调用（成功与失败、兜底尝试），含厂商、模型、耗时、token 用量与估算费用，支持按厂商汇总费用。

### 性能优化（v2）
- **索引**：为 root_domain/country/cms/source/status_code/created_at/updated_at 及 asset_tags、asset_changelog、dict_options 的关联列建立索引，筛选、排序、标签 JOIN 查询提速；老库启动时自动 `CREATE INDEX IF NOT EXISTS` 升级。
- **FTS5 全文检索**：新增 `assets_fts` 虚拟表（外联 assets，触发器自动同步增删改），搜索走 `MATCH` 前缀分词（中英文均支持），不再全表 LIKE；SQLite 未编译 FTS5 时自动回退 LIKE，不影响功能。
- **批量导入优化**：扫描导入、TXT 导入、CSV 导入统一走 `batch_upsert_assets()`——单事务 + 分块预取已有记录 + `executemany` 批量写标签/字典/变更日志，导入万级资产只做 1 次提交。
- **分片扫描**：`iter_asset_shards()` 按 id 键集（keyset）分片流式扫描全表，替代大结果集的 OFFSET 深翻页；CSV 导出与批量任务均按 2000 条/片扫描，内存占用有界。
- **并行扫描**：`scan_root_domains()` 并发扫描多个根域（线程池，`scan_concurrency` 配置默认 5），定时任务自动使用，扫描多个根域大幅提速。
- **缓存**：进程内 TTL 缓存（`cache.py`）——仪表盘统计、标签云、字典选项、最近变更、配置项均缓存（秒级 TTL），所有写操作自动失效对应缓存，热点页面不再反复查库。
- **WAL 模式**：`PRAGMA journal_mode=WAL` + busy_timeout + synchronous=NORMAL，读写并发下更稳更快。

## 本地启动

```bash
# 1. 安装依赖
pip install -r requirements.txt

# 2. 启动
python3 app.py

# 3. 浏览器打开 http://127.0.0.1:5000
```

运行冒烟测试（使用临时数据库，不影响 assets.db）：

```bash
python -m unittest test_smoke -v
```

数据库 `assets.db` 自动创建。定时任务在 Flask 启动时自动初始化。

## 使用流程

1. **系统设置**：配置 FOFA Email + API Key（可选）、扫描超时、定时扫描、钉钉 Webhook、代理（可「测试代理连接」）、Nuclei 可执行文件路径（可「检测 Nuclei / 扫描环境」）、「端口扫描配置」（列表/超时/并发/自动开关）；「AI 模型配置」中为想用的服务商填 API Key → 勾选启用（可「🧪 测试连接」、设默认）。
2. **域名探索**：（可选填标签）输入根域 → 开始扫描 → 勾选资产 → 一键导入。
3. **TXT导入**：上传 txt（可选填标签）→ 补充国家/CMS →【批量应用标签】或批量设置 → 导入。
4. **全局搜索**：任意页右上角快速搜索，或进入「🔍 全局搜索」页组合筛选，结果点域名可直接在资产库编辑。
5. **资产库**：搜索、筛选、排序、分页、编辑、查看 CVE、导出 CSV；勾选资产后执行「🛡️ Nuclei 扫描」，详情弹窗「Nuclei 漏洞」选项卡查看结果。
6. **AI助手**：进入「🤖 AI助手」页新建会话，顶部下拉选择模型（每会话独立，可随时切换），用自然语言查询资产 / 扫描域名 / 查看统计 / 查询 CVE / 导出报告；批量打标签、删除等危险操作会先弹出二次确认。
7. **资产图谱**：在「📊 资产图谱」输入根域查看拓扑，点击子域名进编辑、点击 IP 查看端口服务并支持一键扫描。
8. **仪表盘**：查看统计、饼图、趋势图、变更动态。

## 文件清单

| 文件 | 说明 |
|------|------|
| `app.py` | Flask 路由与 API |
| `db.py` | SQLite 连接与 schema |
| `models.py` | 资产/标签/变更日志 CRUD + 统计 |
| `scanner.py` | crt.sh + FOFA 扫描 + 指纹识别 + 自动端口扫描触发 |
| `port_scanner.py` | 轻量 TCP 端口 banner 识别（并发扫描/服务识别/结果入库/24h 去重） |
| `templates/graph.html` | 资产图谱页（ECharts 力引导关系图 + IP 端口弹窗） |
| `config.py` | 配置读写（config 表） |
| `nvd.py` | NVD CVE 查询 |
| `nuclei_service.py` | Nuclei 被动扫描：环境预检 / 命令安全构建 / 结果解析入库 |
| `ai_providers.py` | AI 多模型适配层：内置服务注册表 / OpenAI 兼容 + Anthropic 原生适配器 / 参数映射 / 自动兜底 / 连接测试 |
| `ai_assistant.py` | AI 助手：多模型函数调用循环 / 工具执行 / 危险操作确认 / SSE 流式输出 |
| `cache.py` | 进程内 TTL 缓存（有容量上限，防无限增长） |
| `notifier.py` | 钉钉通知 |
| `whois_lookup.py` | 域名到期查询 |
| `scheduler.py` | APScheduler 定时扫描 |
| `benchmark_search.py` | 搜索性能/准确率基准（英文 vs 中文，FTS vs LIKE） |
| `templates/*.html` | 页面模板 |
| `static/style.css` | 样式 |
| `requirements.txt` | 依赖 |

## 可靠性加固（v2 修复清单）

1. **Nuclei 结果“清空后写入”改为分代切换**：每次扫描生成独立 `scan_id`，新结果先带着该 id 流入新表行，旧结果在扫描期间保持可见；扫描**成功**后在一个事务里删掉被覆盖资产的旧代结果（`finalize_nuclei_scan`），扫描**失败/停止**则只丢弃本次不完整的部分（`abort_nuclei_scan`），旧结果原样保留 —— 中途失败/崩溃不再让资产详情页变成“空结果”。旧库通过 `ALTER TABLE nuclei_results ADD COLUMN scan_id` 自动升级。
2. **跨连接 UNIQUE 竞态修复**：`batch_upsert_assets` 的“预取 SELECT → INSERT”若与并发写入撞上同域名，不再让整块 500 行回滚 —— 捕获冲突后重读该行并按更新处理（保留精确的变更日志），同时整批写入带 busy 指数退避重试（`db.retry_on_busy`）。
3. **SQLite busy 重试**：Nuclei 结果分批写入、最终切换、手动清除，以及 `upsert_asset` / `batch_upsert_assets` / 指纹任务 checkpoint 全部套用指数退避 + 抖动重试，扫描线程池并发时不再静默丢数据。
4. **AI 会话级串行化**：`chat_events` / `resume_after_confirm` 通过 per-session 锁串行执行 —— 双击回车、双标签页并发不会再交错写历史或重复执行工具；二次确认的 confirm_id 仍是一次性令牌，弹出即失效。
5. **指纹识别持久化 + 断点续跑**：识别任务落库（`fingerprint_tasks`），`processed` 为进度检查点；重启后 running 任务被标记 `interrupted`，前端/API 可通过 `POST /api/assets/identify/<task_id>/resume` 从断点继续（已完成的资产逐条提交，不会重复识别）。
6. **热搜结果缓存**：相同筛选/页码/排序的资产列表查询缓存 8 秒（`search:` 前缀），任何资产/标签/字典写入即失效 —— 翻页、热搜、仪表盘联动不再重复执行 FTS/LIKE + COUNT + 排序。
7. **中文搜索混合路由**：`unicode61` 无法对中文分词（整段 CJK 视为一个 token，跨词查询必然漏），现在含中文的查询自动走“按词 AND 的多词 LIKE”路径（子串语义正确）；英文/技术词仍走 FTS5 前缀索引。取舍与测量见 `benchmark_search.py`。

## 说明

- crt.sh 免费无需认证；FOFA 需要 API Key。
- 凭证存储于 SQLite config 表，便于测试；生产环境请自行加密。
- CVE 查询仅展示公开情报，不执行任何攻击性扫描。
- 所有外部请求支持代理（HTTP/HTTPS/SOCKS5）。
- Nuclei 为外部二进制，请自行安装（https://github.com/projectdiscovery/nuclei/releases），被动模式需 v3.2+；扫描属于主动安全测试，请确保目标已获得授权。
- AI 助手需至少启用一家模型服务（系统设置 → AI 模型配置，如 DeepSeek https://platform.deepseek.com、OpenAI、Gemini、本地 Ollama 等），未启用任何模型时聊天会给出明确提示；Claude 模型 ID 变更时在设置中修改即可；不同厂商按各自官网计量收费，系统按内置单价估算显示（可自行编辑）；模型回答与工具执行均以真实数据库数据为准。
