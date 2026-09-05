"""DingTalk webhook notification."""
import requests
import config
from datetime import datetime


def enabled():
    return config.get_bool("dingtalk_enabled") and config.get("dingtalk_webhook")


def _send_markdown(title, text):
    webhook = config.get("dingtalk_webhook")
    if not webhook:
        return False
    payload = {
        "msgtype": "markdown",
        "markdown": {"title": title, "text": text},
    }
    try:
        resp = requests.post(webhook, json=payload, timeout=10,
                             proxies=config.proxy_dict())
        return resp.status_code == 200
    except Exception:
        return False


def notify_scan_complete(root_domain, summary, changes):
    """changes: list of (domain, change_type) tuples."""
    if not enabled():
        return
    if not config.get_bool("dingtalk_notify_new") and not config.get_bool("dingtalk_notify_change"):
        return
    new_list = [c for c in changes if c[1] == "新增"]
    upd_list = [c for c in changes if c[1] == "更新"]
    if not new_list and not upd_list:
        return

    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    lines = [f"### 扫描完成: {root_domain}\n\n",
             f"**时间:** {ts}\n\n",
             f"**crt.sh:** {summary.get('crtsh_count',0)} 条 | **FOFA:** {summary.get('fofa_count',0)} 条\n\n"]
    if new_list and config.get_bool("dingtalk_notify_new"):
        lines.append(f"#### 新增资产 ({len(new_list)})\n\n")
        for d, _ in new_list[:20]:
            lines.append(f"- {d}\n")
        if len(new_list) > 20:
            lines.append(f"- ...等共 {len(new_list)} 条\n")
        lines.append("\n")
    if upd_list and config.get_bool("dingtalk_notify_change"):
        lines.append(f"#### 属性变更 ({len(upd_list)})\n\n")
        for d, _ in upd_list[:20]:
            lines.append(f"- {d}\n")
        lines.append("\n")
    _send_markdown(f"扫描完成 {root_domain}", "".join(lines))


def notify_cve(domain, cve_list):
    """cve_list: list of dicts with id, description, cvss, published."""
    if not enabled() or not config.get_bool("dingtalk_notify_cve"):
        return
    high = [c for c in cve_list if c.get("cvss") and c["cvss"] >= 7.0]
    if not high:
        return
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    lines = [f"### CVE 高危预警: {domain}\n\n",
             f"**时间:** {ts}\n\n",
             f"#### 高危漏洞 ({len(high)})\n\n"]
    for c in high[:10]:
        lines.append(f"- **{c['id']}** (CVSS {c['cvss']})\n  {c['description'][:80]}\n")
    _send_markdown(f"CVE预警 {domain}", "".join(lines))
