"""NVD CVE lookup — informational only, no scanning."""
import requests
import config

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def _clean_keyword(kw):
    """Turn 'nginx/1.18.0' into 'nginx 1.18.0' and strip noise."""
    kw = (kw or "").strip()
    if not kw or kw.lower() in ("none", "未知"):
        return ""
    return kw.replace("/", " ").replace("\\", " ").strip()


def lookup_cves(server, cms):
    """Query NVD by keyword.

    Returns (results, keywords): results is a deduplicated list of
    {id, description, cvss, published} sorted by CVSS desc; keywords is the
    list of search terms actually used (empty entries were skipped).
    """
    keywords = []
    server_k = _clean_keyword(server)
    cms_k = _clean_keyword(cms)
    if server_k:
        keywords.append(server_k)
    if cms_k and cms_k.lower() not in [k.lower() for k in keywords]:
        keywords.append(cms_k)

    results = []
    seen = set()
    for kw in keywords:
        try:
            resp = requests.get(NVD_URL, params={"keywordSearch": kw, "resultsPerPage": 10},
                                timeout=15, proxies=config.proxy_dict())
            resp.raise_for_status()
            data = resp.json()
        except Exception:
            continue
        for vuln in data.get("vulnerabilities", []):
            cve = vuln.get("cve", {})
            cve_id = cve.get("id", "")
            if not cve_id or cve_id in seen:
                continue
            seen.add(cve_id)
            descriptions = cve.get("descriptions", [])
            desc = ""
            for d in descriptions:
                if d.get("lang") == "en":
                    desc = d.get("value", "")
                    break
            # cvss
            cvss = None
            metrics = cve.get("metrics", {})
            for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                if metrics.get(key):
                    cvss = metrics[key][0].get("cvssData", {}).get("baseScore")
                    break
            published = cve.get("published", "")
            results.append({
                "id": cve_id,
                "description": desc,
                "cvss": cvss,
                "published": published[:10] if published else "",
            })

    results.sort(key=lambda c: (c["cvss"] is None, -(c["cvss"] or 0)))
    return results, keywords
