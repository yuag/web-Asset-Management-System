import requests
import re
import urllib3
from concurrent.futures import ThreadPoolExecutor, as_completed

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

DEFAULT_HEADERS = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
    'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8',
}

# ===================== 指纹规则库（增强版） =====================
FINGERPRINTS = [
    # WordPress - 多重规则
    {'name': 'WordPress', 'rules': [
        {'type': 'header', 'name': 'x-pingback'},  # 注意：小写
        {'type': 'url', 'pattern': r'/wp-admin'},
        {'type': 'url', 'pattern': r'/wp-content'},
        {'type': 'meta', 'name': 'generator', 'pattern': r'WordPress'},
        {'type': 'body', 'pattern': r'wp-content/themes'},
        {'type': 'body', 'pattern': r'wp-json'},
    ]},
    # Drupal
    {'name': 'Drupal', 'rules': [
        {'type': 'header', 'name': 'x-drupal-cache'},
        {'type': 'meta', 'name': 'generator', 'pattern': r'Drupal'},
        {'type': 'url', 'pattern': r'/misc/drupal'},
    ]},
    # Joomla
    {'name': 'Joomla', 'rules': [
        {'type': 'meta', 'name': 'generator', 'pattern': r'Joomla'},
        {'type': 'url', 'pattern': r'/administrator'},
    ]},
    # ThinkPHP
    {'name': 'ThinkPHP', 'rules': [
        {'type': 'header', 'name': 'x-powered-by', 'pattern': r'ThinkPHP'},
        {'type': 'url', 'pattern': r'/index.php?s='},
    ]},
    # Laravel
    {'name': 'Laravel', 'rules': [
        {'type': 'cookie', 'name': 'laravel_session'},
        {'type': 'body', 'pattern': r'Laravel Framework'},
    ]},
    # Spring Boot
    {'name': 'Spring Boot', 'rules': [
        {'type': 'header', 'name': 'x-application-context'},
        {'type': 'body', 'pattern': r'Whitelabel Error Page'},
    ]},
    # Discuz
    {'name': 'Discuz', 'rules': [
        {'type': 'body', 'pattern': r'Discuz!'},
        {'type': 'url', 'pattern': r'/forum.php'},
    ]},
    # DedeCMS
    {'name': 'DedeCMS', 'rules': [
        {'type': 'meta', 'name': 'generator', 'pattern': r'DedeCMS'},
    ]},
    # Server 识别（放在后面）
    {'name': 'Nginx', 'rules': [{'type': 'header', 'name': 'server', 'pattern': r'nginx'}]},
    {'name': 'Apache', 'rules': [{'type': 'header', 'name': 'server', 'pattern': r'Apache'}]},
    {'name': 'IIS', 'rules': [{'type': 'header', 'name': 'server', 'pattern': r'Microsoft-IIS'}]},
    {'name': 'Tomcat', 'rules': [{'type': 'header', 'name': 'server', 'pattern': r'Tomcat'}]},
]

# 调试开关（设置为 True 可以看到匹配过程）
DEBUG = True

def detect_cms(url, response_text, response_headers):
    """根据响应内容识别 CMS 和 Server，带调试输出"""
    # 将 headers 转为小写字典，方便匹配
    headers_lower = {k.lower(): v for k, v in response_headers.items()}
    
    if DEBUG:
        print(f"🔍 识别 URL: {url}")
        print(f"📋 响应头: {list(headers_lower.keys())}")
        print(f"📄 响应体长度: {len(response_text) if response_text else 0}")
    
    # 提取 meta 标签
    metas = {}
    if response_text:
        for meta in re.findall(r'<meta\s+([^>]*?)>', response_text, re.IGNORECASE):
            name_match = re.search(r'name\s*=\s*["\']([^"\']+)["\']', meta, re.IGNORECASE)
            content_match = re.search(r'content\s*=\s*["\']([^"\']+)["\']', meta, re.IGNORECASE)
            if name_match and content_match:
                metas[name_match.group(1).lower()] = content_match.group(1)
    
    url_path = url.split('?')[0].lower()
    cms_result, server_result = None, None

    for fingerprint in FINGERPRINTS:
        name = fingerprint['name']
        matched = False
        for rule in fingerprint['rules']:
            rule_type = rule['type']
            try:
                if rule_type == 'meta':
                    meta_name = rule.get('name', '').lower()
                    pattern = rule.get('pattern', '')
                    if meta_name in metas and re.search(pattern, metas[meta_name], re.IGNORECASE):
                        matched = True
                        if DEBUG: print(f"  ✅ Meta 匹配: {name} (meta:{meta_name}={metas[meta_name]})")
                        break
                elif rule_type == 'url':
                    pattern = rule.get('pattern', '')
                    if re.search(pattern, url_path, re.IGNORECASE):
                        matched = True
                        if DEBUG: print(f"  ✅ URL 匹配: {name} (url:{url_path})")
                        break
                elif rule_type == 'header':
                    header_name = rule.get('name', '').lower()
                    pattern = rule.get('pattern', '')
                    if header_name in headers_lower:
                        header_value = headers_lower[header_name]
                        if not pattern:
                            matched = True
                            if DEBUG: print(f"  ✅ Header 存在: {name} (header:{header_name}={header_value})")
                            break
                        elif re.search(pattern, header_value, re.IGNORECASE):
                            matched = True
                            if DEBUG: print(f"  ✅ Header 匹配: {name} (header:{header_name}={header_value})")
                            break
                elif rule_type == 'cookie':
                    cookie_name = rule.get('name', '')
                    if 'Set-Cookie' in response_headers:
                        if re.search(rf'{cookie_name}\s*=', response_headers.get('Set-Cookie', ''), re.IGNORECASE):
                            matched = True
                            if DEBUG: print(f"  ✅ Cookie 匹配: {name}")
                            break
                elif rule_type in ['body', 'script']:
                    pattern = rule.get('pattern', '')
                    if response_text and re.search(pattern, response_text, re.IGNORECASE):
                        matched = True
                        if DEBUG: print(f"  ✅ Body 匹配: {name} (pattern:{pattern})")
                        break
            except Exception as e:
                if DEBUG: print(f"  ⚠️ 规则异常: {name} - {str(e)}")
                pass
        
        if matched:
            if name in ['Nginx', 'Apache', 'IIS', 'Tomcat']:
                server_result = name
            else:
                cms_result = name
            if DEBUG: print(f"  ✅ 最终识别: CMS={cms_result}, Server={server_result}")
            break

    if DEBUG:
        print(f"📊 识别结果: CMS='{cms_result}', Server='{server_result}'")
        print("-" * 50)
    
    return cms_result, server_result

def verify_and_fingerprint(domain):
    """对单个域名执行存活验证 + 指纹识别"""
    result = {
        'domain': domain,
        'alive': False,
        'status_code': None,
        'cms': None,
        'server': None,
        'error': None
    }

    # 清洗域名
    if '://' in domain:
        domain = domain.split('/')[2] if '://' in domain else domain
    domain = domain.split(':')[0]

    for protocol in ['https', 'http']:
        try:
            url = f"{protocol}://{domain}"
            if DEBUG: print(f"🌐 请求: {url}")
            resp = requests.get(
                url, 
                headers=DEFAULT_HEADERS, 
                timeout=5, 
                verify=False, 
                allow_redirects=True
            )
            result['status_code'] = resp.status_code
            result['alive'] = 200 <= resp.status_code < 500
            
            if DEBUG: print(f"📡 状态码: {resp.status_code}")
            
            cms, server = detect_cms(url, resp.text, dict(resp.headers))
            result['cms'] = cms
            result['server'] = server
            break
        except requests.exceptions.Timeout:
            result['error'] = 'Timeout'
        except requests.exceptions.ConnectionError:
            result['error'] = 'ConnectionError'
        except Exception as e:
            result['error'] = str(e)

    return result

def batch_fingerprint(domains, max_workers=10):
    """批量指纹识别，线程池并发"""
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_domain = {executor.submit(verify_and_fingerprint, domain): domain for domain in domains}
        for future in as_completed(future_to_domain):
            yield future.result()
