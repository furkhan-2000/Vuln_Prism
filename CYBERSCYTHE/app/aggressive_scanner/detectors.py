import re
import httpx
from .config import settings
from loguru import logger

def detect_xss(response_text: str, payload: str) -> bool:
    try:
        if not response_text:
            return False

        # Check for direct payload reflection
        if re.search(re.escape(payload), response_text, re.IGNORECASE):
            return True

        # Check for DOM-based indicators
        dom_patterns = [
            r"<script[^>]*>.*alert\(.*\)",
            r'onerror\s*=\s*["\']?alert\(\)',
            r'<iframe[^>]*src\s*=["\']?javascript:'
        ]

        for pattern in dom_patterns:
            if re.search(pattern, response_text, re.IGNORECASE | re.DOTALL):
                return True

        return False
    except Exception as e:
        logger.error(f"XSS detection error: {e}")
        return False

def detect_sqli(response_text: str) -> bool:
    try:
        if not response_text:
            return False

        error_patterns = [
            r"SQL syntax.*MySQL",
            r"Warning.*mysqli?",
            r"Unclosed.*quotation",
            r"PG::SyntaxError",
            r"Microsoft OLE DB Provider",
            r"ODBC Driver",
            r"ORA-[0-9]{5}",
            r"com\.mysql\.jdbc\.exceptions",
            r"org\.postgresql\.util\.PSQLException",
            r"SQLiteException",
            r"Unterminated string literal"
        ]

        for pattern in error_patterns:
            if re.search(pattern, response_text, re.IGNORECASE):
                return True

        return False
    except Exception as e:
        logger.error(f"SQLi detection error: {e}")
        return False

def detect_cmd_injection(response_text: str) -> bool:
    try:
        if not response_text:
            return False

        patterns = [
            r"root:.*:0:0:",
            r"uid=\d+",
            r"windows nt",
            r"command not found",
            r"syntax error",
            r"cannot find the file specified",
        ]

        for pattern in patterns:
            if re.search(pattern, response_text, re.IGNORECASE):
                return True

        return False
    except Exception as e:
        logger.error(f"CMD Injection detection error: {e}")
        return False

def detect_path_traversal(response_text: str) -> bool:
    try:
        if not response_text:
            return False

        patterns = [
            r"root:.*:0:0:",
            r"\[extensions\]",
            r"cannot open",
            r"failed to open stream",
            r"no such file or directory",
            r"Warning: include\(",
        ]

        for pattern in patterns:
            if re.search(pattern, response_text, re.IGNORECASE):
                return True

        return False
    except Exception as e:
        logger.error(f"Path Traversal detection error: {e}")
        return False

def detect_info_disclosure(response_text: str) -> bool:
    try:
        if not response_text:
            return False

        sensitive_patterns = [
            r"(?i)api[_-]?key\s*[:=]\s*['\"][a-f0-9]{20,}['\"]",
            r"(?i)secret\s*[:=]\s*['\"][a-f0-9]{20,}['\"]",
            r"(?i)password\s*[:=]\s*['\"][^'\"]{8,}['\"]",
            r"(?i)aws_access_key_id\s*=\s*[A-Z0-9]{20}",
            r"(?i)-----BEGIN (RSA|DSA|EC|PGP) PRIVATE KEY-----",
            r"(?i)<dbpassword>[^<]+</dbpassword>",
            r"(?i)DB_USERNAME\s*=\s*['\"][^'\"]+['\"]",
            r"(?i)config\.prod\.json",
            r"(?i)\.env",
            r"(?i)phpinfo\(\)"
        ]

        for pattern in sensitive_patterns:
            if re.search(pattern, response_text):
                return True

        return False
    except Exception as e:
        logger.error(f"Info disclosure detection error: {e}")
        return False

def check_security_headers(headers, scan_result, url):
    missing_headers = []
    if 'Strict-Transport-Security' not in headers:
        missing_headers.append("Strict-Transport-Security (HSTS)")
    if 'X-Content-Type-Options' not in headers:
        missing_headers.append("X-Content-Type-Options")
    if 'X-Frame-Options' not in headers:
        missing_headers.append("X-Frame-Options")
    if 'Content-Security-Policy' not in headers:
        missing_headers.append("Content-Security-Policy")
    if 'X-XSS-Protection' not in headers or headers['X-XSS-Protection'] != '1; mode=block':
        missing_headers.append("X-XSS-Protection (or misconfigured)")

    if missing_headers:
        scan_result.add_vulnerability(
            url=url,
            vuln_type="Missing Security Headers",
            param="N/A",
            payload=f"Missing: {', '.join(missing_headers)}"
        )

def check_exposed_api_keys(html_content, scan_result, url):
    patterns = [
        r'sk-[a-zA-Z0-9]{32,}',
        r'AIza[0-9A-Za-z\-_]{35}',
        r'AKIA[0-9A-Z]{16}',
        r'[0-9a-fA-F]{32}-us[0-9]',
        r'pk_live_[0-9a-zA-Z]{24}',
        r'rk_live_[0-9a-zA-Z]{24}',
        r'sq0csp-[0-9A-Za-z\-_]{43}',
        r'EAACEdEose0cBA[0-9A-Za-z]+',
        r'xoxb-[0-9]{12}-[0-9]{12}-[0-9]{12}',
        r'ghp_[0-9a-zA-Z]{36}',
        r'gho_[0-9a-zA-Z]{36}',
        r'glpat-[0-9a-zA-Z\-_]{20}',
        r'Bearer\s[A-Za-z0-9\-\_=]+\.?[A-Za-z0-9\-\_=]+\.?[A-Za-z0-9\-\_=]+',
        r'Basic\s[A-Za-z0-9\-\_=]+',
        r'api_key=[a-zA-Z0-9]{32,}',
        r'token=[a-zA-Z0-9]{32,}',
    ]

    found_keys = []
    for pattern in patterns:
        matches = re.findall(pattern, html_content)
        for match in matches:
            found_keys.append(match)

    if found_keys:
        scan_result.add_vulnerability(
            url=url,
            vuln_type="Exposed API Key/Token",
            param="Page Content",
            payload=", ".join(found_keys[:3])
        )

def check_outdated_software(headers, html_content, scan_result, url):
    server_header = headers.get('Server', '').lower()
    if "apache" in server_header and not re.search(r'apache/(2\.[4-9]\.\d+|[3-9]\.\d+\.\d+)', server_header):
        vulnerabilities.append({
            "url": url,
            "type": "Outdated Server Software",
            "severity": "Medium",
            "description": f"Potentially outdated Apache server detected: {server_header}. Update to the latest stable version to mitigate known vulnerabilities.",
            "param": "Server Header",
            "payload": server_header
        })
    if "nginx" in server_header and not re.search(r'nginx/(1\.[18-9]\.\d+|[2-9]\.\d+\.\d+)', server_header):
        vulnerabilities.append({
            "url": url,
            "type": "Outdated Server Software",
            "severity": "Medium",
            "description": f"Potentially outdated Nginx server detected: {server_header}. Update to the latest stable version to mitigate known vulnerabilities.",
            "param": "Server Header",
            "payload": server_header
        })

    if "wordpress" in html_content.lower():
        wp_version_match = re.search(r'wp-emoji-release\.min\.js\?ver=([0-9.]+)', html_content)
        if wp_version_match:
            version = wp_version_match.group(1)
            if version < "6.0":
                vulnerabilities.append({
                    "url": url,
                    "type": "Outdated CMS (WordPress)",
                    "severity": "High",
                    "description": f"Outdated WordPress version detected: {version}. Many vulnerabilities exist in older versions. Update to the latest version.",
                    "param": "HTML Content",
                    "payload": version
                })

    php_header = headers.get('X-Powered-By', '').lower()
    if "php" in php_header:
        php_version_match = re.search(r'php/([0-9.]+)', php_header)
        if php_version_match:
            version = php_version_match.group(1)
            if version.startswith(('5.', '7.0', '7.1', '7.2', '7.3', '7.4')):
                vulnerabilities.append({
                    "url": url,
                    "type": "Outdated PHP Version",
                    "severity": "High",
                    "description": f"Outdated PHP version detected: {version}. This version is End-of-Life and no longer receives security updates. Upgrade to a supported PHP version (e.g., 8.x).",
                    "param": "X-Powered-By Header",
                    "payload": version
                })

def check_directory_listing(base_url, vulnerabilities, url):
    common_paths = ["/.git/HEAD", "/.svn/entries", "/wp-content/", "/uploads/"]
    for path in common_paths:
        test_url = f"{base_url.rstrip('/')}{path}"
        try:
            response = httpx.get(test_url, follow_redirects=True, timeout=5)
            if response.status_code == 200 and ("Index of /" in response.text or "Parent Directory" in response.text or "wp-content" in response.text):
                vulnerabilities.append({
                    "url": url,
                    "type": "Directory Listing Enabled",
                    "severity": "High",
                    "description": f"Directory listing is enabled for {test_url}. This can expose sensitive files and directory structures.",
                    "param": "N/A",
                    "payload": test_url
                })
        except httpx.RequestError:
            pass

def check_common_misconfigurations(base_url, vulnerabilities, url):
    misconfig_paths = [
        "/.git/config", "/admin/", "/phpmyadmin/", "/backup/", "/test/",
        "/config.php.bak", "/.env", "/crossdomain.xml", "/sitemap.xml.bak",
        "/web.config.bak", "/wp-config.php.bak",
    ]
    for path in misconfig_paths:
        test_url = f"{base_url.rstrip('/')}{path}"
        try:
            response = httpx.get(test_url, follow_redirects=True, timeout=5)
            if response.status_code == 200 and len(response.text) > 50:
                vulnerabilities.append({
                    "url": url,
                    "type": "Common Misconfiguration/Exposed File",
                    "severity": "High",
                    "description": f"Potentially exposed sensitive file or misconfiguration at {test_url}. This could reveal sensitive information or provide unauthorized access.",
                    "param": "N/A",
                    "payload": test_url
                })
        except httpx.RequestError:
            pass

def check_basic_xss(base_url, html_content, vulnerabilities, url):
    test_payload = "<script>alert('XSS')</script>"
    if test_payload in html_content:
        vulnerabilities.append({
            "url": url,
            "type": "Reflected XSS (Basic)",
            "severity": "Medium",
            "description": f"A basic XSS payload was reflected in the page content. This indicates a potential Cross-Site Scripting vulnerability. Further testing is recommended.",
            "param": "HTML Content",
            "payload": test_payload
        })

    try:
        test_url = f"{base_url}?q={test_payload}"
        response = httpx.get(test_url, follow_redirects=True, timeout=5)
        if test_payload in response.text:
            vulnerabilities.append({
                "url": url,
                "type": "Reflected XSS (URL Parameter)",
                "severity": "Medium",
                "description": f"A basic XSS payload injected via URL parameter was reflected. This indicates a potential Cross-Site Scripting vulnerability. Further testing is recommended.",
                "param": "URL Parameter",
                "payload": test_payload
                })
    except httpx.RequestError:
        pass

def check_insecure_forms(tree, base_url, vulnerabilities, url):
    forms = tree.css('form')
    for form in forms:
        action = form.attributes.get('action', '')
        method = form.attributes.get('method', 'GET').upper()

        if base_url.startswith("https://") and action.startswith("http://"):
            vulnerabilities.append({
                "url": url,
                "type": "Insecure Form Submission (HTTP on HTTPS)",
                "severity": "High",
                "description": f"Form submits data over HTTP ({action}) while the page is HTTPS. This can expose sensitive user data.",
                "param": "Form Action",
                "payload": action
            })

        csrf_token_found = False
        for input_tag in form.css('input[type="hidden"]'):
            name = input_tag.attributes.get('name', '').lower()
            if 'csrf' in name or 'token' in name:
                csrf_token_found = True
                break

        if not csrf_token_found and method == 'POST':
            vulnerabilities.append({
                "url": url,
                "type": "Missing CSRF Token (Heuristic)",
                "severity": "Medium",
                "description": f"POST form at '{action}' might be missing a CSRF token. This could make it vulnerable to Cross-Site Request Forgery (CSRF) attacks.",
                "param": "Form Action",
                "payload": action
            })

def check_sensitive_file_exposure(base_url, vulnerabilities, url):
    sensitive_files = [
        "/robots.txt", "/sitemap.xml", "/admin/config.php", "/config.inc.php",
        "/wp-config.php", "/.htaccess", "/.htpasswd", "/README.md", "/LICENSE",
        "/package.json", "/composer.json", "/web.config", "/server-status",
        "/phpinfo.php",
    ]
    for file_path in sensitive_files:
        test_url = f"{base_url.rstrip('/')}{file_path}"
        try:
            response = httpx.get(test_url, follow_redirects=True, timeout=5)
            if response.status_code == 200 and len(response.text) > 0:
                if any(token in response.text for token in ["User-agent", "Disallow", "sitemap", "<?php", "root", "password", "license", "dependencies", "phpinfo()"]):
                    vulnerabilities.append({
                        "url": url,
                        "type": "Sensitive File Exposure",
                        "severity": "Medium",
                        "description": f"Potentially sensitive file exposed at {test_url}. Review its content for confidential information.",
                        "param": "N/A",
                        "payload": test_url
                    })
        except httpx.RequestError:
            pass

def check_insecure_cookies(cookies, base_url, scan_result, url):
    for cookie in cookies:
        cookie_name = cookie.get('name')
        cookie_secure = cookie.get('secure')
        cookie_httponly = cookie.get('httponly')
        cookie_samesite = cookie.get('samesite')

        if base_url.startswith("https://") and not cookie_secure:
            scan_result.add_vulnerability(
                url=url,
                vuln_type="Insecure Cookie (Missing Secure Flag)",
                param=cookie_name,
                payload="Missing Secure Flag"
            )

        if not cookie_httponly:
            scan_result.add_vulnerability(
                url=url,
                vuln_type="Insecure Cookie (Missing HttpOnly Flag)",
                param=cookie_name,
                payload="Missing HttpOnly Flag"
            )

        if cookie_samesite not in ['Lax', 'Strict', 'lax', 'strict']:
            scan_result.add_vulnerability(
                url=url,
                vuln_type="Insecure Cookie (Missing/Weak SameSite Flag)",
                param=cookie_name,
                payload=f"Weak SameSite: {cookie_samesite}"
            )

def check_cors_misconfiguration(headers, scan_result, url):
    acao = headers.get('Access-Control-Allow-Origin')
    if acao == '*':
        scan_result.add_vulnerability(
            url=url,
            vuln_type="CORS Misconfiguration (Wildcard Origin)",
            param="Access-Control-Allow-Origin Header",
            payload=acao
        )
    elif acao and ',' in acao:
        vulnerabilities.append({
            "url": url,
            "type": "CORS Misconfiguration (Multiple Origins)",
            "severity": "Medium",
            "description": f"The 'Access-Control-Allow-Origin' header allows multiple origins: '{acao}'. Ensure this is intentional and properly secured to prevent unauthorized access.",
            "param": "Access-Control-Allow-Origin Header",
            "payload": acao
        })
