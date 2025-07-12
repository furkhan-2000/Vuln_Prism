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
            r"onerror\s*=\s*["']?alert\(\)",
            r"<iframe[^>]*src\s*=\s*["']?javascript:"
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
            r"com\\.mysql\\.jdbc\\.exceptions",
            r"org\\.postgresql\\.util\\.PSQLException",
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
            r"uid=\\d+",
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
            r"Warning: include\\(",
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
            r"(?i)api[_-]?key\\s*[:=]\\s*["'][a-f0-9]{20,}["']",
            r"(?i)secret\\s*[:=]\\s*["'][a-f0-9]{20,}["']",
            r"(?i)password\\s*[:=]\\s*["'][^"']{8,}["']",
            r"(?i)aws_access_key_id\\s*=\\s*[A-Z0-9]{20}",
            r"(?i)-----BEGIN (RSA|DSA|EC|PGP) PRIVATE KEY-----",
            r"(?i)<dbpassword>[^<]+</dbpassword>",
            r"(?i)DB_USERNAME\\s*=\\s*["'][^"']+["']",
            r"(?i)config\\.prod\\.json",
            r"(?i)\\.env",
            r"(?i)phpinfo\\(\)"
        ]
        
        for pattern in sensitive_patterns:
            if re.search(pattern, response_text):
                return True
                
        return False
    except Exception as e:
        logger.error(f"Info disclosure detection error: {e}")
        return False

def check_security_headers(headers, vulnerabilities):
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
        vulnerabilities.append({
            "type": "Missing Security Headers",
            "severity": "Medium",
            "description": f"The following security headers are missing or misconfigured: {', '.join(missing_headers)}. This can lead to various attacks like XSS, clickjacking, and protocol downgrade attacks."
        })

def check_exposed_api_keys(html_content, vulnerabilities):
    # This is a very basic check. Real API key detection requires more sophisticated methods.
    patterns = [
        r'sk-[a-zA-Z0-9]{32,}',  # OpenAI API keys
        r'AIza[0-9A-Za-z-_]{35}', # Google API keys
        r'AKIA[0-9A-Z]{16}', # AWS Access Key ID
        r'[0-9a-fA-F]{32}-us[0-9]', # Mailchimp API keys
        r'pk_live_[0-9a-zA-Z]{24}', # Stripe Publishable Key
        r'rk_live_[0-9a-zA-Z]{24}', # Stripe Restricted Key
        r'sq0csp-[0-9A-Za-z\\-_]{43}', # Square OAuth Secret
        r'EAACEdEose0cBA[0-9A-Za-z]+', # Facebook Access Token
        r'xoxb-[0-9]{12}-[0-9]{12}-[0-9]{12}', # Slack Bot Token
        r'ghp_[0-9a-zA-Z]{36}', # GitHub Personal Access Token
        r'gho_[0-9a-zA-Z]{36}', # GitHub OAuth Token
        r'glpat-[0-9a-zA-Z\\-_]{20}', # GitLab Personal Access Token
        r'Bearer\\s[A-Za-z0-9\\-_=]+\\.?[A-Za-z0-9\\-_=]+\\.?[A-Za-z0-9\\-_=]+', # Generic JWT
        r'Basic\\s[A-Za-z0-9\\-_=]+', # Generic Basic Auth
        r'api_key=[a-zA-Z0-9]{32,}', # Generic API key parameter
        r'token=[a-zA-Z0-9]{32,}', # Generic token parameter
    ]
    
    found_keys = []
    for pattern in patterns:
        matches = re.findall(pattern, html_content)
        for match in matches:
            found_keys.append(match)
            
    if found_keys:
        vulnerabilities.append({
            "type": "Exposed API Key/Token",
            "severity": "High",
            "description": f"Potentially exposed API keys or tokens found in the HTML content. Examples: {', '.join(found_keys[:3])}. This could lead to unauthorized access to services."
        })

def check_outdated_software(headers, html_content, vulnerabilities):
    # Check server banners
    server_header = headers.get('Server', '').lower()
    if "apache" in server_header and not re.search(r'apache/(2\\.[4-9]\\.\\d+|[3-9]\\.\\d+\\.\\d+)', server_header):
        vulnerabilities.append({
            "type": "Outdated Server Software",
            "severity": "Medium",
            "description": f"Potentially outdated Apache server detected: {server_header}. Update to the latest stable version to mitigate known vulnerabilities."
        })
    if "nginx" in server_header and not re.search(r'nginx/(1\\.[18-9]\\.\\d+|[2-9]\\.\\d+\\.\\d+)', server_header):
        vulnerabilities.append({
            "type": "Outdated Server Software",
            "severity": "Medium",
            "description": f"Potentially outdated Nginx server detected: {server_header}. Update to the latest stable version to mitigate known vulnerabilities."
        })

    # Check for common CMS versions (very basic, can be expanded)
    if "wordpress" in html_content.lower():
        wp_version_match = re.search(r'wp-emoji-release\\.min\\.js\\?ver=([0-9.]+)', html_content)
        if wp_version_match:
            version = wp_version_match.group(1)
            # This is a placeholder for actual version comparison
            # In a real scanner, you'd compare against a known vulnerability database
            if version < "6.0": # Example: assuming 6.0 is a recent secure version
                vulnerabilities.append({
                    "type": "Outdated CMS (WordPress)",
                    "severity": "High",
                    "description": f"Outdated WordPress version detected: {version}. Many vulnerabilities exist in older versions. Update to the latest version."
                })
    
    # Check for PHP version in headers
    php_header = headers.get('X-Powered-By', '').lower()
    if "php" in php_header:
        php_version_match = re.search(r'php/([0-9.]+)', php_header)
        if php_version_match:
            version = php_version_match.group(1)
            # Example: PHP 7.4 and below are EOL
            if version.startswith(('5.', '7.0', '7.1', '7.2', '7.3', '7.4')):
                vulnerabilities.append({
                    "type": "Outdated PHP Version",
                    "severity": "High",
                    "description": f"Outdated PHP version detected: {version}. This version is End-of-Life and no longer receives security updates. Upgrade to a supported PHP version (e.g., 8.x)."
                })

def check_directory_listing(base_url, vulnerabilities):
    common_paths = ["/.git/HEAD", "/.svn/entries", "/wp-content/", "/uploads/"]
    for path in common_paths:
        test_url = f"{base_url.rstrip('/')}{path}"
        try:
            response = httpx.get(test_url, follow_redirects=True, timeout=5)
            if response.status_code == 200 and ("Index of /" in response.text or "Parent Directory" in response.text or "wp-content" in response.text):
                vulnerabilities.append({
                    "type": "Directory Listing Enabled",
                    "severity": "High",
                    "description": f"Directory listing is enabled for {test_url}. This can expose sensitive files and directory structures."
                })
        except httpx.RequestError:
            pass # Ignore connection errors for this check

def check_common_misconfigurations(base_url, vulnerabilities):
    misconfig_paths = [
        "/.git/config",  # Exposed Git repository
        "/admin/",       # Common admin panel path
        "/phpmyadmin/",  # Common phpMyAdmin path
        "/backup/",      # Common backup directory
        "/test/",        # Common test directory
        "/config.php.bak", # Backup config file
        "/.env",         # Environment variables file
        "/crossdomain.xml", # Flash cross-domain policy file
        "/sitemap.xml.bak", # Backup sitemap
        "/web.config.bak", # ASP.NET config backup
        "/wp-config.php.bak", # WordPress config backup
    ]
    for path in misconfig_paths:
        test_url = f"{base_url.rstrip('/')}{path}"
        try:
            response = httpx.get(test_url, follow_redirects=True, timeout=5)
            # Check for 200 OK and some content, but avoid false positives on empty pages
            if response.status_code == 200 and len(response.text) > 50: # Arbitrary length check
                vulnerabilities.append({
                    "type": "Common Misconfiguration/Exposed File",
                    "severity": "High",
                    "description": f"Potentially exposed sensitive file or misconfiguration at {test_url}. This could reveal sensitive information or provide unauthorized access."
                })
        except httpx.RequestError:
            pass

def check_basic_xss(base_url, html_content, vulnerabilities):
    # This is a very rudimentary check for reflected XSS.
    # A real XSS scanner would involve injecting payloads and analyzing responses.
    test_payload = "<script>alert('XSS')</script>"
    
    # Check if the payload is reflected directly in the HTML
    if test_payload in html_content:
        vulnerabilities.append({
            "type": "Reflected XSS (Basic)",
            "severity": "Medium",
            "description": f"A basic XSS payload was reflected in the page content. This indicates a potential Cross-Site Scripting vulnerability. Further testing is recommended."
        })
    
    # Try injecting into a URL parameter and check reflection
    try:
        test_url = f"{base_url}?q={test_payload}"
        response = httpx.get(test_url, follow_redirects=True, timeout=5)
        if test_payload in response.text:
            vulnerabilities.append({
                "type": "Reflected XSS (URL Parameter)",
                "severity": "Medium",
                "description": f"A basic XSS payload injected via URL parameter was reflected. This indicates a potential Cross-Site Scripting vulnerability. Further testing is recommended."
            })
    except httpx.RequestError:
        pass

def check_insecure_forms(tree, base_url, vulnerabilities):
    forms = tree.css('form')
    for form in forms:
        action = form.get('action', '')
        method = form.get('method', 'GET').upper()
        
        # Check for forms submitted over HTTP on an HTTPS page
        if base_url.startswith("https://") and action.startswith("http://"):
            vulnerabilities.append({
                "type": "Insecure Form Submission (HTTP on HTTPS)",
                "severity": "High",
                "description": f"Form submits data over HTTP ({action}) while the page is HTTPS. This can expose sensitive user data."
            })
        
        # Check for missing CSRF tokens (very basic: look for common hidden input names)
        # This is a heuristic, not a definitive check.
        csrf_token_found = False
        for input_tag in form.css('input[type="hidden"]'):
            name = input_tag.get('name', '').lower()
            if 'csrf' in name or 'token' in name:
                csrf_token_found = True
                break
        
        if not csrf_token_found and method == 'POST':
            vulnerabilities.append({
                "type": "Missing CSRF Token (Heuristic)",
                "severity": "Medium",
                "description": f"POST form at '{action}' might be missing a CSRF token. This could make it vulnerable to Cross-Site Request Forgery (CSRF) attacks."
            })

def check_sensitive_file_exposure(base_url, vulnerabilities):
    sensitive_files = [
        "/robots.txt",
        "/sitemap.xml",
        "/admin/config.php",
        "/config.inc.php",
        "/wp-config.php",
        "/.htaccess",
        "/.htpasswd",
        "/README.md",
        "/LICENSE",
        "/package.json",
        "/composer.json",
        "/web.config",
        "/server-status", # Apache server status
        "/phpinfo.php", # PHP info file
    ]
    for file_path in sensitive_files:
        test_url = f"{base_url.rstrip('/')}{file_path}"
        try:
            response = httpx.get(test_url, follow_redirects=True, timeout=5)
            if response.status_code == 200 and len(response.text) > 0:
                # Heuristic: check for common content in these files
                if "User-agent" in response.text or "Disallow" in response.text or \
                   "sitemap" in response.text or "<?php" in response.text or \
                   "root" in response.text or "password" in response.text or \
                   "license" in response.text or "dependencies" in response.text or \
                   "phpinfo()" in response.text:
                    vulnerabilities.append({
                        "type": "Sensitive File Exposure",
                        "severity": "Medium",
                        "description": f"Potentially sensitive file exposed at {test_url}. Review its content for confidential information."
                    })
        except httpx.RequestError: 
            pass

def check_insecure_cookies(cookies, base_url, vulnerabilities):
    for cookie in cookies:
        cookie_name = cookie.get('name')
        cookie_value = cookie.get('value')
        cookie_domain = cookie.get('domain')
        cookie_path = cookie.get('path')
        cookie_secure = cookie.get('secure')
        cookie_httponly = cookie.get('httponly')
        cookie_samesite = cookie.get('samesite') # Playwright might return None or 'unspecified'

        # Check for missing Secure flag on HTTPS
        if base_url.startswith("https://") and not cookie_secure:
            vulnerabilities.append({
                "type": "Insecure Cookie (Missing Secure Flag)",
                "severity": "Medium",
                "description": f"Cookie '{cookie_name}' is served over HTTPS but is missing the 'Secure' flag. This cookie could be intercepted over HTTP if the user accesses the site insecurely."
            })
        
        # Check for missing HttpOnly flag
        if not cookie_httponly:
            vulnerabilities.append({
                "type": "Insecure Cookie (Missing HttpOnly Flag)",
                "severity": "Medium",
                "description": f"Cookie '{cookie_name}' is missing the 'HttpOnly' flag. This makes it vulnerable to XSS attacks, as JavaScript can access the cookie."
            })
        
        # Check for SameSite attribute (lax or strict recommended)
        # Playwright's samesite can be 'unspecified', 'no_restriction', 'lax', 'strict'
        if cookie_samesite not in ['Lax', 'Strict', 'lax', 'strict']:
            vulnerabilities.append({
                "type": "Insecure Cookie (Missing/Weak SameSite Flag)",
                "severity": "Low", # Can be Medium depending on context
                "description": f"Cookie '{cookie_name}' is missing or has a weak 'SameSite' attribute ('{cookie_samesite}'). This can make it vulnerable to CSRF attacks."
            })

def check_cors_misconfiguration(headers, vulnerabilities):
    # Very basic check: look for overly permissive Access-Control-Allow-Origin
    acao = headers.get('Access-Control-Allow-Origin')
    if acao == '*':
        vulnerabilities.append({
            "type": "CORS Misconfiguration (Wildcard Origin)",
            "severity": "High",
            "description": "The 'Access-Control-Allow-Origin' header is set to '*', allowing any domain to access resources. This can lead to Cross-Origin Resource Sharing (CORS) vulnerabilities if sensitive data is exposed."
        })
    elif acao and ',' in acao: # Check for multiple origins, which might indicate a misconfig if not carefully managed
        vulnerabilities.append({
            "type": "CORS Misconfiguration (Multiple Origins)",
            "severity": "Medium",
            "description": f"The 'Access-Control-Allow-Origin' header allows multiple origins: '{acao}'. Ensure this is intentional and properly secured to prevent unauthorized access."
        })