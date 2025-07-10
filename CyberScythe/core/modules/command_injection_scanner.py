import logging
import httpx
import re
from urllib.parse import urlparse, parse_qs, urlencode, quote, quote_plus
from core.scanner import capture_screenshot # Import capture_screenshot
import asyncio # For time-based blind command injection

logger = logging.getLogger(__name__)

def evolve_payload(base_payload: str) -> list[str]:
    """Generates variations of a payload, including URL encoded versions."""
    variations = [base_payload] # Original payload
    variations.append(quote(base_payload)) # URL encoded
    variations.append(quote_plus(base_payload)) # URL encoded (space as +)
    # Add more encoding variations as needed (e.g., HTML entities, double encoding)
    return variations

# --- Load Payloads ---
def load_payloads():
    try:
        with open("data/payloads/command_injection.txt", "r") as f:
            return [line.strip() for line in f.readlines() if line.strip()]
    except FileNotFoundError:
        logger.error("command_injection.txt not found. Please ensure it exists in data/payloads/")
        return []

COMMAND_INJECTION_PAYLOADS = load_payloads()

# --- Command Injection Scanner ---
async def run(http_client: httpx.AsyncClient, url: str, page, scan_id: int, api_endpoints: list = None, cookies: list = None, headers: list = None) -> list:
    """Runs the Command Injection scan on a given URL."""
    parsed_url = urlparse(url)
    query_params = parse_qs(parsed_url.query)
    vulnerabilities = []
    MAX_JSON_DEPTH = 5 # For infinite recursion risk fix

    # Test URL parameters
    if query_params:
        logger.info(f"Running Command Injection scan on URL parameters for: {url}")
        for param_name, param_values in query_params.items():
            original_value = param_values[0]
            
            for payload in COMMAND_INJECTION_PAYLOADS:
                for evolved_payload in evolve_payload(payload):
                    # Add safeguards for dangerous payloads
                    dangerous_patterns = re.compile(r"(rm\s|shutdown|mkfs|reboot|poweroff|dd\s|mkfs|fdisk)", re.IGNORECASE)
                    if dangerous_patterns.search(evolved_payload):
                        logger.warning(f"Skipped dangerous command injection payload: {evolved_payload}")
                        continue

                    test_params = query_params.copy()
                    test_params[param_name] = evolved_payload
                    
                    # Reconstruct the URL with the malicious payload
                    test_url = parsed_url._replace(query=urlencode(test_params, doseq=True)).geturl()

                    try:
                        start_time = asyncio.get_event_loop().time()
                        response = await http_client.get(test_url, timeout=5)
                        end_time = asyncio.get_event_loop().time()
                        response_time = end_time - start_time
                        
                        # --- Basic Vulnerability Check ---
                        # Look for common command output in the response
                        if "root:x:0:0" in response.text or \
                           "bin/bash" in response.text or \
                           "windows" in response.text.lower() and "system32" in response.text.lower() or \
                           "uid=" in response.text and "gid=" in response.text:
                            
                            await page.goto(test_url, wait_until="networkidle")
                            screenshot_path = await capture_screenshot(page, scan_id, "Command Injection")
                            vulnerability = {
                                "type": "Command Injection",
                                "url": url,
                                "payload": evolved_payload,
                                "parameter": param_name,
                                "description": f"Potential Command Injection vulnerability found in parameter '{param_name}' with payload: {evolved_payload}. Command output detected.",
                                "severity": "Critical",
                                "screenshot": screenshot_path
                            }
                            vulnerabilities.append(vulnerability)
                            logger.warning(f"Potential Command Injection found at {url} in parameter {param_name}")
                            # No break here, continue testing other payloads for the same parameter
                        
                        # --- Time-based Blind Command Injection Check ---
                        if "ping -c 4 127.0.0.1" in evolved_payload or "sleep 5" in evolved_payload:
                            if response_time >= 5: # Assuming a 5-second delay
                                screenshot_path = await capture_screenshot(page, scan_id, "Blind Command Injection")
                                vulnerability = {
                                    "type": "Blind Command Injection (Time-Based)",
                                    "url": url,
                                    "payload": evolved_payload,
                                    "parameter": param_name,
                                    "description": f"Time-based Blind Command Injection vulnerability detected in parameter '{param_name}' with payload '{evolved_payload}'. Response time: {response_time:.2f}s.",
                                    "severity": "High",
                                    "screenshot": screenshot_path
                                }
                                vulnerabilities.append(vulnerability)
                                logger.warning(f"Time-based Blind Command Injection found at {url} in parameter {param_name}")

                    except httpx.RequestError as e:
                        logger.debug(f"Request failed during Command Injection scan for {test_url}: {e}", exc_info=True)

    # Test JSON/XML request bodies in API endpoints
    if api_endpoints:
        logger.info(f"Running Command Injection scan on API endpoints for: {url}")
        for endpoint in api_endpoints:
            if endpoint["type"] == "json" and endpoint["body"]:
                # Recursively test JSON values
                async def _test_json_body_ci(current_json, path="", depth=0):
                    if depth > MAX_JSON_DEPTH: return
                    if isinstance(current_json, dict):
                        for key, value in current_json.items():
                            if isinstance(value, str):
                                for payload in COMMAND_INJECTION_PAYLOADS:
                                    for evolved_payload in evolve_payload(payload):
                                        # Add safeguards for dangerous payloads
                                        dangerous_patterns = re.compile(r"(rm\s|shutdown|mkfs|reboot|poweroff|dd\s|mkfs|fdisk)", re.IGNORECASE)
                                        if dangerous_patterns.search(evolved_payload):
                                            logger.warning(f"Skipped dangerous command injection payload: {evolved_payload}")
                                            continue

                                        temp_json = current_json.copy()
                                        temp_json[key] = evolved_payload
                                        try:
                                            start_time = asyncio.get_event_loop().time()
                                            response = await http_client.post(endpoint["url"], json=temp_json)
                                            end_time = asyncio.get_event_loop().time()
                                            response_time = end_time - start_time

                                            if "root:x:0:0" in response.text or \
                                               "bin/bash" in response.text or \
                                               "windows" in response.text.lower() and "system32" in response.text.lower() or \
                                               "uid=" in response.text and "gid=" in response.text or \
                                               ("ping -c 4 127.0.0.1" in evolved_payload and response_time >= 5):
                                                
                                                screenshot_path = await capture_screenshot(page, scan_id, "Command Injection (JSON Body)")
                                                vulnerabilities.append({
                                                    "type": "Command Injection (JSON Body)",
                                                    "url": endpoint["url"],
                                                    "payload": evolved_payload,
                                                    "parameter": f"JSON path: {path}.{key}",
                                                    "description": f"Potential Command Injection vulnerability found in JSON body at '{path}.{key}' with payload: {evolved_payload}",
                                                    "severity": "Critical",
                                                    "screenshot": screenshot_path
                                                })
                                                logger.warning(f"Potential CI found in JSON body at {endpoint['url']} in {path}.{key}")
                                        except httpx.RequestError as e:
                                            logger.error(f"Request failed during CI scan for {endpoint['url']} (JSON body): {e}", exc_info=True)
                            elif isinstance(value, (dict, list)):
                                await _test_json_body_ci(value, f"{path}.{key}", depth + 1)
                    elif isinstance(current_json, list):
                        for i, item in enumerate(current_json):
                            if isinstance(item, str):
                                for payload in COMMAND_INJECTION_PAYLOADS:
                                    for evolved_payload in evolve_payload(payload):
                                        # Add safeguards for dangerous payloads
                                        dangerous_patterns = re.compile(r"(rm\s|shutdown|mkfs|reboot|poweroff|dd\s|mkfs|fdisk)", re.IGNORECASE)
                                        if dangerous_patterns.search(evolved_payload):
                                            logger.warning(f"Skipped dangerous command injection payload: {evolved_payload}")
                                            continue

                                        temp_list = current_json[:]
                                        temp_list[i] = evolved_payload
                                        try:
                                            start_time = asyncio.get_event_loop().time()
                                            response = await http_client.post(endpoint["url"], json=temp_list)
                                            end_time = asyncio.get_event_loop().time()
                                            response_time = end_time - start_time

                                            if "root:x:0:0" in response.text or \
                                               "bin/bash" in response.text or \
                                               "windows" in response.text.lower() and "system32" in response.text.lower() or \
                                               "uid=" in response.text and "gid=" in response.text or \
                                               ("ping -c 4 127.0.0.1" in evolved_payload and response_time >= 5):
                                                
                                                screenshot_path = await capture_screenshot(page, scan_id, "Command Injection (JSON Body)")
                                                vulnerabilities.append({
                                                    "type": "Command Injection (JSON Body)",
                                                    "url": endpoint["url"],
                                                    "payload": evolved_payload,
                                                    "parameter": f"JSON path: {path}[{i}]",
                                                    "description": f"Potential Command Injection vulnerability found in JSON body at '{path}[{i}]' with payload: {evolved_payload}",
                                                    "severity": "Critical",
                                                    "screenshot": screenshot_path
                                                })
                                                logger.warning(f"Potential CI found in JSON body at {endpoint['url']} in {path}[{i}]")
                                        except httpx.RequestError as e:
                                            logger.error(f"Request failed during CI scan for {endpoint['url']} (JSON body): {e}", exc_info=True)
                            elif isinstance(item, (dict, list)):
                                await _test_json_body_ci(item, f"{path}[{i}]")
                
                await _test_json_body_ci(endpoint["body"])

    # Test custom HTTP headers
    if headers:
        logger.info(f"Running Command Injection scan on HTTP headers for: {url}")
        for header_info in headers:
            # Only test headers for the current URL being scanned
            if urlparse(header_info["url"]).netloc == urlparse(url).netloc:
                for header_name, header_value in header_info["headers"].items():
                    for payload in COMMAND_INJECTION_PAYLOADS:
                        for evolved_payload in evolve_payload(payload):
                            # Add safeguards for dangerous payloads
                            dangerous_patterns = re.compile(r"(rm\s|shutdown|mkfs|reboot|poweroff|dd\s|mkfs|fdisk)", re.IGNORECASE)
                            if dangerous_patterns.search(evolved_payload):
                                logger.warning(f"Skipped dangerous command injection payload: {evolved_payload}")
                                continue

                            test_headers = header_info["headers"].copy()
                            test_headers[header_name] = evolved_payload
                            try:
                                start_time = asyncio.get_event_loop().time()
                                response = await http_client.request(header_info["method"], header_info["url"], headers=test_headers)
                                end_time = asyncio.get_event_loop().time()
                                response_time = end_time - start_time

                                if "root:x:0:0" in response.text or \
                                   "bin/bash" in response.text or \
                                   "windows" in response.text.lower() and "system32" in response.text.lower() or \
                                   "uid=" in response.text and "gid=" in response.text or \
                                   ("ping -c 4 127.0.0.1" in evolved_payload and response_time >= 5):
                                    
                                    screenshot_path = await capture_screenshot(page, scan_id, "Command Injection (Header)")
                                    vulnerabilities.append({
                                        "type": "Command Injection (Header)",
                                        "url": header_info["url"],
                                        "payload": evolved_payload,
                                        "parameter": f"Header: {header_name}",
                                        "description": f"Potential Command Injection vulnerability found in header '{header_name}' with payload: {evolved_payload}",
                                        "severity": "Critical",
                                        "screenshot": screenshot_path
                                    })
                                    logger.warning(f"Potential CI found in header {header_name} at {header_info['url']}")
                            except httpx.RequestError as e:
                                logger.error(f"Request failed during CI scan for {header_info['url']} (header): {e}", exc_info=True)

    # Test cookies
    if cookies:
        logger.info(f"Running Command Injection scan on Cookies for: {url}")
        for cookie_info in cookies:
            # Only test cookies for the current URL being scanned
            if urlparse(cookie_info["url"]).netloc == urlparse(url).netloc:
                for payload in COMMAND_INJECTION_PAYLOADS:
                    for evolved_payload in evolve_payload(payload):
                        # Add safeguards for dangerous payloads
                        dangerous_patterns = re.compile(r"(rm\s|shutdown|mkfs|reboot|poweroff|dd\s|mkfs|fdisk)", re.IGNORECASE)
                        if dangerous_patterns.search(evolved_payload):
                            logger.warning(f"Skipped dangerous command injection payload: {evolved_payload}")
                            continue

                        # Preserve existing cookies and add the test cookie
                        test_cookies = http_client.cookies.copy()
                        test_cookies.set(cookie_info["name"], evolved_payload)
                        try:
                            start_time = asyncio.get_event_loop().time()
                            response = await http_client.get(cookie_info["url"], cookies=test_cookies)
                            end_time = asyncio.get_event_loop().time()
                            response_time = end_time - start_time

                            if "root:x:0:0" in response.text or \
                               "bin/bash" in response.text or \
                               "windows" in response.text.lower() and "system32" in response.text.lower() or \
                               "uid=" in response.text and "gid=" in response.text or \
                               ("ping -c 4 127.0.0.1" in evolved_payload and response_time >= 5):
                                
                                screenshot_path = await capture_screenshot(page, scan_id, "Command Injection (Cookie)")
                                vulnerabilities.append({
                                    "type": "Command Injection (Cookie)",
                                    "url": cookie_info["url"],
                                    "payload": evolved_payload,
                                    "parameter": f"Cookie: {cookie_info['name']}",
                                    "description": f"Potential Command Injection vulnerability found in cookie '{cookie_info['name']}' with payload: {evolved_payload}",
                                    "severity": "Critical",
                                    "screenshot": screenshot_path
                                })
                                logger.warning(f"Potential CI found in cookie {cookie_info['name']} at {cookie_info['url']}")
                        except httpx.RequestError as e:
                            logger.error(f"Request failed during CI scan for {cookie_info['url']} (cookie): {e}", exc_info=True)

    return vulnerabilities