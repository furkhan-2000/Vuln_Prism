import logging
import httpx
from urllib.parse import urlparse, parse_qs, urlencode, quote, quote_plus
from core.scanner import capture_screenshot # Import capture_screenshot
import asyncio # For time-based blind SQLi
import json # Import json for JSON body parsing

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
    with open("data/payloads/sqli.txt", "r") as f:
        return [line.strip() for line in f.readlines()]

SQLI_PAYLOADS = load_payloads()

# --- SQL Injection Scanner ---
async def run(http_client: httpx.AsyncClient, url: str, page, scan_id: int, api_endpoints: list = None, cookies: list = None, headers: list = None) -> list:
    """Runs the SQL Injection scan on a given URL."""
    vulnerabilities = []
    parsed_url = urlparse(url)
    query_params = parse_qs(parsed_url.query)

    # Test URL parameters
    if query_params:
        logger.info(f"Running SQLi scan on URL parameters for: {url}")
        for param_name, param_values in query_params.items():
            original_value = param_values[0]
            for payload in SQLI_PAYLOADS:
                for evolved_payload in evolve_payload(payload):
                    test_params = query_params.copy()
                    test_params[param_name] = evolved_payload
                    
                    # Reconstruct the URL with the malicious payload
                    test_url = parsed_url._replace(query=urlencode(test_params, doseq=True)).geturl()

                    try:
                        start_time = asyncio.get_event_loop().time()
                        response = await http_client.get(test_url)
                        end_time = asyncio.get_event_loop().time()
                        response_time = end_time - start_time
                        
                        # --- Basic Vulnerability Check ---
                        # A more advanced check would look for specific DB errors
                        if "sql syntax" in response.text.lower() or \
                           "mysql" in response.text.lower() or \
                           "unclosed quotation mark" in response.text.lower():
                            
                            await page.goto(test_url, wait_until="networkidle")
                            screenshot_path = await capture_screenshot(page, scan_id, "SQL Injection")
                            vulnerability = {
                                "type": "SQL Injection",
                                "url": url,
                                "payload": evolved_payload,
                                "parameter": param_name,
                                "description": f"Potential SQL Injection vulnerability found in parameter '{param_name}' with payload: {evolved_payload}",
                                "severity": "Critical",
                                "screenshot": screenshot_path
                            }
                            vulnerabilities.append(vulnerability)
                            logger.warning(f"Potential SQLi found at {url} in parameter {param_name}")
                            # No break here, continue testing other payloads for the same parameter
                        
                        # --- Time-based Blind SQLi Check ---
                        if "SLEEP(5)" in evolved_payload or "pg_sleep(5)" in evolved_payload or "WAITFOR DELAY '0:0:5'" in evolved_payload:
                            if response_time >= 5: # Assuming a 5-second delay
                                screenshot_path = await capture_screenshot(page, scan_id, "Blind SQL Injection")
                                vulnerability = {
                                    "type": "Blind SQL Injection (Time-Based)",
                                    "url": url,
                                    "payload": evolved_payload,
                                    "parameter": param_name,
                                    "description": f"Time-based Blind SQL Injection vulnerability detected in parameter '{param_name}' with payload '{evolved_payload}'. Response time: {response_time:.2f}s.",
                                    "severity": "High",
                                    "screenshot": screenshot_path
                                }
                                vulnerabilities.append(vulnerability)
                                logger.warning(f"Time-based Blind SQL Injection found at {url} in parameter {param_name}")

                    except httpx.RequestError as e:
                        logger.error(f"Request failed during SQLi scan for {test_url}: {e}", exc_info=True)

    # Test JSON/XML request bodies in API endpoints
    if api_endpoints:
        logger.info(f"Running SQLi scan on API endpoints for: {url}")
        for endpoint in api_endpoints:
            if endpoint["type"] == "json" and endpoint["body"]:
                # Recursively test JSON values
                async def _test_json_body_sqli(current_json, path="", depth=0):
                    if depth > MAX_JSON_DEPTH: return
                    if isinstance(current_json, dict):
                        for key, value in current_json.items():
                            if isinstance(value, str):
                                for payload in SQLI_PAYLOADS:
                                    for evolved_payload in evolve_payload(payload):
                                        temp_json = current_json.copy()
                                        temp_json[key] = evolved_payload
                                        try:
                                            start_time = asyncio.get_event_loop().time()
                                            response = await http_client.post(endpoint["url"], json=temp_json)
                                            end_time = asyncio.get_event_loop().time()
                                            response_time = end_time - start_time

                                            if "sql syntax" in response.text.lower() or \
                                               "mysql" in response.text.lower() or \
                                               "unclosed quotation mark" in response.text.lower() or \
                                               ("SLEEP(5)" in evolved_payload and response_time >= 5):
                                                
                                                screenshot_path = await capture_screenshot(page, scan_id, "SQL Injection (JSON Body)")
                                                vulnerabilities.append({
                                                    "type": "SQL Injection (JSON Body)",
                                                    "url": endpoint["url"],
                                                    "payload": evolved_payload,
                                                    "parameter": f"JSON path: {path}.{key}",
                                                    "description": f"Potential SQL Injection vulnerability found in JSON body at '{path}.{key}' with payload: {evolved_payload}",
                                                    "severity": "Critical",
                                                    "screenshot": screenshot_path
                                                })
                                                logger.warning(f"Potential SQLi found in JSON body at {endpoint['url']} in {path}.{key}")
                                        except httpx.RequestError as e:
                                            logger.error(f"Request failed during SQLi scan for {endpoint['url']} (JSON body): {e}", exc_info=True)
                            elif isinstance(value, (dict, list)):
                                await _test_json_body_sqli(value, f"{path}.{key}", depth + 1)
                    elif isinstance(current_json, list):
                        for i, item in enumerate(current_json):
                            if isinstance(item, str):
                                for payload in SQLI_PAYLOADS:
                                    for evolved_payload in evolve_payload(payload):
                                        temp_list = current_json[:]
                                        temp_list[i] = evolved_payload
                                        try:
                                            start_time = asyncio.get_event_loop().time()
                                            response = await http_client.post(endpoint["url"], json=temp_list)
                                            end_time = asyncio.get_event_loop().time()
                                            response_time = end_time - start_time

                                            if "sql syntax" in response.text.lower() or \
                                               "mysql" in response.text.lower() or \
                                               "unclosed quotation mark" in response.text.lower() or \
                                               ("SLEEP(5)" in evolved_payload and response_time >= 5):
                                                
                                                screenshot_path = await capture_screenshot(page, scan_id, "SQL Injection (JSON Body)")
                                                vulnerabilities.append({
                                                    "type": "SQL Injection (JSON Body)",
                                                    "url": endpoint["url"],
                                                    "payload": evolved_payload,
                                                    "parameter": f"JSON path: {path}[{i}]",
                                                    "description": f"Potential SQL Injection vulnerability found in JSON body at '{path}[{i}]' with payload: {evolved_payload}",
                                                    "severity": "Critical",
                                                    "screenshot": screenshot_path
                                                })
                                                logger.warning(f"Potential SQLi found in JSON body at {endpoint['url']} in {path}[{i}]")
                                        except httpx.RequestError as e:
                                            logger.error(f"Request failed during SQLi scan for {endpoint['url']} (JSON body): {e}", exc_info=True)
                            elif isinstance(item, (dict, list)):
                                await _test_json_body_sqli(item, f"{path}[{i}]")
                
                await _test_json_body_sqli(endpoint["body"])

    # Test custom HTTP headers
    if headers:
        logger.info(f"Running SQLi scan on HTTP headers for: {url}")
        for header_info in headers:
            # Only test headers for the current URL being scanned
            if urlparse(header_info["url"]).netloc == urlparse(url).netloc:
                for header_name, header_value in header_info["headers"].items():
                    for payload in SQLI_PAYLOADS:
                        for evolved_payload in evolve_payload(payload):
                            test_headers = header_info["headers"].copy()
                            test_headers[header_name] = evolved_payload
                            try:
                                start_time = asyncio.get_event_loop().time()
                                response = await http_client.request(header_info["method"], header_info["url"], headers=test_headers)
                                end_time = asyncio.get_event_loop().time()
                                response_time = end_time - start_time

                                if "sql syntax" in response.text.lower() or \
                                   "mysql" in response.text.lower() or \
                                   "unclosed quotation mark" in response.text.lower() or \
                                   ("SLEEP(5)" in evolved_payload and response_time >= 5):
                                    
                                    screenshot_path = await capture_screenshot(page, scan_id, "SQL Injection (Header)")
                                    vulnerabilities.append({
                                        "type": "SQL Injection (Header)",
                                        "url": header_info["url"],
                                        "payload": evolved_payload,
                                        "parameter": f"Header: {header_name}",
                                        "description": f"Potential SQL Injection vulnerability found in header '{header_name}' with payload: {evolved_payload}",
                                        "severity": "Critical",
                                        "screenshot": screenshot_path
                                    })
                                    logger.warning(f"Potential SQLi found in header {header_name} at {header_info['url']}")
                            except httpx.RequestError as e:
                                logger.error(f"Request failed during SQLi scan for {header_info['url']} (header): {e}", exc_info=True)

    # Test cookies
    if cookies:
        logger.info(f"Running SQLi scan on Cookies for: {url}")
        for cookie_info in cookies:
            # Only test cookies for the current URL being scanned
            if urlparse(cookie_info["url"]).netloc == urlparse(url).netloc:
                for payload in SQLI_PAYLOADS:
                    for evolved_payload in evolve_payload(payload):
                        # httpx expects cookies as a dictionary {name: value}
                        test_cookies = {cookie_info["name"]: evolved_payload}
                        try:
                            start_time = asyncio.get_event_loop().time()
                            response = await http_client.get(cookie_info["url"], cookies=test_cookies)
                            end_time = asyncio.get_event_loop().time()
                            response_time = end_time - start_time

                            if "sql syntax" in response.text.lower() or \
                               "mysql" in response.text.lower() or \
                               "unclosed quotation mark" in response.text.lower() or \
                               ("SLEEP(5)" in evolved_payload and response_time >= 5):
                                
                                screenshot_path = await capture_screenshot(page, scan_id, "SQL Injection (Cookie)")
                                vulnerabilities.append({
                                    "type": "SQL Injection (Cookie)",
                                    "url": cookie_info["url"],
                                    "payload": evolved_payload,
                                    "parameter": f"Cookie: {cookie_info['name']}",
                                    "description": f"Potential SQL Injection vulnerability found in cookie '{cookie_info['name']}' with payload: {evolved_payload}",
                                    "severity": "Critical",
                                    "screenshot": screenshot_path
                                })
                                logger.warning(f"Potential SQLi found in cookie {cookie_info['name']} at {cookie_info['url']}")
                        except httpx.RequestError as e:
                            logger.error(f"Request failed during SQLi scan for {cookie_info['url']} (cookie): {e}", exc_info=True)

    return vulnerabilities
