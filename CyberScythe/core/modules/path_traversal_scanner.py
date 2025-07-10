import httpx
import logging
from urllib.parse import urlparse, urlencode, parse_qs, unquote, quote, quote_plus
from core.scanner import capture_screenshot # Import capture_screenshot

logger = logging.getLogger(__name__)

def evolve_payload(base_payload: str) -> list[str]:
    """Generates variations of a payload, including URL encoded versions."""
    variations = [base_payload] # Original payload
    variations.append(quote(base_payload)) # URL encoded
    variations.append(quote_plus(base_payload)) # URL encoded (space as +)
    # Add more encoding variations as needed (e.g., HTML entities, double encoding)
    return variations

def is_local_target(url: str) -> bool:
    """Checks if the URL is a local target (localhost or 127.0.0.1)."""
    parsed_url = urlparse(url)
    return parsed_url.hostname in ("localhost", "127.0.0.1")

# --- Load Payloads ---
def load_payloads():
    try:
        with open("data/payloads/path_traversal.txt", "r") as f:
            return [line.strip() for line in f.readlines() if line.strip()]
    except FileNotFoundError:
        logger.error("path_traversal.txt not found. Please ensure it exists in data/payloads/")
        return []

PATH_TRAVERSAL_PAYLOADS = load_payloads()

# --- Path Traversal Scanner ---
async def run(http_client: httpx.AsyncClient, url: str, page, scan_id: int, api_endpoints: list = None, cookies: list = None, headers: list = None) -> list:
    """Runs the Path Traversal scan on a given URL."""
    MAX_JSON_DEPTH = 5
    # Test URL parameters
    if query_params:
        logger.info(f"Running Path Traversal scan on URL parameters for: {url}")
        for param_name, param_values in query_params.items():
            original_value = param_values[0]
            
            for payload in PATH_TRAVERSAL_PAYLOADS:
                for evolved_payload in evolve_payload(payload):
                    # Add filtering for dangerous payloads (e.g., those targeting system files outside expected scope)
                    # This is a basic example; more sophisticated checks might be needed.
                    normalized_payload = unquote(evolved_payload).lower()
                    if "etc/passwd" in normalized_payload and not is_local_target(url):
                        logger.warning(f"Skipped potentially dangerous path traversal payload in production: {evolved_payload}")
                        continue
                    if "windows/win.ini" in normalized_payload and not is_local_target(url):
                        logger.warning(f"Skipped potentially dangerous path traversal payload in production: {evolved_payload}")
                        continue

                    test_params = query_params.copy()
                    test_params[param_name] = evolved_payload
                    
                    # Reconstruct the URL with the malicious payload
                    test_url = parsed_url._replace(query=urlencode(test_params, doseq=True)).geturl()

                    try:
                        response = await http_client.get(test_url, timeout=5)
                        
                        # --- Basic Vulnerability Check ---
                        # Look for common file content in the response
                        if "root:x:0:0" in response.text or \
                           "nobody:x:65534:65534" in response.text or \
                           "[drivers]" in response.text.lower() and "for 16-bit app support" in response.text.lower():
                            
                            await page.goto(test_url, wait_until="networkidle")
                            screenshot_path = await capture_screenshot(page, scan_id, "Path Traversal")
                            vulnerability = {
                                "type": "Path Traversal",
                                "url": url,
                                "payload": evolved_payload,
                                "parameter": param_name,
                                "description": f"Potential Path Traversal vulnerability found in parameter '{param_name}' with payload: {evolved_payload}. File content detected.",
                                "severity": "High",
                                "screenshot": screenshot_path
                            }
                            vulnerabilities.append(vulnerability)
                            logger.warning(f"Potential Path Traversal found at {url} in parameter {param_name}")
                            # No break here, continue testing other payloads for the same parameter

                    except httpx.RequestError as e:
                        logger.debug(f"Request failed during Path Traversal scan for {test_url}: {e}", exc_info=True)

    # Test JSON/XML request bodies in API endpoints
    if api_endpoints:
        logger.info(f"Running Path Traversal scan on API endpoints for: {url}")
        for endpoint in api_endpoints:
            if endpoint["type"] == "json" and endpoint["body"]:
                # Recursively test JSON values
                async def _test_json_body_pt(current_json, path="", depth=0):
                    if isinstance(current_json, dict):
                        for key, value in current_json.items():
                            if isinstance(value, str):
                                for payload in PATH_TRAVERSAL_PAYLOADS:
                                    for evolved_payload in evolve_payload(payload):
                                        normalized_payload = unquote(evolved_payload).lower()
                                        if "etc/passwd" in normalized_payload and not is_local_target(url):
                                            logger.warning(f"Skipped potentially dangerous path traversal payload in production: {evolved_payload}")
                                            continue
                                        if "windows/win.ini" in normalized_payload and not is_local_target(url):
                                            logger.warning(f"Skipped potentially dangerous path traversal payload in production: {evolved_payload}")
                                            continue

                                        temp_json = current_json.copy()
                                        temp_json[key] = evolved_payload
                                        try:
                                            response = await http_client.post(endpoint["url"], json=temp_json)

                                            if "root:x:0:0" in response.text or \
                                               "nobody:x:65534:65534" in response.text or \
                                               "[drivers]" in response.text.lower() and "for 16-bit app support" in response.text.lower():
                                                
                                                screenshot_path = await capture_screenshot(page, scan_id, "Path Traversal (JSON Body)")
                                                vulnerabilities.append({
                                                    "type": "Path Traversal (JSON Body)",
                                                    "url": endpoint["url"],
                                                    "payload": evolved_payload,
                                                    "parameter": f"JSON path: {path}.{key}",
                                                    "description": f"Potential Path Traversal vulnerability found in JSON body at '{path}.{key}' with payload: {evolved_payload}",
                                                    "severity": "High",
                                                    "screenshot": screenshot_path
                                                })
                                                logger.warning(f"Potential PT found in JSON body at {endpoint['url']} in {path}.{key}")
                                        except httpx.RequestError as e:
                                            logger.error(f"Request failed during PT scan for {endpoint['url']} (JSON body): {e}", exc_info=True)
                            elif isinstance(value, (dict, list)):
                                await _test_json_body_pt(value, f"{path}.{key}", depth + 1)
                    elif isinstance(current_json, list):
                        for i, item in enumerate(current_json):
                            if isinstance(item, str):
                                for payload in PATH_TRAVERSAL_PAYLOADS:
                                    for evolved_payload in evolve_payload(payload):
                                        normalized_payload = unquote(evolved_payload).lower()
                                        if "etc/passwd" in normalized_payload and not is_local_target(url):
                                            logger.warning(f"Skipped potentially dangerous path traversal payload in production: {evolved_payload}")
                                            continue
                                        if "windows/win.ini" in normalized_payload and not is_local_target(url):
                                            logger.warning(f"Skipped potentially dangerous path traversal payload in production: {evolved_payload}")
                                            continue

                                        temp_list = current_json[:]
                                        temp_list[i] = evolved_payload
                                        try:
                                            response = await http_client.post(endpoint["url"], json=temp_list)

                                            if "root:x:0:0" in response.text or \
                                               "nobody:x:65534:65534" in response.text or \
                                               "[drivers]" in response.text.lower() and "for 16-bit app support" in response.text.lower():
                                                
                                                screenshot_path = await capture_screenshot(page, scan_id, "Path Traversal (JSON Body)")
                                                vulnerabilities.append({
                                                    "type": "Path Traversal (JSON Body)",
                                                    "url": endpoint["url"],
                                                    "payload": evolved_payload,
                                                    "parameter": f"JSON path: {path}[{i}]",
                                                    "description": f"Potential Path Traversal vulnerability found in JSON body at '{path}[{i}]' with payload: {evolved_payload}",
                                                    "severity": "High",
                                                    "screenshot": screenshot_path
                                                })
                                                logger.warning(f"Potential PT found in JSON body at {endpoint['url']} in {path}[{i}]")
                                        except httpx.RequestError as e:
                                            logger.error(f"Request failed during PT scan for {endpoint['url']} (JSON body): {e}", exc_info=True)
                            elif isinstance(item, (dict, list)):
                                await _test_json_body_pt(item, f"{path}[{i}]")
                
                await _test_json_body_pt(endpoint["body"])

    # Test custom HTTP headers
    if headers:
        logger.info(f"Running Path Traversal scan on HTTP headers for: {url}")
        for header_info in headers:
            # Only test headers for the current URL being scanned
            if urlparse(header_info["url"]).netloc == urlparse(url).netloc:
                for header_name, header_value in header_info["headers"].items():
                    for payload in PATH_TRAVERSAL_PAYLOADS:
                        for evolved_payload in evolve_payload(payload):
                            normalized_payload = unquote(evolved_payload).lower()
                            if "etc/passwd" in normalized_payload and not is_local_target(url):
                                logger.warning(f"Skipped potentially dangerous path traversal payload in production: {evolved_payload}")
                                continue
                            if "windows/win.ini" in normalized_payload and not is_local_target(url):
                                logger.warning(f"Skipped potentially dangerous path traversal payload in production: {evolved_payload}")
                                continue

                            test_headers = header_info["headers"].copy()
                            test_headers[header_name] = evolved_payload
                            try:
                                response = await http_client.request(header_info["method"], header_info["url"], headers=test_headers)

                                if "root:x:0:0" in response.text or \
                                   "nobody:x:65534:65534" in response.text or \
                                   "[drivers]" in response.text.lower() and "for 16-bit app support" in response.text.lower():
                                    
                                    screenshot_path = await capture_screenshot(page, scan_id, "Path Traversal (Header)")
                                    vulnerabilities.append({
                                        "type": "Path Traversal (Header)",
                                        "url": header_info["url"],
                                        "payload": evolved_payload,
                                        "parameter": f"Header: {header_name}",
                                        "description": f"Potential Path Traversal vulnerability found in header '{header_name}' with payload: {evolved_payload}",
                                        "severity": "High",
                                        "screenshot": screenshot_path
                                    })
                                    logger.warning(f"Potential PT found in header {header_name} at {header_info['url']}")
                            except httpx.RequestError as e:
                                logger.error(f"Request failed during PT scan for {header_info['url']} (header): {e}", exc_info=True)

    # Test cookies
    if cookies:
        logger.info(f"Running Path Traversal scan on Cookies for: {url}")
        for cookie_info in cookies:
            # Only test cookies for the current URL being scanned
            if urlparse(cookie_info["url"]).netloc == urlparse(url).netloc:
                for payload in PATH_TRAVERSAL_PAYLOADS:
                    for evolved_payload in evolve_payload(payload):
                        normalized_payload = unquote(evolved_payload).lower()
                        if "etc/passwd" in normalized_payload and not is_local_target(url):
                            logger.warning(f"Skipped potentially dangerous path traversal payload in production: {evolved_payload}")
                            continue
                        if "windows/win.ini" in normalized_payload and not is_local_target(url):
                            logger.warning(f"Skipped potentially dangerous path traversal payload in production: {evolved_payload}")
                            continue

                        # httpx expects cookies as a dictionary {name: value}
                        test_cookies = {cookie_info["name"]: evolved_payload}
                        try:
                            response = await http_client.get(cookie_info["url"], cookies=test_cookies)

                            if "root:x:0:0" in response.text or \
                               "nobody:x:65534:65534" in response.text or \
                               "[drivers]" in response.text.lower() and "for 16-bit app support" in response.text.lower():
                                
                                screenshot_path = await capture_screenshot(page, scan_id, "Path Traversal (Cookie)")
                                vulnerabilities.append({
                                    "type": "Path Traversal (Cookie)",
                                    "url": cookie_info["url"],
                                    "payload": evolved_payload,
                                    "parameter": f"Cookie: {cookie_info['name']}",
                                    "description": f"Potential Path Traversal vulnerability found in cookie '{cookie_info['name']}' with payload: {evolved_payload}",
                                    "severity": "High",
                                    "screenshot": screenshot_path
                                })
                                logger.warning(f"Potential PT found in cookie {cookie_info['name']} at {cookie_info['url']}")
                        except httpx.RequestError as e:
                            logger.error(f"Request failed during PT scan for {cookie_info['url']} (cookie): {e}", exc_info=True)

    return vulnerabilities
