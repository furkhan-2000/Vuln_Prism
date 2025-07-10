import logging
import httpx
from urllib.parse import urlparse, parse_qs, urlencode, quote, quote_plus
from playwright.async_api import async_playwright, TimeoutError as PlaywrightTimeoutError
from core.scanner import capture_screenshot # Import capture_screenshot
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
    with open("data/payloads/xss.txt", "r") as f:
        return [line.strip() for line in f.readlines()]

XSS_PAYLOADS = load_payloads()

# --- XSS Scanner ---
async def run(http_client: httpx.AsyncClient, url: str, page, scan_id: int, api_endpoints: list = None, cookies: list = None, headers: list = None) -> list:
    """Runs the XSS scan on a given URL."""
    MAX_JSON_DEPTH = 5
    # Test URL parameters
    if query_params:
        logger.info(f"Running XSS scan on URL parameters for: {url}")
        for param_name, param_values in query_params.items():
            original_value = param_values[0]
            
            for payload in XSS_PAYLOADS:
                for evolved_payload in evolve_payload(payload):
                    test_params = query_params.copy()
                    test_params[param_name] = evolved_payload
                    
                    # Reconstruct the URL with the malicious payload
                    test_url = parsed_url._replace(query=urlencode(test_params, doseq=True)).geturl()

                    try:
                        async with async_playwright() as p:
                            browser = await p.chromium.launch()
                            context = await browser.new_context()
                            page = await context.new_page()
                            
                            # Listen for dialogs (like alert() or confirm() triggered by XSS)
                            page.on("dialog", lambda dialog: dialog.accept())

                            await page.goto(test_url, wait_until="domcontentloaded")
                            
                            # Check for XSS execution in the DOM
                            xss_detected = await page.evaluate('''() => {
                                // Check if the payload is present in the DOM after rendering
                                if (document.documentElement.outerHTML.includes('<script>')) {
                                    return true;
                                }
                                // More advanced checks could involve looking for specific element attributes or JS execution
                                // For example, if an alert(1) was supposed to fire, the dialog listener would catch it.
                                return false;
                            }''')

                            if xss_detected:
                                screenshot_path = await capture_screenshot(page, scan_id, "XSS")
                                vulnerability = {
                                    "type": "Cross-Site Scripting (XSS)",
                                    "url": url,
                                    "payload": evolved_payload,
                                    "parameter": param_name,
                                    "description": f"Potential XSS vulnerability found in parameter '{param_name}'. Payload was rendered in the DOM.",
                                    "severity": "High",
                                    "screenshot": screenshot_path
                                }
                                vulnerabilities.append(vulnerability)
                                logger.warning(f"Potential XSS found at {url} in parameter {param_name}")
                                # No break here, continue testing other payloads for the same parameter

                            await browser.close()

                    except PlaywrightTimeoutError:
                        logger.warning(f"Timeout loading {test_url} during XSS scan.")
                    except Exception as e:
                        logger.error(f"An unexpected error occurred during XSS scan for {test_url}: {e}", exc_info=True)

    # Test JSON/XML request bodies in API endpoints
    if api_endpoints:
        logger.info(f"Running XSS scan on API endpoints for: {url}")
        for endpoint in api_endpoints:
            if endpoint["type"] == "json" and endpoint["body"]:
                # Recursively test JSON values
                async def _test_json_body_xss(current_json, path="", depth=0):
                    if depth > MAX_JSON_DEPTH: return
                    if isinstance(current_json, dict):
                        for key, value in current_json.items():
                            if isinstance(value, str):
                                for payload in XSS_PAYLOADS:
                                    for evolved_payload in evolve_payload(payload):
                                        temp_json = current_json.copy()
                                        temp_json[key] = evolved_payload
                                        try:
                                            async with async_playwright() as p:
                                                browser = await p.chromium.launch()
                                                context = await browser.new_context()
                                                page = await context.new_page()
                                                page.on("dialog", lambda dialog: dialog.accept())

                                                # Make the API request and then navigate to a page that might reflect the output
                                                # This is a simplified approach. A more robust solution would involve analyzing the API response directly.
                                                response = await http_client.post(endpoint["url"], json=temp_json)
                                                await page.goto(url, wait_until="domcontentloaded") # Navigate to original URL to check for reflected XSS

                                                xss_detected = await page.evaluate('''() => {
                                                    return document.documentElement.outerHTML.includes('<script>');
                                                }''')

                                                if xss_detected:
                                                    screenshot_path = await capture_screenshot(page, scan_id, "XSS (JSON Body)")
                                                    vulnerabilities.append({
                                                        "type": "Cross-Site Scripting (JSON Body)",
                                                        "url": endpoint["url"],
                                                        "payload": evolved_payload,
                                                        "parameter": f"JSON path: {path}.{key}",
                                                        "description": f"Potential XSS vulnerability found in JSON body at '{path}.{key}' with payload: {evolved_payload}",
                                                        "severity": "High",
                                                        "screenshot": screenshot_path
                                                    })
                                                    logger.warning(f"Potential XSS found in JSON body at {endpoint['url']} in {path}.{key}")
                                                await browser.close()
                                        except Exception as e:
                                            logger.error(f"Request failed during XSS scan for {endpoint['url']} (JSON body): {e}", exc_info=True)
                            elif isinstance(value, (dict, list)):
                                await _test_json_body_xss(value, f"{path}.{key}", depth + 1)
                    elif isinstance(current_json, list):
                        for i, item in enumerate(current_json):
                            if isinstance(item, str):
                                for payload in XSS_PAYLOADS:
                                    for evolved_payload in evolve_payload(payload):
                                        temp_list = current_json[:]
                                        temp_list[i] = evolved_payload
                                        try:
                                            async with async_playwright() as p:
                                                browser = await p.chromium.launch()
                                                context = await browser.new_context()
                                                page = await context.new_page()
                                                page.on("dialog", lambda dialog: dialog.accept())

                                                response = await http_client.post(endpoint["url"], json=temp_list)
                                                await page.goto(url, wait_until="domcontentloaded")

                                                xss_detected = await page.evaluate('''() => {
                                                    return document.documentElement.outerHTML.includes('<script>');
                                                }''')

                                                if xss_detected:
                                                    screenshot_path = await capture_screenshot(page, scan_id, "XSS (JSON Body)")
                                                    vulnerabilities.append({
                                                        "type": "Cross-Site Scripting (JSON Body)",
                                                        "url": endpoint["url"],
                                                        "payload": evolved_payload,
                                                        "parameter": f"JSON path: {path}[{i}]",
                                                        "description": f"Potential XSS vulnerability found in JSON body at '{path}[{i}]' with payload: {evolved_payload}",
                                                        "severity": "High",
                                                        "screenshot": screenshot_path
                                                    })
                                                    logger.warning(f"Potential XSS found in JSON body at {endpoint['url']} in {path}[{i}]")
                                                await browser.close()
                                        except Exception as e:
                                            logger.error(f"Request failed during XSS scan for {endpoint['url']} (JSON body): {e}", exc_info=True)
                            elif isinstance(item, (dict, list)):
                                await _test_json_body_xss(item, f"{path}[{i}]")
                
                await _test_json_body_xss(endpoint["body"])

    # Test custom HTTP headers
    if headers:
        logger.info(f"Running XSS scan on HTTP headers for: {url}")
        for header_info in headers:
            # Only test headers for the current URL being scanned
            if urlparse(header_info["url"]).netloc == urlparse(url).netloc:
                for header_name, header_value in header_info["headers"].items():
                    for payload in XSS_PAYLOADS:
                        for evolved_payload in evolve_payload(payload):
                            test_headers = header_info["headers"].copy()
                            test_headers[header_name] = evolved_payload
                            try:
                                async with async_playwright() as p:
                                    browser = await p.chromium.launch()
                                    context = await browser.new_context()
                                    page = await context.new_page()
                                    page.on("dialog", lambda dialog: dialog.accept())

                                    # Make the API request with modified headers and then navigate to a page that might reflect the output
                                    response = await http_client.request(header_info["method"], header_info["url"], headers=test_headers)
                                    await page.goto(url, wait_until="domcontentloaded") # Navigate to original URL to check for reflected XSS

                                    xss_detected = await page.evaluate('''() => {
                                        return document.documentElement.outerHTML.includes('<script>');
                                    }''')

                                    if xss_detected:
                                        screenshot_path = await capture_screenshot(page, scan_id, "XSS (Header)")
                                        vulnerabilities.append({
                                            "type": "Cross-Site Scripting (Header)",
                                            "url": header_info["url"],
                                            "payload": evolved_payload,
                                            "parameter": f"Header: {header_name}",
                                            "description": f"Potential XSS vulnerability found in header '{header_name}' with payload: {evolved_payload}",
                                            "severity": "High",
                                            "screenshot": screenshot_path
                                        })
                                        logger.warning(f"Potential XSS found in header {header_name} at {header_info['url']}")
                                    await browser.close()
                            except Exception as e:
                                logger.error(f"Request failed during XSS scan for {header_info['url']} (header): {e}", exc_info=True)

    # Test cookies
    if cookies:
        logger.info(f"Running XSS scan on Cookies for: {url}")
        for cookie_info in cookies:
            # Only test cookies for the current URL being scanned
            if urlparse(cookie_info["url"]).netloc == urlparse(url).netloc:
                for payload in XSS_PAYLOADS:
                    for evolved_payload in evolve_payload(payload):
                        # httpx expects cookies as a dictionary {name: value}
                        test_cookies = {cookie_info["name"]: evolved_payload}
                        try:
                            async with async_playwright() as p:
                                browser = await p.chromium.launch()
                                context = await browser.new_context()
                                page = await context.new_page()
                                page.on("dialog", lambda dialog: dialog.accept())

                                # Make the API request with modified cookies and then navigate to a page that might reflect the output
                                response = await http_client.get(cookie_info["url"], cookies=test_cookies)
                                await page.goto(url, wait_until="domcontentloaded") # Navigate to original URL to check for reflected XSS

                                xss_detected = await page.evaluate('''() => {
                                    return document.documentElement.outerHTML.includes('<script>');
                                }''')

                                if xss_detected:
                                    screenshot_path = await capture_screenshot(page, scan_id, "XSS (Cookie)")
                                    vulnerabilities.append({
                                        "type": "Cross-Site Scripting (Cookie)",
                                        "url": cookie_info["url"],
                                        "payload": evolved_payload,
                                        "parameter": f"Cookie: {cookie_info['name']}",
                                        "description": f"Potential XSS vulnerability found in cookie '{cookie_info['name']}' with payload: {evolved_payload}",
                                        "severity": "High",
                                        "screenshot": screenshot_path
                                    })
                                    logger.warning(f"Potential XSS found in cookie {cookie_info['name']} at {cookie_info['url']}")
                                await browser.close()
                        except Exception as e:
                            logger.error(f"Request failed during XSS scan for {cookie_info['url']} (cookie): {e}", exc_info=True)

    return vulnerabilities
