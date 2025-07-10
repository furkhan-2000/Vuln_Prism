import logging
import httpx
from urllib.parse import urlparse, parse_qs, urlencode

logger = logging.getLogger(__name__)

# --- Load Payloads ---
def load_payloads():
    with open("data/payloads/xss.txt", "r") as f:
        return [line.strip() for line in f.readlines()]

XSS_PAYLOADS = load_payloads()

# --- XSS Scanner ---
async def run(http_client: httpx.AsyncClient, url: str) -> list:
    """Runs the XSS scan on a given URL."""
    vulnerabilities = []
    parsed_url = urlparse(url)
    query_params = parse_qs(parsed_url.query)

    if not query_params:
        return [] # Skip URLs with no parameters

    logger.info(f"Running XSS scan on: {url}")

    for param_name, param_values in query_params.items():
        original_value = param_values[0]
        
        for payload in XSS_PAYLOADS:
            test_params = query_params.copy()
            test_params[param_name] = payload
            
            # Reconstruct the URL with the malicious payload
            test_url = parsed_url._replace(query=urlencode(test_params, doseq=True)).geturl()

            try:
                response = await http_client.get(test_url)
                
                # --- Basic Vulnerability Check ---
                # If the payload is reflected in the response, it's a potential vulnerability
                if payload in response.text:
                    vulnerability = {
                        "type": "Cross-Site Scripting (XSS)",
                        "url": url,
                        "payload": payload,
                        "parameter": param_name,
                        "description": f"Potential Reflected XSS vulnerability found in parameter '{param_name}'. The payload was reflected in the response.",
                        "severity": "High"
                    }
                    vulnerabilities.append(vulnerability)
                    logger.warning(f"Potential XSS found at {url} in parameter {param_name}")
                    break # Move to the next parameter

            except httpx.RequestError as e:
                logger.error(f"Request failed during XSS scan for {test_url}: {e}", exc_info=True)

    return vulnerabilities
