import logging
import httpx
from urllib.parse import urlparse, parse_qs, urlencode

logger = logging.getLogger(__name__)

# --- Load Payloads ---
def load_payloads():
    with open("data/payloads/sqli.txt", "r") as f:
        return [line.strip() for line in f.readlines()]

SQLI_PAYLOADS = load_payloads()

# --- SQL Injection Scanner ---
async def run(http_client: httpx.AsyncClient, url: str) -> list:
    """Runs the SQL Injection scan on a given URL."""
    vulnerabilities = []
    parsed_url = urlparse(url)
    query_params = parse_qs(parsed_url.query)

    if not query_params:
        return [] # Skip URLs with no parameters

    logger.info(f"Running SQLi scan on: {url}")

    for param_name, param_values in query_params.items():
        original_value = param_values[0]
        
        for payload in SQLI_PAYLOADS:
            test_params = query_params.copy()
            test_params[param_name] = payload
            
            # Reconstruct the URL with the malicious payload
            test_url = parsed_url._replace(query=urlencode(test_params, doseq=True)).geturl()

            try:
                response = await http_client.get(test_url)
                
                # --- Basic Vulnerability Check ---
                # A more advanced check would look for specific DB errors
                if "sql syntax" in response.text.lower() or \
                   "mysql" in response.text.lower() or \
                   "unclosed quotation mark" in response.text.lower():
                    
                    vulnerability = {
                        "type": "SQL Injection",
                        "url": url,
                        "payload": payload,
                        "parameter": param_name,
                        "description": f"Potential SQL Injection vulnerability found in parameter '{param_name}' with payload: {payload}",
                        "severity": "Critical"
                    }
                    vulnerabilities.append(vulnerability)
                    logger.warning(f"Potential SQLi found at {url} in parameter {param_name}")
                    break # Move to the next parameter after finding a vulnerability

            except httpx.RequestError as e:
                logger.error(f"Request failed during SQLi scan for {test_url}: {e}", exc_info=True)

    return vulnerabilities
