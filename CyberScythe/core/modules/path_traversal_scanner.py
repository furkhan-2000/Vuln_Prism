import logging
import httpx
from urllib.parse import urlparse, parse_qs, urlencode

logger = logging.getLogger(__name__)

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
async def run(http_client: httpx.AsyncClient, url: str) -> list:
    """Runs the Path Traversal scan on a given URL."""
    vulnerabilities = []
    parsed_url = urlparse(url)
    query_params = parse_qs(parsed_url.query)

    if not query_params:
        return [] # Skip URLs with no parameters

    logger.info(f"Running Path Traversal scan on: {url}")

    for param_name, param_values in query_params.items():
        original_value = param_values[0]
        
        for payload in PATH_TRAVERSAL_PAYLOADS:
            test_params = query_params.copy()
            test_params[param_name] = payload
            
            # Reconstruct the URL with the malicious payload
            test_url = parsed_url._replace(query=urlencode(test_params, doseq=True)).geturl()

            try:
                response = await http_client.get(test_url, timeout=5)
                
                # --- Basic Vulnerability Check ---
                # Look for common file content in the response
                if "root:x:0:0" in response.text or \
                   "nobody:x:65534:65534" in response.text or \
                   "[drivers]" in response.text.lower() and "for 16-bit app support" in response.text.lower():
                    
                    vulnerability = {
                        "type": "Path Traversal",
                        "url": url,
                        "payload": payload,
                        "parameter": param_name,
                        "description": f"Potential Path Traversal vulnerability found in parameter '{param_name}' with payload: {payload}. File content detected.",
                        "severity": "High"
                    }
                    vulnerabilities.append(vulnerability)
                    logger.warning(f"Potential Path Traversal found at {url} in parameter {param_name}")
                    break # Move to the next parameter after finding a vulnerability

            except httpx.RequestError as e:
                logger.debug(f"Request failed during Path Traversal scan for {test_url}: {e}", exc_info=True)

    return vulnerabilities
