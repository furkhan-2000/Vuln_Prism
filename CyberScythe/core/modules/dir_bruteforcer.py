import logging
import httpx
from urllib.parse import urljoin

logger = logging.getLogger(__name__)

# --- Load Wordlist ---
def load_wordlist():
    try:
        with open("data/wordlists/common_dirs.txt", "r") as f:
            return [line.strip() for line in f.readlines() if line.strip()]
    except FileNotFoundError:
        logger.error("common_dirs.txt not found. Please ensure it exists in data/wordlists/")
        return []

COMMON_DIRS_WORDLIST = load_wordlist()

# --- Directory Bruteforcer Scanner ---
async def run(http_client: httpx.AsyncClient, base_url: str) -> list:
    """Runs the Directory Bruteforcing scan on a given base URL."""
    vulnerabilities = []
    logger.info(f"Starting Directory Bruteforcing scan on: {base_url}")

    for path in COMMON_DIRS_WORDLIST:
        test_url = urljoin(base_url, path)
        try:
            response = await http_client.get(test_url, follow_redirects=True, timeout=5)
            
            # Check for successful responses (200 OK, or redirects that lead to 200)
            if response.status_code == 200:
                # Heuristic to detect directory listing vs. actual file/page
                if "Index of /" in response.text or "<title>Index of /" in response.text.lower():
                    description = f"Directory listing enabled at {test_url}, potentially exposing sensitive files."
                    severity = "Medium"
                else:
                    description = f"Potentially sensitive file or directory found at {test_url}."
                    severity = "Low"

                vulnerability = {
                    "type": "Information Disclosure",
                    "url": test_url,
                    "description": description,
                    "severity": severity
                }
                vulnerabilities.append(vulnerability)
                logger.warning(f"Found: {test_url} (Status: {response.status_code})")

        except httpx.RequestError as e:
            logger.debug(f"Request failed during directory bruteforce for {test_url}: {e}", exc_info=True)
        except Exception as e:
            logger.error(f"An unexpected error occurred during directory bruteforce for {test_url}: {e}", exc_info=True)

    return vulnerabilities
