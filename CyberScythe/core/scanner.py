import logging
import asyncio
import httpx
from urllib.parse import urljoin, urlparse
from collections import deque
from playwright.async_api import async_playwright, TimeoutError as PlaywrightTimeoutError
import os
import uuid
import json # Import json for API body parsing

from celery_app import celery_app
from core.database import SessionLocal, Scan, Vulnerability
from core.reporting import generate_pdf_report

# --- Import Scanner Modules ---
from core.modules import sqli_scanner, xss_scanner, dir_bruteforcer, port_scanner, command_injection_scanner, path_traversal_scanner
from config import DEFAULT_USER_AGENT, MAX_URLS_TO_CRAWL, CONCURRENT_REQUESTS, REPORTS_DIR, SAFE_MODE, DANGEROUS_FORM_ACTIONS

logger = logging.getLogger(__name__)

# Ensure logger uses the root logger's configuration (which is now structured)
# This assumes the root logger is configured in main.py or similar entry point.
# If this file is run standalone, it would need its own logging configuration.


# --- Helper Functions ---
async def retry_request(http_client: httpx.AsyncClient, method: str, url: str, max_retries: int = 3, delay: float = 1.0, **kwargs):
    """Retries an HTTP request with exponential backoff."""
    for attempt in range(max_retries):
        try:
            response = await http_client.request(method, url, **kwargs)
            response.raise_for_status()  # Raise an exception for 4xx/5xx responses
            return response
        except (httpx.RequestError, httpx.HTTPStatusError) as e:
            logger.warning(f"Request failed (attempt {attempt + 1}/{max_retries}) for {url}: {e}")
            if attempt < max_retries - 1:
                await asyncio.sleep(delay * (2 ** attempt))
            else:
                raise

def normalize_url(url: str) -> str:
    """Normalizes a URL by removing fragments and ensuring consistent trailing slash."""
    parsed = urlparse(url)
    path = parsed.path.rstrip('/') # Remove trailing slash
    if not path: # If path is empty, make it a single slash
        path = '/'
    return parsed._replace(path=path, fragment='').geturl()

def is_same_domain(url1: str, url2: str) -> bool:
    """Checks if two URLs belong to the same domain."""
    return urlparse(url1).netloc == urlparse(url2).netloc

async def capture_screenshot(page, scan_id: int, vulnerability_type: str) -> str | None:
    """Captures a screenshot of the current page and returns its path."""
    try:
        screenshots_dir = os.path.join(REPORTS_DIR, str(scan_id), "screenshots")
        os.makedirs(screenshots_dir, exist_ok=True)
        filename = f"{vulnerability_type.replace(' ', '_').lower()}_{uuid.uuid4().hex}.png"
        screenshot_path = os.path.join(screenshots_dir, filename)
        await page.screenshot(path=screenshot_path, full_page=True)
        logger.info(f"Screenshot captured: {screenshot_path}")
        return screenshot_path
    except Exception as e:
        logger.error(f"Failed to capture screenshot: {e}", exc_info=True)
        return None

class Crawler:
    def __init__(self, base_url: str, http_client: httpx.AsyncClient, page):
        self.base_url = base_url
        self.http_client = http_client
        self.page = page
        self.urls_to_scan = deque([normalize_url(base_url)])
        self.crawled_urls = set()
        self.attack_surface = {
            "crawled_urls": set(),
            "forms": [],
            "url_params": set(),
            "api_endpoints": [],
            "cookies": [],
            "headers": []
        }

    async def _handle_route(self, route):
        """Intercepts network requests to capture headers, cookies, and identify API endpoints."""
        request = route.request
        headers = request.headers
        url = request.url
        method = request.method
        post_data = request.post_data
        resource_type = request.resource_type

        # Capture request headers
        self.attack_surface["headers"].append({"url": url, "method": method, "headers": dict(headers)})

        # Identify potential API endpoints (e.g., JSON/XML content types, common API paths, XHR requests)
        # Prioritize XHR/fetch requests as potential API endpoints
        if resource_type == "xhr" or resource_type == "fetch":
            if post_data:
                try:
                    # Attempt to parse as JSON
                    json_data = json.loads(post_data)
                    self.attack_surface["api_endpoints"].append({"url": url, "method": method, "body": json_data, "type": "json"})
                except json.JSONDecodeError:
                    # Not JSON, maybe XML or other data
                    self.attack_surface["api_endpoints"].append({"url": url, "method": method, "body": post_data, "type": "other"})
            else:
                self.attack_surface["api_endpoints"].append({"url": url, "method": method, "type": "get"})
        elif "/api/" in url or "/graphql" in url or "/rest/" in url:
            # Also consider URLs with common API path patterns
            if post_data:
                try:
                    json_data = json.loads(post_data)
                    self.attack_surface["api_endpoints"].append({"url": url, "method": method, "body": json_data, "type": "json"})
                except json.JSONDecodeError:
                    self.attack_surface["api_endpoints"].append({"url": url, "method": method, "body": post_data, "type": "other"})
            else:
                self.attack_surface["api_endpoints"].append({"url": url, "method": method, "type": "get"})

        await route.continue_()

    async def crawl(self) -> dict:
        """Crawls a website to discover URLs, forms, parameters, API endpoints, cookies, and headers."""
        self.page.route("**", self._handle_route)

        while self.urls_to_scan and len(self.crawled_urls) < MAX_URLS_TO_CRAWL:
            current_url = self.urls_to_scan.popleft()
            if current_url in self.crawled_urls or not is_same_domain(current_url, self.base_url):
                continue

            logger.info(f"Crawling: {current_url}")
            self.crawled_urls.add(current_url)
            self.attack_surface["crawled_urls"].add(current_url)

            try:
                await self.page.goto(current_url, wait_until="networkidle")
                
                # Discover links
                links = await self.page.evaluate("Array.from(document.querySelectorAll('a[href]')).map(a => a.href)")
                for link in links:
                    absolute_link = urljoin(self.base_url, link)
                    normalized_link = normalize_url(absolute_link)
                    if normalized_link not in self.crawled_urls and is_same_domain(normalized_link, self.base_url):
                        self.urls_to_scan.append(normalized_link)

                # Discover forms and attempt submission
                forms_on_page = await self.page.evaluate('''
                    Array.from(document.querySelectorAll('form')).map(form => ({
                        action: form.action,
                        method: form.method,
                        inputs: Array.from(form.querySelectorAll('input, textarea, select')).map(input => ({
                            name: input.name,
                            type: input.type || input.tagName.toLowerCase(),
                            value: input.value || ''
                        }))
                    }))
                ''')
                for form_data in forms_on_page:
                    form_url = urljoin(current_url, form_data['action'])

                    # --- Safety Mechanism: Skip dangerous form actions in SAFE_MODE ---
                    if SAFE_MODE and any(action in form_url.lower() for action in DANGEROUS_FORM_ACTIONS):
                        logger.warning(f"[SAFE_MODE] Skipping potentially dangerous form action: {form_url}")
                        continue

                    self.attack_surface["forms"].append({
                        "url": form_url,
                        "method": form_data['method'],
                        "inputs": form_data['inputs']
                    })

                    # Attempt to submit forms with dummy data to discover more URLs/parameters
                    try:
                        form_page = await self.page.context.new_page()
                        await form_page.goto(current_url, wait_until="networkidle")
                        # Find the form again on the new page context
                        form_selector = f"form[action='{form_data['action']}']" if form_data['action'] else 'form'
                        if form_data['method'].lower() == 'get':
                            # For GET forms, just construct the URL with dummy params
                            get_params = {}
                            for input_field in form_data['inputs']:
                                if input_field['name']:
                                    get_params[input_field['name']] = "test_value"
                            if get_params:
                                new_query = urlencode(get_params)
                                test_form_url = f"{form_url}?{new_query}"
                                normalized_test_form_url = normalize_url(test_form_url)
                                if normalized_test_form_url not in self.crawled_urls and is_same_domain(normalized_test_form_url, self.base_url):
                                    self.urls_to_scan.append(normalized_test_form_url)
                        else:
                            # For POST forms, fill and submit
                            csrf_token = await form_page.evaluate('''() => {
                                const meta = document.querySelector('meta[name="csrf-token"]');
                                if (meta) return meta.content;
                                const input = document.querySelector('input[name="csrf_token"], input[name="_csrf"], input[name="authenticity_token"]');
                                return input ? input.value : null;
                            }''')
                            if csrf_token:
                                logger.info(f"Found CSRF token: {csrf_token[:10]}...")
                                # Attempt to fill common CSRF token field names
                                await form_page.fill('[name="csrf_token"]', csrf_token).catch(lambda e: logger.debug(f"Could not fill csrf_token field: {e}"))
                                await form_page.fill('[name="_csrf"]', csrf_token).catch(lambda e: logger.debug(f"Could not fill _csrf field: {e}"))
                                await form_page.fill('[name="authenticity_token"]', csrf_token).catch(lambda e: logger.debug(f"Could not fill authenticity_token field: {e}"))

                            for input_field in form_data['inputs']:
                                if input_field['name']:
                                    await form_page.fill(f"[name='{input_field['name']}']", "test_value")
                            await form_page.click('button[type="submit"], input[type="submit"]') # Click submit button
                            await form_page.wait_for_load_state("networkidle")
                            # After submission, check the new URL
                            submitted_url = form_page.url
                            normalized_submitted_url = normalize_url(submitted_url)
                            if normalized_submitted_url not in self.crawled_urls and is_same_domain(normalized_submitted_url, self.base_url):
                                self.urls_to_scan.append(normalized_submitted_url)
                        await form_page.close()
                    except Exception as form_e:
                        logger.warning(f"Error submitting form on {current_url}: {form_e}")

                # Discover URL parameters
                if '?' in current_url:
                    self.attack_surface["url_params"].add(current_url)

                # Also consider form inputs as potential parameters for attack modules
                for form_data in forms_on_page:
                    for input_field in form_data['inputs']:
                        if input_field['name']:
                            # Create a dummy URL to represent the form submission with parameters
                            # This is a simplified representation; actual exploitation would involve POST requests
                            dummy_url = f"{urljoin(current_url, form_data['action'])}?{input_field['name']}=value"
                            self.attack_surface["url_params"].add(dummy_url)

            except PlaywrightTimeoutError:
                logger.warning(f"Timeout loading {current_url}", exc_info=True)
            except Exception as e:
                logger.error(f"Error crawling {current_url}: {e}", exc_info=True)
        
        # Capture cookies after all navigations for the current page
        cookies = await self.page.context.cookies()
        for cookie in cookies:
            self.attack_surface["cookies"].append(cookie)

        return self.attack_surface

# --- Main Scanner Orchestrator ---
@celery_app.task(name="run_scan_task")
def run_scan_task(scan_id: int, base_url: str, old_scan_state: dict = None):
    """Celery task to orchestrate the scanning process."""
    db = SessionLocal()
    try:
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if not scan:
            logger.error(f"[{scan_id}] Scan not found in database.")
            return

        logger.info(f"[{scan_id}] Starting deep scan for URL: {base_url}")
        vulnerabilities = []
        
        headers = {"User-Agent": DEFAULT_USER_AGENT}
        
        async with httpx.AsyncClient(timeout=30, follow_redirects=True, headers=headers) as http_client:
            async with async_playwright() as p:
                browser = await p.chromium.launch()
                page = await browser.new_page()

                try:
                    # --- Phase 1: Reconnaissance & Crawling ---
                    logger.info("Phase 1: Starting Reconnaissance & Crawling...")
                    crawler = Crawler(base_url, http_client, page)
                    attack_surface = await crawler.crawl()
                    scanned_urls = attack_surface["crawled_urls"]
                    logger.info(f"Crawling complete. Found {len(scanned_urls)} unique URLs.")

                    # --- Phase 2: The Attack Arsenal (Concurrent Scanning) ---
                    logger.info("Phase 2: Launching Attack Modules...")
                    
                    # List of all scanner modules to run
                    scanner_modules = [
                        sqli_scanner,
                        xss_scanner,
                        dir_bruteforcer,
                        # port_scanner, # Note: Port scanning can be slow and noisy
                        command_injection_scanner,
                        path_traversal_scanner
                    ]

                    tasks = []
                    # Use a semaphore to limit concurrent requests
                    sem = asyncio.Semaphore(CONCURRENT_REQUESTS)
                    
                    # Domain-based rate limiting
                    rate_limits = {}

                    async def run_module_with_sem(module, url):
                        parsed_url = urlparse(url)
                        domain = parsed_url.netloc
                        if domain not in rate_limits:
                            # Implement tiered rate limiting
                            limit = 20 if "large-site.com" in domain else CONCURRENT_REQUESTS
                            rate_limits[domain] = asyncio.Semaphore(limit)
                        
                        async with rate_limits[domain]:
                            return await module.run(http_client, url, page, scan_id, attack_surface["api_endpoints"], attack_surface["cookies"], attack_surface["headers"]) # Pass page object, scan_id, api_endpoints, cookies, and headers here

                    for module in scanner_modules:
                        # Each module will scan all discovered URLs
                        for url in scanned_urls:
                            task = run_module_with_sem(module, url)
                            tasks.append(task)

                    # Wait for all scanner tasks to complete
                    scan_results = asyncio.run(asyncio.gather(*tasks, return_exceptions=True))

                    # Process results
                    for result in scan_results:
                        if isinstance(result, Exception):
                            logger.error(f"An error occurred in a scanner module: {result}", exc_info=True)
                        elif result: # If the module returned any vulnerabilities
                            vulnerabilities.extend(result)
                    
                finally:
                    await browser.close()

        # Save vulnerabilities to database
        for vuln_data in vulnerabilities:
            vulnerability = Vulnerability(
                scan_id=scan_id,
                title=vuln_data.get("type", "Unknown"),
                description=vuln_data.get("description", ""),
                severity=vuln_data.get("severity", "Info"),
                url=vuln_data.get("url", ""),
                payload=vuln_data.get("payload")
            )
            db.add(vulnerability)
        db.commit()

        # Generate the report
        report_path = os.path.join(REPORTS_DIR, f"CyberScythe_Report_{scan_id}.pdf")
        generate_pdf_report(base_url, vulnerabilities, report_path)
        
        # Update scan status and report path
        scan.status = "completed"
        scan.report_path = report_path
        db.commit()

    except Exception as e:
        logger.error(f"[{scan_id}] An unexpected error occurred during scan: {e}", exc_info=True)
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if scan:
            scan.status = "failed"
            db.commit()
    finally:
        db.close()