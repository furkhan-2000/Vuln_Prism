import logging
import asyncio
import httpx
from urllib.parse import urljoin, urlparse
from collections import deque
from playwright.async_api import async_playwright, TimeoutError as PlaywrightTimeoutError

from celery_app import celery_app
from core.database import SessionLocal, Scan, Vulnerability
from core.reporting import generate_pdf_report

# --- Import Scanner Modules ---
from core.modules import sqli_scanner, xss_scanner, dir_bruteforcer, port_scanner, command_injection_scanner, path_traversal_scanner
from config import DEFAULT_USER_AGENT, MAX_URLS_TO_CRAWL, CONCURRENT_REQUESTS, REPORTS_DIR

logger = logging.getLogger(__name__)

# --- Helper Functions ---
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

# --- Main Scanner Orchestrator ---
@celery_app.task(name="run_scan_task")
def run_scan_task(scan_id: int, base_url: str):
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
        # Use a synchronous httpx client for the Celery task
        # For truly async operations within Celery, you'd use aiohttp or similar
        # and run the async parts with asyncio.run()
        with httpx.Client(timeout=30, follow_redirects=True, headers=headers) as http_client:
            
            # --- Phase 1: Reconnaissance & Crawling ---
            logger.info("Phase 1: Starting Reconnaissance & Crawling...")
            # Note: Playwright is async, so we need to run it in an async loop
            attack_surface = asyncio.run(crawl_and_discover(base_url))
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

            async def run_module_with_sem(module, url):
                async with sem:
                    return await module.run(http_client, url)

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

        logger.info(f"[{scan_id}] Scan finished for: {base_url}. Found {len(vulnerabilities)} potential issues.")

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

async def crawl_and_discover(base_url: str) -> dict:
    """Crawls a website to discover URLs, forms, and parameters."""
    urls_to_scan = deque([normalize_url(base_url)])
    crawled_urls = set()
    attack_surface = {
        "crawled_urls": set(),
        "forms": [],
        "url_params": set()
    }

    async with async_playwright() as p:
        browser = await p.chromium.launch()
        page = await browser.new_page()

        while urls_to_scan and len(crawled_urls) < MAX_URLS_TO_CRAWL:
            current_url = urls_to_scan.popleft()
            if current_url in crawled_urls or not is_same_domain(current_url, base_url):
                continue

            logger.info(f"Crawling: {current_url}")
            crawled_urls.add(current_url)
            attack_surface["crawled_urls"].add(current_url)

            try:
                await page.context.clear_cookies()
                await page.evaluate("() => localStorage.clear()")
                await page.goto(current_url, wait_until="domcontentloaded")
                
                # Discover links
                links = await page.evaluate("Array.from(document.querySelectorAll('a[href]')).map(a => a.href)")
                for link in links:
                    absolute_link = urljoin(base_url, link)
                    normalized_link = normalize_url(absolute_link)
                    if normalized_link not in crawled_urls and is_same_domain(normalized_link, base_url):
                        urls_to_scan.append(normalized_link)

                # Discover forms
                forms_on_page = await page.evaluate('''
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
                    attack_surface["forms"].append({
                        "url": urljoin(current_url, form_data['action']),
                        "method": form_data['method'],
                        "inputs": form_data['inputs']
                    })

                # Discover URL parameters
                if '?' in current_url:
                    attack_surface["url_params"].add(current_url)

                # Also consider form inputs as potential parameters for attack modules
                for form_data in forms_on_page:
                    for input_field in form_data['inputs']:
                        if input_field['name']:
                            # Create a dummy URL to represent the form submission with parameters
                            # This is a simplified representation; actual exploitation would involve POST requests
                            dummy_url = f"{urljoin(current_url, form_data['action'])}?{input_field['name']}=value"
                            attack_surface["url_params"].add(dummy_url)

            except PlaywrightTimeoutError:
                logger.warning(f"Timeout loading {current_url}", exc_info=True)
            except Exception as e:
                logger.error(f"Error crawling {current_url}: {e}", exc_info=True)
        
        await browser.close()

    return attack_surface