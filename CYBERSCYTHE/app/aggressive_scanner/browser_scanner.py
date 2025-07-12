import asyncio
import random
import re
import math
import numpy as np
from playwright.async_api import async_playwright, Error as PlaywrightError
from loguru import logger
from selectolax.parser import HTMLParser

from .payloads import (
    polymorphic_xss_payload,
    polymorphic_sqli_payload,
    polymorphic_cmd_injection_payload,
    polymorphic_path_traversal_payload
)
from .detectors import (
    detect_xss,
    detect_sqli,
    detect_cmd_injection,
    detect_path_traversal,
    detect_info_disclosure,
    check_security_headers,
    check_exposed_api_keys,
    check_outdated_software,
    check_directory_listing,
    check_common_misconfigurations,
    check_insecure_forms,
    check_sensitive_file_exposure,
    check_insecure_cookies,
    check_cors_misconfiguration
)
from .scanner import ScanResult
from .config import settings

# --- Human-like Interaction Simulation ---

async def human_like_mouse_move(page, element):
    """Simulates a more natural mouse movement towards an element."""
    try:
        box = await element.bounding_box()
        if not box:
            return

        start_x, start_y = await page.evaluate("() => [window.scrollX, window.scrollY]")
        end_x = box['x'] + box['width'] / 2
        end_y = box['y'] + box['height'] / 2

        steps = random.randint(15, 30)
        for i in range(steps + 1):
            t = i / steps
            # Simple ease-in-out curve
            t = t * t * (3 - 2 * t)
            x = start_x + (end_x - start_x) * t + random.uniform(-5, 5)
            y = start_y + (end_y - start_y) * t + random.uniform(-5, 5)
            await page.mouse.move(x, y)
            await asyncio.sleep(random.uniform(0.001, 0.005))
    except PlaywrightError as e:
        logger.warning(f"Could not perform mouse move: {e}")

async def human_like_type(element, text):
    """Simulates more natural typing with variable delays."""
    for char in text:
        await element.type(char)
        await asyncio.sleep(random.uniform(0.05, 0.15))

# --- Browser Context and Fingerprint Evasion ---

async def create_stealth_context(browser):
    """Creates a browser context with anti-fingerprinting measures."""
    user_agent = random.choice(settings.user_agents)
    context = await browser.new_context(
        user_agent=user_agent,
        viewport={'width': 1920, 'height': 1080},
        java_script_enabled=True,
        accept_downloads=False,
        ignore_https_errors=True,
        # Spoof some properties to make detection harder
        locale='en-US',
        timezone_id='America/New_York',
        color_scheme='dark',
    )

    # Evasion script to hide webdriver presence
    await context.add_init_script("""
        Object.defineProperty(navigator, 'webdriver', {get: () => undefined});
        Object.defineProperty(window, 'chrome', {get: () => ({ runtime: {} })});
        Object.defineProperty(navigator, 'plugins', {get: () => [1, 2, 3]});
    """)
    return context

# --- Main Scanning Logic ---

async def aggressive_run(url: str, scan_result: ScanResult):
    """The core browser-based scanning engine."""
    async with async_playwright() as p:
        browser = await p.chromium.launch(
            headless=True,
            args=[
                '--no-sandbox',
                '--disable-setuid-sandbox',
                '--disable-dev-shm-usage',
                '--disable-blink-features=AutomationControlled'
            ]
        )
        context = await create_stealth_context(browser)
        page = await context.new_page()

        try:
            logger.info(f"Navigating to {url} for initial analysis.")
            initial_response = await page.goto(url, timeout=60000, wait_until='domcontentloaded')
            
            scan_result.scanned_urls += 1
            html_content = await page.content()
            headers = initial_response.headers
            tree = HTMLParser(html_content)

            # --- Perform Static Analysis First ---
            logger.info(f"Performing static analysis on {url}")
            check_security_headers(headers, scan_result.vulnerabilities)
            check_exposed_api_keys(html_content, scan_result.vulnerabilities)
            check_outdated_software(headers, html_content, scan_result.vulnerabilities)
            check_directory_listing(url, scan_result.vulnerabilities)
            check_common_misconfigurations(url, scan_result.vulnerabilities)
            check_insecure_forms(tree, url, scan_result.vulnerabilities)
            check_sensitive_file_exposure(url, scan_result.vulnerabilities)
            check_insecure_cookies(await context.cookies(), url, scan_result.vulnerabilities)
            check_cors_misconfiguration(headers, scan_result.vulnerabilities)

            # --- Dynamic Injection Testing on Forms ---
            logger.info(f"Starting dynamic form injection for {url}")
            input_elements = await page.query_selector_all('input:not([type="submit"]):not([type="button"]):not([type="hidden"]), textarea')

            for element in input_elements:
                try:
                    name = await element.get_attribute('name') or await element.get_attribute('id') or 'unnamed'
                    logger.info(f"Testing input field: {name}")

                    test_cases = [
                        (polymorphic_xss_payload, detect_xss, "XSS"),
                        (polymorphic_sqli_payload, detect_sqli, "SQLi"),
                        (polymorphic_cmd_injection_payload, detect_cmd_injection, "CMD Injection"),
                        (polymorphic_path_traversal_payload, detect_path_traversal, "Path Traversal")
                    ]

                    for payload_func, detect_func, vuln_type in test_cases:
                        payload = payload_func()
                        
                        await human_like_mouse_move(page, element)
                        await element.fill('') # Clear field before typing
                        await human_like_type(element, payload)
                        await asyncio.sleep(0.5) # Wait for any potential JS validation

                        # Check for vulnerabilities without submitting the form (for DOM-based issues)
                        current_content = await page.content()
                        if detect_func(current_content, payload if vuln_type == "XSS" else None):
                            scan_result.add_vulnerability(url, vuln_type, f"{name} (pre-submit)", payload)

                        # Try to submit the form to check for server-side vulnerabilities
                        await element.press('Enter')
                        await page.wait_for_timeout(2000) # Wait for navigation/response

                        response_text = await page.content()
                        if detect_func(response_text, payload if vuln_type == "XSS" else None):
                            scan_result.add_vulnerability(url, vuln_type, name, payload)
                        
                        if detect_info_disclosure(response_text):
                            scan_result.add_vulnerability(url, "Info Disclosure", name, payload)

                        # Navigate back if submission caused a redirect
                        if page.url != url:
                            await page.goto(url, wait_until='domcontentloaded')

                except PlaywrightError as e:
                    logger.warning(f"Error interacting with an input element: {e}")
                    scan_result.error_count += 1

            logger.info(f"Browser scan complete for {url}")

        except PlaywrightError as e:
            logger.error(f"A Playwright error occurred during the browser scan for {url}: {e}")
            scan_result.error_count += 1
        except Exception as e:
            logger.exception(f"An unexpected error occurred during the browser scan for {url}: {e}")
            scan_result.error_count += 1
        finally:
            await context.close()
            await browser.close()), lambda route: route.abort())
    await context.route(re.compile(r".*(google|facebook|twitter|analytics|track|pixel|ads|beacon)\.\w{2,}"), lambda route: route.abort())

    return context

# --- CAPTCHA stormbreaker module ---
async def break_captcha(page):
    if await page.query_selector('iframe[src*="recaptcha"]'):
        logger.info("Detected reCAPTCHA - deploying countermeasures")
        # 1. Audio challenge bypass
        await page.evaluate('''async () => {
            const iframes = document.querySelectorAll('iframe');
            for (const iframe of iframes) {
                if (iframe.src.includes('recaptcha')) {
                    const newIframe = document.createElement('iframe');
                    newIframe.srcdoc = '<html><head></head><body>Bypassed</body></html>';
                    iframe.parentNode.replaceChild(newIframe, iframe);
                }
            }
        }''')
        await asyncio.sleep(1)

        # 2. Behavioral override
        await page.keyboard.press('Tab', delay=100)
        await page.keyboard.press('Space', delay=100)
        await asyncio.sleep(2)

        # 3. Nuclear option (if still visible)
        if await page.query_selector('div.recaptcha-challenge'):
            await page.evaluate('document.querySelector("div.recaptcha-challenge").style.display = "none"')

    return True

# --- Main assault engine ---
async def aggressive_run(url: str, scan_result: ScanResult, aggression_level=3):
    async with async_playwright() as p:
        # Configure browser for maximum penetration
        browser = await p.chromium.launch(
            headless=True,
            args=[
                '--no-sandbox',
                '--disable-setuid-sandbox',
                '--disable-dev-shm-usage',
                '--disable-blink-features=AutomationControlled',
                '--disable-web-security',
                '--disable-features=IsolateOrigins,site-per-process',
                '--disable-site-isolation-trials',
                '--disable-infobars',
                f'--window-size={random.randint(1200,1920)},{random.randint(800,1080)}'
            ]
        )

        context = await create_stealth_context(browser)
        page = await context.new_page()

        try:
            await page.goto(url, timeout=60000, wait_until=random.choice(['domcontentloaded', 'load', 'networkidle']))
        except Exception as e:
            logger.error(f"Failed to navigate to {url}: {e}")
            scan_result.error_count += 1
            await browser.close()
            return

            logger.info(f"Starting scan for {url}")
            await simulate_human_behavior(page, aggression_level)
            await break_captcha(page) # Attempt to break CAPTCHA

            scan_result.scanned_urls += 1
            logger.info(f"Browser scanning URL: {url}")

            # --- Static and Dynamic Vulnerability Checks ---
            # Get initial response headers for header-based checks
            initial_response = await page.request.get(url)
            headers = initial_response.headers

            # Get HTML content for content-based checks
            html_content = await page.content()
            tree = HTMLParser(html_content)

            check_security_headers(headers, scan_result.vulnerabilities)
            check_exposed_api_keys(html_content, scan_result.vulnerabilities)
            check_outdated_software(headers, html_content, scan_result.vulnerabilities)
            check_directory_listing(url, scan_result.vulnerabilities)
            check_common_misconfigurations(url, scan_result.vulnerabilities)
            check_basic_xss(url, html_content, scan_result.vulnerabilities)
            check_insecure_forms(tree, url, scan_result.vulnerabilities)
            check_sensitive_file_exposure(url, scan_result.vulnerabilities)
            check_insecure_cookies(await page.context.cookies(), url, scan_result.vulnerabilities)
            check_cors_misconfiguration(headers, scan_result.vulnerabilities)

            # --- Dynamic Interaction and Vulnerability Testing ---

            # Find all input fields and textareas
            input_elements = await page.query_selector_all('input:not([type="submit"]):not([type="button"]):not([type="hidden"]), textarea')

            for element in input_elements:
                try:
                    name = await element.get_attribute('name') or await element.get_attribute('id')
                    if not name:
                        logger.warning(f"Found an input element without a name or id. Skipping.")
                        continue

                    logger.info(f"Testing input field: {name}")
                    test_cases = [
                        (polymorphic_xss_payload, detect_xss, "XSS"),
                        (polymorphic_sqli_payload, detect_sqli, "SQLi"),
                        (polymorphic_cmd_injection_payload, detect_cmd_injection, "CMD Injection"),
                        (polymorphic_path_traversal_payload, detect_path_traversal, "Path Traversal")
                    ]

                    for payload_func, detect_func, vuln_type in test_cases:
                        payload = payload_func()

                        # Type payload into the field
                        await element.fill(payload)
                        await asyncio.sleep(random.uniform(0.1, 0.5)) # Human-like typing delay

                        # Get current page content after typing
                        response_text = await page.content()

                        if detect_func(response_text, payload if vuln_type == "XSS" else None):
                            scan_result.add_vulnerability(url, vuln_type, name, payload)

                        if detect_info_disclosure(response_text):
                            scan_result.add_vulnerability(url, "Info Disclosure", name, payload)

                        # Clear the field for the next payload
                        await element.fill("")
                        await asyncio.sleep(random.uniform(0.1, 0.3))

                except Exception as e:
                    logger.exception(f"Error typing into input: {e}")
                    scan_result.error_count += 1

            # Check for info disclosure on the page itself
            response_text = await page.content()
            if detect_info_disclosure(response_text):
                scan_result.add_vulnerability(url, "Info Disclosure", "Page Content", "N/A")

            logger.info(f"Browser scan complete for {url}")

        except Exception as e:
            logger.exception(f"Browser scan failed for {url}: {e}")
            scan_result.error_count += 1
        finally:
            await context.clear_cookies()
            await browser.close()

# --- Battlefield commander (for testing, not used in main scanner flow) ---
if __name__ == "__main__":
    async def test_run():
        # Create a dummy ScanResult for testing
        class DummyScanResult:
            def __init__(self):
                self.vulnerabilities = []
                self.scanned_urls = 0
                self.vuln_count = 0
                self.error_count = 0
            def add_vulnerability(self, url, vuln_type, param, payload):
                logger.critical(f"[VULN] {vuln_type} at {url} in {param} with {payload}")
                self.vulnerabilities.append({'url': url, 'type': vuln_type, 'param': param, 'payload': payload})
                self.vuln_count += 1

        dummy_result = DummyScanResult()
        await aggressive_run("https://www.google.com", dummy_result, aggression_level=3)
        logger.info(f"Total vulnerabilities found: {dummy_result.vuln_count}")

    asyncio.run(test_run())
