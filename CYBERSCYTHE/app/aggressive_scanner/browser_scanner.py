import asyncio
import random
import re
import math
import numpy as np
from playwright.async_api import async_playwright
from fake_useragent import UserAgent
from loguru import logger
import httpx

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
    check_basic_xss,
    check_insecure_forms,
    check_sensitive_file_exposure,
    check_insecure_cookies,
    check_cors_misconfiguration
)
from .scanner import ScanResult

# --- Enhanced Cubic Bezier with adaptive curvature ---
def bezier(t, p0, p1, p2, p3):
    return (
        (1 - t) ** 3 * p0 +
        3 * (1 - t) ** 2 * t * p1 +
        3 * (1 - t) * t ** 2 * p2 +
        t ** 3 * p3
    )

def generate_control_points(start_x, start_y, end_x, end_y):
    # Add nonlinearity to mouse paths
    curvature = random.choice([
        ('sigmoid', 3.5),
        ('parabolic', 1.8),
        ('logistic', 2.2)
    ])

    mid_x = (start_x + end_x) / 2
    mid_y = (start_y + end_y) / 2

    # Apply curvature transform
    if curvature[0] == 'sigmoid':
        mid_x += 120 * math.sin(curvature[1] * (mid_x/1920))
        mid_y += 80 * math.cos(curvature[1] * (mid_y/1080))
    elif curvature[0] == 'parabolic':
        mid_x += 100 * (mid_x/1920)**curvature[1]
        mid_y += 60 * (mid_y/1080)**curvature[1]

    cp1 = (mid_x + random.randint(-200, 200), mid_y + random.randint(-150, 150))
    cp2 = (mid_x + random.randint(-200, 200), mid_y + random.randint(-150, 150))
    return cp1, cp2

# --- Mouse movement with neural jitter simulation ---
async def human_like_mouse_move(page, start_x, start_y, end_x, end_y):
    cp1, cp2 = generate_control_points(start_x, start_y, end_x, end_y)
    steps = random.randint(30, 60)

    # Generate jitter pattern with momentum decay
    jitter_x = np.cumsum(np.random.normal(0, 1.8, steps + 1))
    jitter_y = np.cumsum(np.random.normal(0, 1.5, steps + 1))
    jitter_x *= np.linspace(1, 0.1, steps + 1)
    jitter_y *= np.linspace(1, 0.1, steps + 1)

    for i in range(steps + 1):
        t = i / steps
        x = bezier(t, start_x, cp1[0], cp2[0], end_x) + jitter_x[i]
        y = bezier(t, start_y, cp1[1], cp2[1], end_y) + jitter_y[i]
        await page.mouse.move(x, y)

        # Dynamic speed modeling (accelerate->decelerate)
        speed_factor = 0.02 * math.sin(math.pi * t) + 0.01
        await asyncio.sleep(random.uniform(0.005, 0.03) * speed_factor)

# --- Typing with biometric rhythm simulation ---
async def human_like_type(element, text, user_profile="expert"):
    # Typing profiles (words per minute)
    profiles = {
        "novice": (45, 0.25, 0.15),
        "average": (70, 0.12, 0.08),
        "expert": (120, 0.06, 0.04)
    }
    wpm, typo_chance, pause_factor = profiles[user_profile]

    # Simulate muscle memory patterns
    common_errors = {
        'a': 'qsz', 'e': 'rdw', 'i': 'uko', 'o': 'ipl', 't': 'rgy',
        'n': 'bhjm', 's': 'adwxz', 'r': 'edft'
    }

    words = text.split()
    for i, word in enumerate(words):
        # Burst typing with fatigue simulation
        burst_length = max(1, int(len(word) * (0.3 + random.random()*0.5)))
        for j, char in enumerate(word):
            # Error injection based on common mistypes
            if (j > 0 and random.random() < typo_chance and
                char in common_errors and
                random.random() > 0.7):

                typo_char = random.choice(common_errors[char])
                await element.type(typo_char)
                await asyncio.sleep(random.uniform(0.04, 0.12))
                await element.press('Backspace')
                await asyncio.sleep(random.uniform(0.03, 0.09))

            await element.type(char)

            # Simulate typing rhythm with Gaussian distribution
            base_delay = 60/(wpm*5)  # Average seconds per character
            delay = max(0.01, random.gauss(base_delay, base_delay/3))
            await asyncio.sleep(delay * (1 + (j/burst_length)*0.5))

        # Inter-word behavior
        if i < len(words) - 1:
            await element.type(' ')

            # Cognitive pause modeling
            pause = random.gauss(0.25, 0.1) * pause_factor * len(word)
            await asyncio.sleep(max(0.1, pause))

            # 40% chance of micro-corrections
            if random.random() < 0.4 and recursion_depth < 3: # Added recursion limit
                corrections = random.randint(1, min(3, len(word)))
                for _ in range(corrections):
                    await element.press('Backspace')
                    await asyncio.sleep(0.05)
                await human_like_type(element, word[-corrections:], user_profile, recursion_depth + 1)

# --- Advanced human behavior with strategic patterns ---
async def simulate_human_behavior(page, aggression_level=3):
    # Aggression levels: 1=stealthy, 3=aggressive, 5=combative
    viewport_width = await page.evaluate("window.innerWidth")
    viewport_height = await page.evaluate("window.innerHeight")

    # Strategic scrolling patterns
    scroll_patterns = [
        (0, random.randint(300, 700)),  # Downward
        (0, random.randint(-400, -200)),  # Upward
        (random.randint(-200, 200), random.randint(100, 300))  # Diagonal
    ]

    for _ in range(aggression_level + random.randint(1, 3)):
        dx, dy = random.choice(scroll_patterns)
        await page.mouse.wheel(dx, dy)
        await asyncio.sleep(random.uniform(0.3, 1.2))

    # Target acquisition simulation
    if aggression_level > 2:
        # Scan page elements like human eye movement
        elements = await page.query_selector_all('a, button, input')
        if elements:
            for _ in range(min(aggression_level, len(elements))):
                target = random.choice(elements)
                box = await target.bounding_box()
                if box:
                    await human_like_mouse_move(
                        page,
                        random.randint(0, viewport_width),
                        random.randint(0, viewport_height),
                        box['x'] + box['width']/2,
                        box['y'] + box['height']/2
                    )
                    if aggression_level > 3 and random.random() > 0.6:
                        await page.mouse.down()
                        await asyncio.sleep(random.uniform(0.1, 0.3))
                        await page.mouse.up()
                    await asyncio.sleep(random.uniform(0.15, 0.4))

# --- Browser fingerprint warfare system ---
async def create_stealth_context(browser, proxy=None):
    ua = UserAgent(browsers=['chrome', 'edge', 'safari'], os=['windows', 'macos', 'linux'])
    context = await browser.new_context(
        viewport={'width': random.choice([1366, 1920, 1440, 1536]),
                 'height': random.choice([768, 1080, 900, 864])},
        locale=random.choice(['en-US', 'en-GB', 'en-CA', 'en-AU']),
        timezone_id=random.choice([
            'America/New_York',
            'Europe/London',
            'Asia/Tokyo',
            'Australia/Sydney'
        ]),
        user_agent=ua.random,
        proxy=proxy,
        # Nuclear fingerprint spoofing
        color_scheme='dark' if random.random() > 0.7 else 'light',
        reduced_motion='reduce' if random.random() > 0.8 else 'no-preference'
    )

    # Advanced evasion techniques
    await context.add_init_script("""
    delete navigator.__proto__.webdriver;
    window.chrome = {runtime: {}};
    Object.defineProperty(navigator, 'plugins', {
        get: () => [1, 2, 3],
    });
    Object.defineProperty(navigator, 'languages', {
        get: () => ['en-US', 'en'],
    });
    """)

    # Resource warfare: block trackers and heavy assets
    await context.route(re.compile(r".*\.(png|jpg|jpeg|webp|gif|svg|mp4|woff2?)$"), lambda route: route.abort())
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
