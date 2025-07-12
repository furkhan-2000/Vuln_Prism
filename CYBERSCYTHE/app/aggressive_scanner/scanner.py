import asyncio
from urllib.parse import urlparse, parse_qs, urlunparse, urljoin
from utils import is_blacklisted, reliable_request
from payloads import (
    polymorphic_xss_payload,
    polymorphic_sqli_payload,
    polymorphic_cmd_injection_payload,
    polymorphic_path_traversal_payload
)
from detectors import (
    detect_xss,
    detect_sqli,
    detect_cmd_injection,
    detect_path_traversal,
    detect_info_disclosure
)
from config import settings
from selectolax.parser import HTMLParser
import httpx
from loguru import logger
from typing import List, Dict, Any

class ScanResult:
    def __init__(self):
        self.vulnerabilities: List[Dict[str, Any]] = []
        self.scanned_urls: int = 0
        self.vuln_count: int = 0
        self.error_count: int = 0

    def add_vulnerability(self, url: str, vuln_type: str, param: str, payload: str):
        self.vulnerabilities.append({
            'url': url,
            'type': vuln_type,
            'param': param,
            'payload': payload
        })
        self.vuln_count += 1
        logger.critical(f"VULNERABILITY: {vuln_type} at {url} in param '{param}'")

    def report(self):
        logger.info("\n=== SCAN REPORT ===")
        logger.info(f"Scanned URLs: {self.scanned_urls}")
        logger.info(f"Vulnerabilities found: {self.vuln_count}")
        logger.info(f"Errors encountered: {self.error_count}")
        
        for vuln in self.vulnerabilities:
            logger.info(
                f"[{vuln['type']}] {vuln['url']} "
                f"Parameter: {vuln['param']} "
                f"Payload: {vuln['payload']}"
            )

async def extract_forms(html: str, base_url: str) -> list:
    if not html:
        return []
        
    try:
        tree = HTMLParser(html)
    except Exception as e:
        logger.error(f"Form extraction error: {e}")
        return []
        
    forms = []
    for form in tree.css('form'):
        form_details = {
            'action': form.attributes.get('action') or base_url,
            'method': form.attributes.get('method', 'get').lower(),
            'inputs': {}
        }
        
        for input_tag in form.css('input, textarea, select'):
            name = input_tag.attributes.get('name')
            if not name:
                continue
                
            value = input_tag.attributes.get('value', '')
            form_details['inputs'][name] = value
            
        forms.append(form_details)
        
    return forms

async def test_parameter(client: httpx.AsyncClient, result: ScanResult, 
                         url: str, param: str, method: str = 'GET') -> bool:
    try:
        parsed = urlparse(url)
        base_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, '', '', ''))
        orig_params = parse_qs(parsed.query)
        orig_params = {k: v[0] for k, v in orig_params.items()}
        
        test_cases = [
            (polymorphic_xss_payload, detect_xss, "XSS"),
            (polymorphic_sqli_payload, detect_sqli, "SQLi"),
            (polymorphic_cmd_injection_payload, detect_cmd_injection, "CMD Injection"),
            (polymorphic_path_traversal_payload, detect_path_traversal, "Path Traversal")
        ]
        
        for payload_func, detect_func, vuln_type in test_cases:
            payload = payload_func()
            test_params = orig_params.copy()
            test_params[param] = payload
            
            response = await reliable_request(
                client, 
                method, 
                base_url,
                params=test_params if method == 'GET' else None,
                data=test_params if method == 'POST' else None
            )
            
            if not response or not response.text:
                continue
                
            if detect_func(response.text, payload if vuln_type == "XSS" else None):
                result.add_vulnerability(url, vuln_type, param, payload)
                
            if detect_info_disclosure(response.text):
                result.add_vulnerability(url, "Info Disclosure", param, payload)
                
        return True
    except Exception as e:
        logger.error(f"Parameter test error: {e}")
        result.error_count += 1
        return False

async def test_form(client: httpx.AsyncClient, result: ScanResult, 
                    form: dict, base_url: str) -> bool:
    try:
        method = form.get('method', 'get').upper()
        action = form.get('action') or base_url
        action = urljoin(base_url, action)
        
        if is_blacklisted(action):
            return False
            
        for param in form.get('inputs', {}):
            await test_parameter(client, result, action, param, method)
            
        return True
    except Exception as e:
        logger.error(f"Form test error: {e}")
        result.error_count += 1
        return False

async def scan_url(client: httpx.AsyncClient, result: ScanResult, url: str):
    if is_blacklisted(url):
        return
        
    result.scanned_urls += 1
    logger.info(f"Scanning URL: {url}")
    
    try:
        response = await reliable_request(client, "GET", url)
        if not response or not response.text:
            return
            
        parsed = urlparse(url)
        if parsed.query:
            params = parse_qs(parsed.query)
            for param in params:
                await test_parameter(client, result, url, param, 'GET')
                
        forms = await extract_forms(response.text, url)
        for form in forms:
            await test_form(client, result, form, url)
            
        if detect_info_disclosure(response.text):
            result.add_vulnerability(url, "Info Disclosure", "Page Content", "N/A")
            
    except Exception as e:
        logger.error(f"URL scan error: {e}")
        result.error_count += 1

async def aggressive_scan_whole_site(urls: List[str], client: httpx.AsyncClient) -> ScanResult:
    result = ScanResult()
    
    semaphore = asyncio.Semaphore(settings.max_concurrent_requests)
    
    async def limited_scan(url: str):
        async with semaphore:
            await scan_url(client, result, url)
    
    tasks = [limited_scan(url) for url in urls]
    await asyncio.gather(*tasks)
    
    result.report()
    return result

async def full_scan(base_url: str) -> ScanResult:
    from .crawler import AsyncCrawler
    from .utils import create_http_client
    
    async with create_http_client() as client:
        # Crawl first
        crawler = AsyncCrawler(base_url, client)
        urls = await crawler.crawl()
        
        if not urls:
            logger.warning("No URLs found during crawling")
            return ScanResult()
        
        # Then scan
        return await aggressive_scan_whole_site(urls, client)
