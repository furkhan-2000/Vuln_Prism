import asyncio
from urllib.parse import urlparse, urldefrag
from selectolax.parser import HTMLParser
from .config import settings
from .utils import normalize_url, is_same_domain, is_blacklisted, reliable_request
from loguru import logger
import httpx
from typing import Optional, List, Dict, Any

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

    def to_dict(self):
        return {
            'url': getattr(self, 'url', 'N/A'),
            'title': getattr(self, 'title', 'N/A'),
            'vulnerabilities': self.vulnerabilities,
            'scanned_urls': self.scanned_urls,
            'vuln_count': self.vuln_count,
            'error_count': self.error_count
        }

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

async def perform_scan(url: str) -> ScanResult:
    # Delay import to avoid circular dependency
    from .browser_scanner import aggressive_run

    scan_result = ScanResult()
    await aggressive_run(url, scan_result)
    return scan_result

class AsyncCrawler:
    def __init__(self, base_url: str, client: httpx.AsyncClient):
        self.base_url = base_url
        self.parsed_base = urlparse(base_url)
        self.visited = set()
        self.to_visit = asyncio.Queue()
        self.to_visit.put_nowait((base_url, 0))
        self.semaphore = asyncio.Semaphore(settings.max_concurrent_requests)
        self.found_urls = set()
        self.client = client
        self.crawl_stats = {
            'total': 0,
            'success': 0,
            'failed': 0,
            'blacklisted': 0
        }

    async def fetch(self, url: str) -> Optional[httpx.Response]:
        async with self.semaphore:
            try:
                response = await reliable_request(self.client, "GET", url)
                if response and response.status_code == 200:
                    self.crawl_stats['success'] += 1
                    return response
                else:
                    self.crawl_stats['failed'] += 1
            except Exception as e:
                logger.error(f"Fetch error for {url}: {e}")
                self.crawl_stats['failed'] += 1
            return None

    def extract_links(self, html: str, current_url: str) -> set:
        if not html:
            return set()

        try:
            tree = HTMLParser(html)
        except Exception as e:
            logger.error(f"HTML parsing error for {current_url}: {e}")
            return set()

        links = set()
        selectors = [
            ('a', 'href'),
            ('form', 'action'),
            ('iframe', 'src'),
            ('frame', 'src'),
            ('link[rel="stylesheet"]', 'href'),
            ('script', 'src'),
            ('meta[http-equiv="refresh"]', 'content')
        ]

        for tag, attr in selectors:
            for node in tree.css(tag):
                link = node.attributes.get(attr)
                if not link:
                    continue
                if tag == 'meta' and 'refresh' in node.attributes.get('http-equiv', '').lower():
                    if 'url=' in link:
                        link = link.split('url=', 1)[1]
                full_url = normalize_url(current_url, link)
                if is_blacklisted(full_url):
                    self.crawl_stats['blacklisted'] += 1
                    continue
                if is_same_domain(self.base_url, full_url):
                    links.add(full_url)

        return links

    async def worker(self):
        while True:
            try:
                url, depth = await asyncio.wait_for(self.to_visit.get(), timeout=30)
                if url in self.visited or depth > settings.max_crawl_depth:
                    self.to_visit.task_done()
                    continue

                self.visited.add(url)
                self.crawl_stats['total'] += 1

                response = await self.fetch(url)
                if not response or not response.text:
                    self.to_visit.task_done()
                    continue

                links = self.extract_links(response.text, url)
                for link in links:
                    if link not in self.visited and link not in self.found_urls:
                        self.found_urls.add(link)
                        await self.to_visit.put((link, depth + 1))

                logger.debug(f"Crawled: {url} | Depth: {depth} | Found: {len(links)}")
            except asyncio.TimeoutError:
                logger.info("Worker timeout, exiting")
                break
            except Exception as e:
                logger.error(f"Worker error: {e}")
            finally:
                self.to_visit.task_done()

    async def crawl(self) -> List[str]:
        workers = [
            asyncio.create_task(self.worker())
            for _ in range(settings.max_concurrent_requests)
        ]

        await self.to_visit.join()
        for w in workers:
            w.cancel()
        await asyncio.gather(*workers, return_exceptions=True)

        stats = (
            f"Crawl completed: Total={self.crawl_stats['total']} "
            f"Success={self.crawl_stats['success']} "
            f"Failed={self.crawl_stats['failed']} "
            f"Blacklisted={self.crawl_stats['blacklisted']}"
        )
        logger.info(stats)
        return list(self.visited)

