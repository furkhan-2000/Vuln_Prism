import asyncio
from urllib.parse import urlparse, parse_qs, urlunparse, urljoin
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
    detect_info_disclosure
)
from .browser_scanner import aggressive_run
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
    scan_result = ScanResult()
    await aggressive_run(url, scan_result)
    return scan_result