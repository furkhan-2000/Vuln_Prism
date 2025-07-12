import asyncio
from typing import List, Dict, Any
from loguru import logger

class ScanResult:
    def __init__(self):
        self.vulnerabilities: List[Dict[str, Any]] = []
        self.scanned_urls: int = 0
        self.vuln_count: int = 0
        self.error_count: int = 0

    def add_vulnerability(self, url: str, vuln_type: str, param: str, payload: str):
        # Avoid adding duplicate vulnerabilities
        vuln_signature = (url, vuln_type, param)
        if not any(v['signature'] == vuln_signature for v in self.vulnerabilities):
            self.vulnerabilities.append({
                'url': url,
                'type': vuln_type,
                'param': param,
                'payload': payload,
                'signature': vuln_signature # Internal signature for deduplication
            })
            self.vuln_count += 1
            logger.critical(f"VULNERABILITY: {vuln_type} at {url} in param '{param}'")

    def to_dict(self):
        # Exclude the internal signature from the final report
        reported_vulns = [{k: v for k, v in vuln.items() if k != 'signature'} for vuln in self.vulnerabilities]
        return {
            'url': getattr(self, 'url', 'N/A'),
            'title': getattr(self, 'title', 'N/A'),
            'vulnerabilities': reported_vulns,
            'scanned_urls': self.scanned_urls,
            'vuln_count': self.vuln_count,
            'error_count': self.error_count
        }

    def report(self):
        logger.info("
=== SCAN REPORT ===")
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
    """Initiates and runs the full scan against the target URL."""
    # Late import to prevent circular dependency issues
    from .browser_scanner import aggressive_run

    scan_result = ScanResult()
    
    # The main logic is now consolidated in aggressive_run
    await aggressive_run(url, scan_result)
    
    scan_result.report() # Log the final report to the console
    return scan_result

