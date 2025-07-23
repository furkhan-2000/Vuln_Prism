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
        """Add a vulnerability with comprehensive error handling and logging"""
        try:
            logger.debug(f"🔍 Adding vulnerability: {vuln_type} at {url} in param '{param}'")

            # Create vulnerability signature for deduplication
            vuln_signature = (url, vuln_type, param)

            # Check for duplicates with safe access
            is_duplicate = False
            try:
                is_duplicate = any(
                    v.get('signature') == vuln_signature
                    for v in self.vulnerabilities
                    if isinstance(v, dict) and 'signature' in v
                )
            except Exception as e:
                logger.warning(f"⚠️ Error checking for duplicates: {e}")
                is_duplicate = False

            if not is_duplicate:
                vulnerability = {
                    'url': url,
                    'type': vuln_type,
                    'param': param,
                    'payload': payload,
                    'signature': vuln_signature,
                    'severity': self._determine_severity(vuln_type)
                }

                self.vulnerabilities.append(vulnerability)
                self.vuln_count += 1
                logger.critical(f"🚨 VULNERABILITY FOUND: {vuln_type} at {url} in param '{param}' | Total: {self.vuln_count}")
            else:
                logger.debug(f"🔄 Duplicate vulnerability skipped: {vuln_type} at {url}")

        except Exception as e:
            logger.error(f"❌ Error adding vulnerability: {e}")
            self.add_error(f"Failed to add vulnerability: {str(e)}")

    def _determine_severity(self, vuln_type: str) -> str:
        """Determine severity based on vulnerability type"""
        try:
            high_severity = ['XSS', 'SQL Injection', 'Command Injection', 'Path Traversal']
            medium_severity = ['Missing Security Headers', 'CORS Misconfiguration', 'Insecure Cookies']

            if vuln_type in high_severity:
                return 'High'
            elif vuln_type in medium_severity:
                return 'Medium'
            else:
                return 'Low'
        except Exception as e:
            logger.error(f"❌ Error determining severity: {e}")
            return 'Unknown'

    def add_error(self, error_message: str = ""):
        """Add an error to the scan results with comprehensive logging"""
        try:
            self.error_count += 1
            logger.error(f"❌ ERROR #{self.error_count}: {error_message}")
        except Exception as e:
            logger.critical(f"💥 CRITICAL: Failed to log error: {e}")

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
    """Initiates and runs the full scan against the target URL with comprehensive error handling."""
    import traceback
    # Late import to prevent circular dependency issues
    from .browser_scanner import aggressive_run

    scan_result = ScanResult()

    try:
        logger.info(f"🚀 Starting comprehensive scan for: {url}")
        # The main logic is now consolidated in aggressive_run
        await aggressive_run(url, scan_result)
        logger.info(f"✅ Scan completed for {url} - Found {scan_result.vuln_count} vulnerabilities, {scan_result.error_count} errors")
    except Exception as e:
        error_msg = f"Critical scan failure for {url}: {str(e)}"
        logger.error(f"❌ {error_msg}")
        logger.error(f"📍 Full traceback: {traceback.format_exc()}")
        scan_result.add_error(error_msg)

    scan_result.report() # Log the final report to the console
    return scan_result