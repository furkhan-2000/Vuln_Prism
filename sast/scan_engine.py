import os
import uuid
import subprocess
import json
import logging
import shutil
import time
from pathlib import Path
from typing import List, Dict, Any, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed

import pdf_report
from lxml import etree

logger = logging.getLogger("app.scan_engine")
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")

SEVERITY_MAP = {
    "CRITICAL": "Critical", "HIGH": "High", "MEDIUM": "Medium", "MODERATE": "Medium",
    "LOW": "Low", "INFO": "Info", "INFORMATIONAL": "Info", "NOTE": "Info",
    "WARNING": "Medium", "WARN": "Medium", "ERROR": "High", "FATAL": "Critical",
    "DEFCON1": "Critical", "URGENT": "High", "IMPORTANT": "High",
    "UNKNOWN": "Info"
}

RISK_SCORE_MAP = {"Critical": 10, "High": 8, "Medium": 5, "Low": 2, "Info": 1}

AUTO_FIX_SUGGESTIONS = {
    "sql-injection": "Use parameterized queries.",
    "hardcoded-secret": "Move secrets to environment variables.",
    "xss": "Escape output.",
    "path-traversal": "Sanitize file paths.",
    "insecure-hash": "Use bcrypt or SHA-256.",
    "weak-crypto": "Use AES-256.",
    "command-injection": "Validate shell inputs.",
    "deserialization": "Use safe formats.",
    "xxe": "Disable external entities.",
    "csrf": "Use CSRF tokens.",
    "open-redirect": "Validate redirect targets.",
    "ldap-injection": "Use parameterized LDAP.",
    "regex-dos": "Use safe regex.",
    "timing-attack": "Use constant-time compare.",
    "insufficient-logging": "Improve security logging.",
    "weak-random": "Use secure RNG.",
    "insecure-transport": "Use HTTPS.",
    "privilege-escalation": "Restrict privileges.",
    "race-condition": "Add locking.",
    "buffer-overflow": "Use bounds checks.",
    "integer-overflow": "Validate math.",
    "use-after-free": "Use smart pointers.",
    "null-pointer": "Check for nulls.",
    "uninitialized-variable": "Initialize variables.",
    "dead-code": "Remove unused code.",
    "hardcoded-credential": "Use secrets manager."
}

def validate_source_directory(source_path: str) -> Dict[str, Any]:
    if not os.path.exists(source_path):
        raise Exception(f"Source path does not exist: {source_path}")
    if not os.path.isdir(source_path):
        raise Exception(f"Source path is not a directory: {source_path}")

    file_count, total_size, extensions = 0, 0, set()
    for root, _, files in os.walk(source_path):
        for file in files:
            path = os.path.join(root, file)
            try:
                stat = os.stat(path)
                file_count += 1
                total_size += stat.st_size
                ext = Path(file).suffix.lower()
                if ext:
                    extensions.add(ext)
            except:
                continue
    return {
        "file_count": file_count,
        "total_size": total_size,
        "extensions": extensions,
        "has_code": bool(extensions & {'.py', '.js', '.java', '.cpp', '.c', '.cs', '.rb', '.php', '.go', '.rs', '.ts', '.jsx', '.tsx'})
    }

def run_tool_with_retry(name: str, cmd: List[str], output_path: str,
                        timeout: int = 600, retries: int = 2) -> bool:
    is_xml = output_path.lower().endswith(".xml")
    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    for attempt in range(retries + 1):
        try:
            logger.info("Running %s (attempt %d/%d): %s", name, attempt + 1, retries + 1, " ".join(cmd))
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)

            logger.info("%s exit code %d", name, result.returncode)
            logger.info("%s STDOUT (first 500): %s", name, result.stdout[:500])
            logger.info("%s STDERR (first 500): %s", name, result.stderr[:500])

            if name.lower() == "semgrep" and result.returncode == 7:
                logger.info("%s finished with no findings.", name)
                return True

            if result.stdout:
                with open(output_path, "w", encoding="utf-8") as f:
                    f.write(result.stdout)
            elif is_xml and result.stderr: # If XML is expected but stdout is empty, check stderr
                with open(output_path, "w", encoding="utf-8") as f:
                    f.write(result.stderr)

            if is_xml:
                if os.path.exists(output_path) and os.path.getsize(output_path) > 0: # Ensure file exists and is not empty
                    return True
            else:
                if os.path.exists(output_path) and os.path.getsize(output_path) > 0:
                    return True

            logger.warning("%s produced no valid output on attempt %d.", name, attempt + 1)

        except subprocess.TimeoutExpired:
            logger.error("%s timed out on attempt %d.", name, attempt + 1)

        time.sleep(2 ** attempt)

    logger.error("%s failed after %d attempts.", name, retries + 1)
    return False

def parse_semgrep(path):
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        issues = []
        for finding in data.get("results", []):
            sev = SEVERITY_MAP.get(finding.get("extra", {}).get("severity", "INFO").upper(), "Info")
            issues.append({
                "rule": finding.get("check_id"),
                "desc": finding.get("extra", {}).get("message"),
                "impact": finding.get("path"),
                "fix": AUTO_FIX_SUGGESTIONS.get(finding.get("check_id"), "Review manually."),
                "file": finding.get("path"),
                "line": finding.get("start", {}).get("line"),
                "severity": sev,
                "risk_score": RISK_SCORE_MAP.get(sev, 1)
            })
        return issues
    except Exception as e:
        logger.error("Error parsing Semgrep output: %s", e, exc_info=True)
        return []

def parse_bandit(path):
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        issues = []
        for finding in data.get("results", []):
            sev = SEVERITY_MAP.get(finding.get("issue_severity", "LOW").upper(), "Low")
            issues.append({
                "rule": finding.get("test_id"),
                "desc": finding.get("issue_text"),
                "impact": finding.get("issue_confidence"),
                "fix": AUTO_FIX_SUGGESTIONS.get(finding.get("test_name"), "Review manually."),
                "file": finding.get("filename"),
                "line": finding.get("line_number"),
                "severity": sev,
                "risk_score": RISK_SCORE_MAP.get(sev, 1)
            })
        return issues
    except Exception as e:
        logger.error("Error parsing Bandit output: %s", e, exc_info=True)
        return []

def parse_trivy(path):
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        issues = []
        for target in data.get("Results", []):
            for vuln in target.get("Vulnerabilities", []):
                sev = SEVERITY_MAP.get(vuln.get("Severity", "LOW").upper(), "Low")
                issues.append({
                    "rule": vuln.get("VulnerabilityID"),
                    "desc": vuln.get("Title"),
                    "impact": vuln.get("PkgName"),
                    "fix": vuln.get("PrimaryURL"),
                    "file": target.get("Target"),
                    "line": "N/A",
                    "severity": sev,
                    "risk_score": RISK_SCORE_MAP.get(sev, 1)
                })
        return issues
    except Exception as e:
        logger.error("Error parsing Trivy output: %s", e, exc_info=True)
        return []

def parse_pip_audit(path):
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        issues = []
        for vuln in data.get("vulnerabilities", []):
            sev = SEVERITY_MAP.get(vuln.get("severity", "LOW").upper(), "Low")
            issues.append({
                "rule": vuln.get("id"),
                "desc": vuln.get("description"),
                "impact": f"{vuln.get('package', {}).get('name')}@{vuln.get('package', {}).get('version')}",
                "fix": vuln.get("fix_versions", ["Review manually."])[0],
                "file": "requirements.txt", # Assuming vulnerabilities are from requirements.txt
                "line": "N/A",
                "severity": sev,
                "risk_score": RISK_SCORE_MAP.get(sev, 1)
            })
        return issues
    except Exception as e:
        logger.error("Error parsing pip-audit output: %s", e, exc_info=True)
        return []

def parse_gitleaks(path):
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        issues = []
        for finding in data:
            sev = SEVERITY_MAP.get(finding.get("Severity", "LOW").upper(), "Low")
            issues.append({
                "rule": finding.get("RuleID"),
                "desc": finding.get("Description"),
                "impact": finding.get("Match"),
                "fix": "Review and remove hardcoded secret.",
                "file": finding.get("File"),
                "line": finding.get("StartLine"),
                "severity": sev,
                "risk_score": RISK_SCORE_MAP.get(sev, 1)
            })
        return issues
    except Exception as e:
        logger.error("Error parsing Gitleaks output: %s", e, exc_info=True)
        return []

def parse_dependency_check(path):
    if not os.path.exists(path):
        logger.warning("Dependency-Check XML not found, skipping parse.")
        return []
    try:
        tree = etree.parse(path)
        vulnerabilities = tree.xpath("//vulnerability")
        issues = []
        for vuln in vulnerabilities:
            sev = SEVERITY_MAP.get(vuln.findtext("severity", default="LOW").upper(), "Low")
            issues.append({
                "rule": vuln.findtext("name"),
                "desc": vuln.findtext("description"),
                "impact": vuln.findtext("cwe"),
                "fix": vuln.findtext("references/reference/url"),
                "file": vuln.findtext("../fileName"),
                "line": "N/A",
                "severity": sev,
                "risk_score": RISK_SCORE_MAP.get(sev, 1)
            })
        return issues
    except Exception as e:
        logger.error("Error parsing Dependency-Check XML: %s", e, exc_info=True)
        return []

def run_full_scan_and_report(source_dir: str, temp_id: str) -> Optional[str]:
    base_output_dir = os.path.join("/tmp", f"scan_results_{temp_id}")
    os.makedirs(base_output_dir, exist_ok=True)
    try:
        dir_analysis = validate_source_directory(source_dir)
        logger.info("Source analysis: %s", dir_analysis)

        all_issues = []
        scan_tasks = {}

        semgrep_output = os.path.join(base_output_dir, "semgrep.json")
        semgrep_cmd = ["semgrep", "--json", "--metrics=off", "--output", semgrep_output, source_dir, "--config", "p/all", "--config", "p/security-audit", "--config", "p/owasp-top-10", "--config", "p/python-security"]
        scan_tasks["semgrep"] = (semgrep_cmd, semgrep_output, parse_semgrep)

        if '.py' in dir_analysis['extensions']:
            bandit_output = os.path.join(base_output_dir, "bandit.json")
            bandit_cmd = ["bandit", "-r", source_dir, "-f", "json", "-o", bandit_output]
            scan_tasks["bandit"] = (bandit_cmd, bandit_output, parse_bandit)

        trivy_output = os.path.join(base_output_dir, "trivy.json")
        trivy_cmd = ["trivy", "fs", "--format", "json", "--output", trivy_output, source_dir]
        scan_tasks["trivy"] = (trivy_cmd, trivy_output, parse_trivy)

        gitleaks_output = os.path.join(base_output_dir, "gitleaks.json")
        gitleaks_cmd = ["gitleaks", "detect", "--source", source_dir, "--report-path", gitleaks_output, "--format", "json"]
        scan_tasks["gitleaks"] = (gitleaks_cmd, gitleaks_output, parse_gitleaks)

        if '.py' in dir_analysis['extensions']:
            pip_audit_output = os.path.join(base_output_dir, "pip_audit.json")
            pip_audit_cmd = ["pip-audit", "--json", "-r", os.path.join(source_dir, "requirements.txt")]
            scan_tasks["pip-audit"] = (pip_audit_cmd, pip_audit_output, parse_pip_audit)

        if dir_analysis['extensions'] & {'.json', '.xml', '.gradle', '.pom', '.csproj', '.yml', '.yaml'}:
            depcheck_output_dir = os.path.join(base_output_dir, "depcheck")
            depcheck_xml = os.path.join(depcheck_output_dir, "dependency-check-report.xml")
            depcheck_data_dir = os.path.join(base_output_dir, "depcheck_data")
            os.makedirs(depcheck_data_dir, exist_ok=True)
            depcheck_cmd = ["/usr/local/bin/dependency-check.sh", "-s", source_dir, "-f", "XML",
                            "-o", depcheck_output_dir, "--prettyPrint", "--data", depcheck_data_dir]
            scan_tasks["dependency-check"] = (depcheck_cmd, depcheck_xml, parse_dependency_check)
        else:
            logger.info("No manifest files found. Skipping Dependency-Check.")

        with ThreadPoolExecutor(max_workers=len(scan_tasks)) as executor:
            future_to_tool = {
                executor.submit(run_tool_with_retry, name, cmd, output): (name, output, parser)
                for name, (cmd, output, parser) in scan_tasks.items()
            }
            for future in as_completed(future_to_tool):
                name, output_file, parser_func = future_to_tool[future]
                success = future.result()
                if success:
                    all_issues.extend(parser_func(output_file))
                else:
                    logger.warning("%s: no valid output or scan failed", name)

        summary = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for issue in all_issues:
            sev = issue.get("severity", "Info").lower()
            summary[sev] = summary.get(sev, 0) + 1

        report_file = os.path.join(base_output_dir, f"VulnPrism_Report_{temp_id}.pdf")
        pdf_report.build_pdf_with_enhancements(summary, all_issues, report_file)
        return report_file

    except Exception as e:
        logger.critical("Full scan failed: %s", e, exc_info=True)
        return None
