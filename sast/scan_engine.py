import os
import uuid
import subprocess
import json
import logging
import shutil
import time
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed
import random

from lxml import etree

# Configure logging
logger = logging.getLogger("app.scan_engine")
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)

# Severity and scoring maps
SEVERITY_MAP = {
    "CRITICAL": "Critical", "HIGH": "High", "MEDIUM": "Medium", "MODERATE": "Medium",
    "LOW": "Low", "INFO": "Info", "INFORMATIONAL": "Info", "NOTE": "Info",
    "WARNING": "Medium", "WARN": "Medium", "ERROR": "High", "FATAL": "Critical",
    "DEFCON1": "Critical", "URGENT": "High", "IMPORTANT": "High",
    "UNKNOWN": "Info"
}
RISK_SCORE_MAP = {"Critical": 10, "High": 8, "Medium": 5, "Low": 2, "Info": 1}

# Auto-fix suggestions
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
    if not os.path.isdir(source_path):
        raise Exception(f"Invalid source directory: {source_path}")

    file_count = total_size = 0
    extensions = set()
    for root, _, files in os.walk(source_path):
        for fname in files:
            fpath = os.path.join(root, fname)
            try:
                st = os.stat(fpath)
                file_count += 1
                total_size += st.st_size
                ext = Path(fname).suffix.lower()
                if ext:
                    extensions.add(ext)
            except OSError:
                continue

    return {
        "file_count": file_count,
        "total_size": total_size,
        "extensions": extensions,
        "has_code": bool(extensions & {'.py', '.js', '.java', '.cpp', '.c', '.cs',
                                       '.rb', '.php', '.go', '.rs', '.ts', '.jsx', '.tsx'})
    }

def run_tool_with_retry(name: str, cmd: List[str], output_path: str,
                        timeout: int = 600, retries: int = 5) -> bool:
    """
    Run a scanning tool with retries and exponential backoff + jitter.
    Write stdout for JSON tools or stderr for XML tools, then treat
    existence of a non-empty output file as success.
    """
    is_xml = output_path.lower().endswith(".xml")
    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    for attempt in range(retries + 1):
        logger.info("Running %s (attempt %d/%d): %s", name, attempt+1, retries+1, " ".join(cmd))
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            logger.info("%s exit code %d", name, result.returncode)
            logger.debug("%s stdout: %s", name, result.stdout[:500])
            logger.debug("%s stderr: %s", name, result.stderr[:500])

            # Semgrep: exit code 7 = no findings (we treat as success)
            if name.lower() == "semgrep" and result.returncode == 7:
                return True

            # Write output: for JSON-based tools use stdout, for XML use stderr if empty
            if not is_xml: # Only capture stdout for non-XML tools
                out = result.stdout
                if out:
                    with open(output_path, "w", encoding="utf-8") as f:
                        f.write(out)

            # Success if file exists and is non-empty (for XML tools, it's written directly)
            if os.path.exists(output_path) and os.path.getsize(output_path) > 0:
                return True

            logger.warning("%s produced no valid output on attempt %d", name, attempt+1)

        except subprocess.TimeoutExpired:
            logger.error("%s timed out on attempt %d", name, attempt+1)

        # Exponential backoff + jitter
        time.sleep((2 ** attempt) + random.uniform(0, 1))

    logger.error("%s failed after %d attempts", name, retries+1)
    return False

def parse_semgrep(path: str) -> List[Dict[str, Any]]:
    issues = []
    try:
        data = json.load(open(path, encoding="utf-8"))
        for r in data.get("results", []):
            sev = SEVERITY_MAP.get(r.get("extra", {}).get("severity", "INFO").upper(), "Info")
            issues.append({
                "rule": r.get("check_id"),
                "desc": r.get("extra", {}).get("message"),
                "impact": r.get("path"),
                "fix": AUTO_FIX_SUGGESTIONS.get(r.get("check_id"), "Review manually."),
                "file": r.get("path"),
                "line": r.get("start", {}).get("line"),
                "severity": sev,
                "risk_score": RISK_SCORE_MAP.get(sev, 1)
            })
    except Exception as e:
        logger.error("Error parsing Semgrep output: %s", e, exc_info=True)
    return issues

def parse_bandit(path: str) -> List[Dict[str, Any]]:
    issues = []
    try:
        data = json.load(open(path, encoding="utf-8"))
        for r in data.get("results", []):
            sev = SEVERITY_MAP.get(r.get("issue_severity", "LOW").upper(), "Low")
            issues.append({
                "rule": r.get("test_id"),
                "desc": r.get("issue_text"),
                "impact": r.get("issue_confidence"),
                "fix": AUTO_FIX_SUGGESTIONS.get(r.get("test_name"), "Review manually."),
                "file": r.get("filename"),
                "line": r.get("line_number"),
                "severity": sev,
                "risk_score": RISK_SCORE_MAP.get(sev, 1)
            })
    except Exception as e:
        logger.error("Error parsing Bandit output: %s", e, exc_info=True)
    return issues

def parse_trivy(path: str) -> List[Dict[str, Any]]:
    issues = []
    try:
        data = json.load(open(path, encoding="utf-8"))
        for result in data.get("Results", []):
            for v in result.get("Vulnerabilities", []):
                sev = SEVERITY_MAP.get(v.get("Severity", "LOW").upper(), "Low")
                issues.append({
                    "rule": v.get("VulnerabilityID"),
                    "desc": v.get("Title"),
                    "impact": v.get("PkgName"),
                    "fix": v.get("PrimaryURL"),
                    "file": result.get("Target"),
                    "line": "N/A",
                    "severity": sev,
                    "risk_score": RISK_SCORE_MAP.get(sev, 1)
                })
    except Exception as e:
        logger.error("Error parsing Trivy output: %s", e, exc_info=True)
    return issues

def parse_gitleaks(path: str) -> List[Dict[str, Any]]:
    issues = []
    try:
        data = json.load(open(path, encoding="utf-8"))
        for r in data:
            sev = SEVERITY_MAP.get(r.get("Severity", "LOW").upper(), "Low")
            issues.append({
                "rule": r.get("RuleID"),
                "desc": r.get("Description"),
                "impact": r.get("Match"),
                "fix": "Review manually.",
                "file": r.get("File"),
                "line": r.get("StartLine"),
                "severity": sev,
                "risk_score": RISK_SCORE_MAP.get(sev, 1)
            })
    except Exception as e:
        logger.error("Error parsing Gitleaks output: %s", e, exc_info=True)
    return issues

def parse_pip_audit(path: str) -> List[Dict[str, Any]]:
    issues = []
    try:
        data = json.load(open(path, encoding="utf-8"))
        for v in data.get("vulnerabilities", []):
            sev = SEVERITY_MAP.get(v.get("severity", "LOW").upper(), "Low")
            pkg = v.get("package", {})
            issues.append({
                "rule": v.get("id"),
                "desc": v.get("description"),
                "impact": f"{pkg.get('name')}@{pkg.get('version')}",
                "fix": v.get("fix_versions", ["Review manually."])[0],
                "file": "requirements.txt",
                "line": "N/A",
                "severity": sev,
                "risk_score": RISK_SCORE_MAP.get(sev, 1)
            })
    except Exception as e:
        logger.error("Error parsing pip-audit output: %s", e, exc_info=True)
    return issues

def parse_dependency_check(path: str) -> List[Dict[str, Any]]:
    issues = []
    if not os.path.exists(path):
        logger.warning("Dependency-Check XML not found; skipping.")
        return issues
    try:
        tree = etree.parse(path)
        for vuln in tree.xpath("//vulnerability"):
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
    except Exception as e:
        logger.error("Error parsing Dependency-Check XML: %s", e, exc_info=True)
    return issues

def run_full_scan(source_dir: str, temp_id: str) -> Tuple[Dict[str, int], List[Dict[str, Any]]]:
    """
    Runs all configured SAST and SCA tools and returns the structured results.

    Args:
        source_dir: The directory containing the source code to scan.
        temp_id: A unique identifier for this scan run.

    Returns:
        A tuple containing:
        - A summary dictionary of vulnerability counts by severity.
        - A list of all found vulnerabilities (issues).
    """
    base_output = os.path.join("/home/jenkins", f"scan_results_{temp_id}")
    os.makedirs(base_output, exist_ok=True)

    dir_info = validate_source_directory(source_dir)
    logger.info("Source analysis: %s", dir_info)

    tasks: Dict[str, Any] = {}

    # Semgrep
    semgrep_out = os.path.join(base_output, "semgrep.json")
    tasks["semgrep"] = (
        ["semgrep", "--json", "--metrics=off", "--timeout", "600",
         "--output", semgrep_out, source_dir,
         "--config", "p/all", "--config", "p/security-audit",
         "--config", "p/owasp-top-10", "--config", "p/python-security"],
        semgrep_out, parse_semgrep
    )

    # Bandit
    if '.py' in dir_info['extensions']:
        bandit_out = os.path.join(base_output, "bandit.json")
        tasks["bandit"] = (
            ["bandit", "-r", source_dir, "-f", "json", "-o", bandit_out],
            bandit_out, parse_bandit
        )

    # Trivy
    trivy_out = os.path.join(base_output, "trivy.json")
    tasks["trivy"] = (
        ["trivy", "fs", "--format", "json", "--output", trivy_out, source_dir],
        trivy_out, parse_trivy
    )

    # Gitleaks
    g_out = os.path.join(base_output, "gitleaks.json")
    tasks["gitleaks"] = (
        ["gitleaks", "detect", "--source", source_dir,
         "--report-path", g_out, "--report-format", "json"],
        g_out, parse_gitleaks
    )

    # Pip-audit
    req_file = os.path.join(source_dir, "requirements.txt")
    if os.path.exists(req_file) and os.path.getsize(req_file) > 0:
        pip_out = os.path.join(base_output, "pip_audit.json")
        tasks["pip-audit"] = (
            ["pip-audit", "-r", req_file, "--format", "json", "--output", pip_out],
            pip_out, parse_pip_audit
        )
    else:
        logger.info("No valid requirements.txt; skipping pip-audit.")

    # Dependency-Check
    dep_dir = os.path.join(base_output, "depcheck")
    os.makedirs(dep_dir, exist_ok=True)
    dep_xml = os.path.join(dep_dir, "dependency-check-report.xml")
    tasks["dependency-check"] = (
        ["/usr/local/bin/dependency-check.sh", "-s", source_dir,
         "-f", "XML", "-o", dep_dir, "--prettyPrint"],
        dep_xml, parse_dependency_check
    )

    all_issues: List[Dict[str, Any]] = []
    with ThreadPoolExecutor(max_workers=os.cpu_count() + 2) as executor:
        future_map = {
            executor.submit(run_tool_with_retry, name, cmd, out): (name, out, parser)
            for name, (cmd, out, parser) in tasks.items()
        }
        for future in as_completed(future_map):
            name, out, parser = future_map[future]
            if future.result():
                all_issues.extend(parser(out))
            else:
                logger.warning("%s: skipped (no output or error)", name)

    # Summarize
    summary = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
    for issue in all_issues:
        sev = issue.get("severity", "Info")
        summary[sev] += 1

    # Return the structured data
    return summary, all_issues