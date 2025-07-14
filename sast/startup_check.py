#!/usr/bin/env python3
"""
Startup check script to verify all tools are working
"""
import subprocess
import sys
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def check_tool(name, command, expected_codes=[0]):
    """Check if a tool is available and working"""
    try:
        result = subprocess.run(command, capture_output=True, timeout=10)
        if result.returncode in expected_codes:
            logger.info("✅ %s is working (exit code: %d)", name, result.returncode)
            return True
        else:
            logger.warning("⚠️ %s returned unexpected exit code: %d", name, result.returncode)
            return False
    except subprocess.TimeoutExpired:
        logger.error("❌ %s timed out", name)
        return False
    except FileNotFoundError:
        logger.error("❌ %s not found", name)
        return False
    except Exception as e:
        logger.error("❌ %s error: %s", name, e)
        return False

def main():
    logger.info("🔍 Checking SAST tools availability...")
    
    tools = [
        ("Python", [sys.executable, "--version"]),
        ("Git", ["git", "--version"]),
        ("Semgrep", ["semgrep", "--version"]),
        ("Bandit", ["bandit", "--version"]),
        ("Trivy", ["trivy", "--version"]),
    ]
    
    # Check dependency-check with multiple possible paths
    depcheck_paths = [
        "dependency-check.sh",
        "/opt/dependency-check/dependency-check/bin/dependency-check.sh"
    ]
    
    depcheck_working = False
    for path in depcheck_paths:
        if check_tool(f"Dependency-Check ({path})", [path, "--version"]):
            depcheck_working = True
            break
    
    if not depcheck_working:
        logger.warning("⚠️ Dependency-Check not working with any known path")
    
    # Check other tools
    all_working = True
    for name, command in tools:
        if not check_tool(name, command):
            all_working = False
    
    if all_working and depcheck_working:
        logger.info("🎉 All tools are working!")
        return 0
    elif all_working:
        logger.info("✅ Core tools working, Dependency-Check may have issues")
        return 0
    else:
        logger.error("💥 Some tools are not working!")
        return 1

if __name__ == "__main__":
    sys.exit(main())
