import re
import logging
from config import settings
from loguru import logger

def detect_xss(response_text: str, payload: str) -> bool:
    try:
        if not response_text:
            return False
            
        # Check for direct payload reflection
        if re.search(re.escape(payload), response_text, re.IGNORECASE):
            return True
            
        # Check for DOM-based indicators
        dom_patterns = [
            r"<script[^>]*>.*alert\(.*\)",
            r"onerror\s*=\s*[\"']?alert\(\)",
            r"<iframe[^>]*src\s*=\s*[\"']?javascript:"
        ]
        
        for pattern in dom_patterns:
            if re.search(pattern, response_text, re.IGNORECASE | re.DOTALL):
                return True
                
        return False
    except Exception as e:
        logger.error(f"XSS detection error: {e}")
        return False

def detect_sqli(response_text: str) -> bool:
    try:
        if not response_text:
            return False
            
        error_patterns = [
            r"SQL syntax.*MySQL",
            r"Warning.*mysqli?",
            r"Unclosed.*quotation",
            r"PG::SyntaxError",
            r"Microsoft OLE DB Provider",
            r"ODBC Driver",
            r"ORA-[0-9]{5}",
            r"com\.mysql\.jdbc\.exceptions",
            r"org\.postgresql\.util\.PSQLException",
            r"SQLiteException",
            r"Unterminated string literal"
        ]
        
        for pattern in error_patterns:
            if re.search(pattern, response_text, re.IGNORECASE):
                return True
                
        return False
    except Exception as e:
        logger.error(f"SQLi detection error: {e}")
        return False

def detect_cmd_injection(response_text: str) -> bool:
    try:
        if not response_text:
            return False
            
        patterns = [
            r"root:.*:0:0:",
            r"uid=\d+",
            r"windows nt",
            r"command not found",
            r"syntax error",
            r"cannot find the file specified",
        ]
        
        for pattern in patterns:
            if re.search(pattern, response_text, re.IGNORECASE):
                return True
                
        return False
    except Exception as e:
        logger.error(f"CMD Injection detection error: {e}")
        return False

def detect_path_traversal(response_text: str) -> bool:
    try:
        if not response_text:
            return False
            
        patterns = [
            r"root:.*:0:0:",
            r"\[extensions\]",
            r"cannot open",
            r"failed to open stream",
            r"no such file or directory",
            r"Warning: include\(",
        ]
        
        for pattern in patterns:
            if re.search(pattern, response_text, re.IGNORECASE):
                return True
                
        return False
    except Exception as e:
        logger.error(f"Path Traversal detection error: {e}")
        return False

def detect_info_disclosure(response_text: str) -> bool:
    try:
        if not response_text:
            return False
            
        sensitive_patterns = [
            r"(?i)api[_-]?key\s*[:=]\s*[\"'][a-f0-9]{20,}[\"']",
            r"(?i)secret\s*[:=]\s*[\"'][a-f0-9]{20,}[\"']",
            r"(?i)password\s*[:=]\s*[\"'][^\"']{8,}[\"']",
            r"(?i)aws_access_key_id\s*=\s*[A-Z0-9]{20}",
            r"(?i)-----BEGIN (RSA|DSA|EC|PGP) PRIVATE KEY-----",
            r"(?i)<dbpassword>[^<]+</dbpassword>",
            r"(?i)DB_USERNAME\s*=\s*[\"'][^\"']+[\"']",
            r"(?i)config\.prod\.json",
            r"(?i)\.env",
            r"(?i)phpinfo\(\)"
        ]
        
        for pattern in sensitive_patterns:
            if re.search(pattern, response_text):
                return True
                
        return False
    except Exception as e:
        logger.error(f"Info disclosure detection error: {e}")
        return False
