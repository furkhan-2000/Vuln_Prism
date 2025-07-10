# --- General Settings ---
APP_TITLE = "CyberScythe"
APP_VERSION = "1.0.0"
LOG_LEVEL = "INFO"  # Options: "DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"

# --- Scanner Settings ---
DEFAULT_USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.4844.51 Safari/537.36"
REQUEST_TIMEOUT = 15  # in seconds
MAX_URLS_TO_CRAWL = 200  # Max number of unique URLs to crawl
CONCURRENT_REQUESTS = 10  # Number of concurrent requests for scanning

# --- Application Settings ---
APP_PORT = 5051

# --- Database Settings ---
DATABASE_URL = "postgresql://user:password@host:port/dbname"

# --- Reporting Settings ---
REPORTS_DIR = "reports"