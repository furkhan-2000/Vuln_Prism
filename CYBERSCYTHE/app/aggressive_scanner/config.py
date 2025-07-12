from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    # Crawler and scanning settings
    max_concurrent_requests: int = 10
    max_crawl_depth: int = 3
    blacklisted_extensions: list = [
        '.jpg', '.png', '.gif', '.svg', '.pdf', 
        '.mp4', '.woff', '.woff2', '.ttf', '.eot'
    ]
    max_response_size: int = 10485760  # 10MB
    rate_limit_delay: float = 0.1
    request_timeout: int = 30
    max_retries: int = 3
    backoff_factor: float = 0.5

    # HTTP client headers
    default_headers: dict = {
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9',
        'Accept-Language': 'en-US,en;q=0.5',
        'Connection': 'keep-alive'
    }
    user_agents: list = [
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Safari/605.1.15',
        'Mozilla/5.0 (X11; Linux x86_64; rv:89.0) Gecko/20100101 Firefox/89.0'
    ]

settings = Settings()
