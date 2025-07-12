from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    # Crawler and scanning settings
    max_concurrent_requests: int = 15
    max_crawl_depth: int = 3
    blacklisted_extensions: list = [
        '.jpg', '.jpeg', '.png', '.gif', '.svg', '.pdf', 
        '.mp3', '.mp4', '.avi', '.woff', '.woff2', '.ttf', '.eot', '.css'
    ]
    max_response_size: int = 10485760  # 10MB
    rate_limit_delay: float = 0.05 # Reduced delay for faster scanning
    request_timeout: int = 20
    max_retries: int = 2
    backoff_factor: float = 0.3

    # Static list of user agents to avoid external dependency issues
    user_agents: list = [
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.0.0 Safari/537.36',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.0.0 Safari/537.36',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.0.0 Safari/537.36',
        'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.1 Safari/605.1.15',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 13_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.1 Safari/605.1.15',
    ]

    # HTTP client headers
    default_headers: dict = {
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
        'Accept-Language': 'en-US,en;q=0.9',
        'Connection': 'keep-alive',
        'Upgrade-Insecure-Requests': '1',
    }

settings = Settings()
