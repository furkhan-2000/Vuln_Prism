from pydantic import BaseSettings, AnyHttpUrl, PositiveInt, PositiveFloat, conint
from typing import List, Set, Optional
from pathlib import Path

class Settings(BaseSettings):
    user_agents: List[str] = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
        "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/118.0"
    ]
    
    default_headers: dict = {
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
        "Connection": "keep-alive",
        "Cache-Control": "no-cache",
        "Pragma": "no-cache"
    }
    
    request_timeout: PositiveInt = 20
    max_concurrent_requests: PositiveInt = 25
    rate_limit_delay: PositiveFloat = 0.15
    max_crawl_depth: conint(ge=1) = 10
    max_retries: conint(ge=0) = 3
    backoff_factor: PositiveFloat = 0.3
    
    blacklisted_extensions: Set[str] = {'.jpg', '.jpeg', '.png', '.gif', '.pdf', '.svg', '.woff', '.woff2', '.ico', '.css'}
    max_response_size: PositiveInt = 5 * 1024 * 1024
    
    log_level: str = "INFO"
    log_file: str = "scanner.log"
    log_format: str = "<green>{time:YYYY-MM-DD HH:mm:ss.SSS}</green> | <level>{level: <8}</level> | <cyan>{name}</cyan>:<cyan>{function}</cyan>:<cyan>{line}</cyan> - <level>{message}</level>"
    
    alert_webhook: Optional[AnyHttpUrl] = None
    
    class Config:
        env_prefix = "SCANNER_"
        case_sensitive = False

settings = Settings()
Path("logs").mkdir(exist_ok=True)
