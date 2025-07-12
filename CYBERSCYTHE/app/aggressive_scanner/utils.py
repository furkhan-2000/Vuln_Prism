import random
import httpx
import asyncio
from urllib.parse import urlparse, urljoin, urldefrag
from tenacity import (
    retry,
    retry_if_exception_type,
    wait_exponential_jitter,
    stop_after_attempt,
    before_sleep_log
)
from .config import settings
from loguru import logger
from functools import lru_cache
import uuid
from typing import Optional

@lru_cache(maxsize=1000)
def normalize_url(base_url: str, link: str) -> str:
    try:
        full_url = urljoin(base_url, link)
        full_url, _ = urldefrag(full_url)
        return full_url
    except Exception as e:
        logger.error(f"URL normalization error: {e}")
        return link

@lru_cache(maxsize=1000)
def is_same_domain(base_url: str, url: str) -> bool:
    try:
        base_host = urlparse(base_url).netloc.split(':')[0]
        url_host = urlparse(url).netloc.split(':')[0]
        return base_host == url_host
    except Exception:
        return False

def is_blacklisted(url: str) -> bool:
    parsed = urlparse(url)
    path = parsed.path.lower()
    return any(path.endswith(ext) for ext in settings.blacklisted_extensions)

def get_random_headers():
    headers = settings.default_headers.copy()
    headers["User-Agent"] = random.choice(settings.user_agents)
    headers["X-Agg-Scan-ID"] = str(uuid.uuid4().hex[:16])
    return headers

@retry(
    retry=retry_if_exception_type((httpx.ConnectError, httpx.TimeoutException)),
    wait=wait_exponential_jitter(
        initial=settings.backoff_factor,
        max=settings.request_timeout,
        jitter=lambda: random.uniform(0.3, 0.7)
    ),
    stop=stop_after_attempt(settings.max_retries),
    before_sleep=before_sleep_log(logger, "WARNING"),
    reraise=True
)
async def reliable_request(
    client: httpx.AsyncClient,
    method: str,
    url: str,
    **kwargs
) -> Optional[httpx.Response]:
    if is_blacklisted(url):
        logger.debug(f"Skipping blacklisted URL: {url}")
        return None

    headers = kwargs.get('headers', get_random_headers())
    params = kwargs.get('params')
    data = kwargs.get('data')

    try:
        response = await client.request(
            method=method.upper(),
            url=url,
            params=params,
            data=data,
            headers=headers,
            timeout=settings.request_timeout,
            follow_redirects=True,
            verify=True,
        )
    except (httpx.RequestError, httpx.HTTPStatusError) as e:
        raise e

    content_length = response.headers.get('content-length')
    if content_length and int(content_length) > settings.max_response_size:
        logger.warning(f"Response too large: {url} ({content_length} bytes)")
        return None

    await asyncio.sleep(settings.rate_limit_delay)
    return response

# HTTPX event hooks
async def request_hook(request):
    request.headers.update(get_random_headers())
    logger.debug(f"Request: {request.method} {request.url}")

async def response_hook(response):
    # Check redirect history for domain changes
    for resp in response.history:
        if resp.url.netloc != response.url.netloc:
            logger.warning(
                f"Possible SSRF redirect: {resp.url} -> {response.url}"
            )
    logger.debug(f"Response: {response.status_code} {response.url}")

def create_http_client():
    return httpx.AsyncClient(
        http2=True,
        limits=httpx.Limits(
            max_connections=settings.max_concurrent_requests,
            max_keepalive_connections=15
        ),
        timeout=settings.request_timeout,
        event_hooks={
            'request': [request_hook],
            'response': [response_hook]
        }
    )
