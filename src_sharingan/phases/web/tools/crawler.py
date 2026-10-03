import re
import time
from collections import deque
from dataclasses import dataclass, field
from urllib.parse import urldefrag, urljoin, urlparse

import requests
from bs4 import BeautifulSoup

_EMAIL_PATTERN = re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}')
# `logo@2x.png` matches the email pattern; these TLD-looking suffixes are really assets.
_ASSET_SUFFIXES = ('png', 'jpg', 'jpeg', 'gif', 'svg', 'webp', 'ico', 'css', 'js')
_REDIRECT_CODES = {301, 302, 303, 307, 308}


@dataclass(frozen=True)
class FetchResponse:
    status_code: int
    text: str | None
    location: str | None = None


@dataclass(frozen=True)
class CrawledUrl:
    url: str
    status_code: int
    depth: int


@dataclass
class CrawlResult:
    pages: list[CrawledUrl] = field(default_factory=list)
    # email -> first URL it was found on
    emails: dict[str, str] = field(default_factory=dict)


class CrawlerTool:
    """Bounded, polite HTML crawler (requests + BeautifulSoup).

    Replaces the legacy `core/spider_core.Spider`, fixing its known problems:
    scope is a caller-supplied predicate (not a substring regex), depth and
    page count are capped, requests are spaced by `delay`, the User-Agent is
    configurable, and it's iterative (no recursion limit). Redirects are never
    followed by `requests` itself: a `Location` is treated like any other link,
    so it goes through the scope check before being requested.
    """

    @staticmethod
    def is_available() -> bool:
        return True

    @staticmethod
    def fetch(url: str, user_agent: str, timeout: int = 10) -> FetchResponse | None:
        try:
            response = requests.get(
                url, headers={'User-Agent': user_agent}, timeout=timeout, allow_redirects=False,
            )
        except requests.RequestException:
            return None
        is_html = 'html' in response.headers.get('Content-Type', '').lower()
        return FetchResponse(
            response.status_code,
            response.text if is_html else None,
            response.headers.get('Location'),
        )

    @classmethod
    def crawl(
        cls,
        start_url: str,
        in_scope,
        max_depth: int,
        max_pages: int,
        delay: float,
        user_agent: str,
        fetch=None,
        sleep=time.sleep,
    ) -> CrawlResult:
        fetch = fetch or cls.fetch
        result = CrawlResult()
        seen: set[str] = set()
        queue: deque[tuple[str, int]] = deque([(urldefrag(start_url)[0], 0)])

        while queue and len(result.pages) < max_pages:
            url, depth = queue.popleft()
            if url in seen or not in_scope(url):
                continue
            seen.add(url)

            if result.pages and delay:
                sleep(delay)
            response = fetch(url, user_agent)
            if response is None:
                continue
            result.pages.append(CrawledUrl(url, response.status_code, depth))

            if response.status_code in _REDIRECT_CODES and response.location:
                target = cls._normalize(urljoin(url, response.location))
                if target:
                    queue.append((target, depth))
            if not response.text:
                continue

            cls._collect_emails(response.text, url, result.emails)
            if depth < max_depth:
                for link in cls._extract_links(response.text, url):
                    queue.append((link, depth + 1))
        return result

    @staticmethod
    def _normalize(url: str) -> str | None:
        url = urldefrag(url)[0]
        return url if urlparse(url).scheme in ('http', 'https') else None

    @classmethod
    def _extract_links(cls, html: str, base_url: str) -> list[str]:
        links = []
        for element in BeautifulSoup(html, 'html.parser').find_all('a', href=True):
            link = cls._normalize(urljoin(base_url, element['href']))
            if link:
                links.append(link)
        return links

    @staticmethod
    def _collect_emails(html: str, url: str, emails: dict[str, str]) -> None:
        # mailto: hrefs are covered too: the address appears verbatim in the markup.
        for match in _EMAIL_PATTERN.findall(html):
            email = match.lower()
            if email.rsplit('.', 1)[-1] in _ASSET_SUFFIXES:
                continue
            emails.setdefault(email, url)
