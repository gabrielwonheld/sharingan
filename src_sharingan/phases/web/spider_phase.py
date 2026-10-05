from urllib.parse import urlparse

from model.crawl_model import CrawledPage, HarvestedEmail
from model.host import Host
from model.workspace_model import DEFAULT_WORKSPACE_ID
from phases.base import PhaseModule
from phases.common import get_or_create_host
from phases.web.tools.crawler import CrawlerTool


def _same_site(start_host: str, hostname: str | None) -> bool:
    """The start host itself or one of its subdomains (label boundary, so
    `badexample.com` is not part of `example.com`). Literal, no DNS."""
    return bool(hostname) and (hostname == start_host or hostname.endswith('.' + start_host))


class SpiderPhase(PhaseModule):
    """Web phase: bounded crawl of a site, harvesting URLs and email addresses.

    Sends real HTTP requests, so the console checks scope on the start
    hostname before this runs and passes `scope_allows` to re-check **every**
    hostname the crawl would touch. On top of scope, the crawl never leaves
    the start site (its host or subdomains), even when no scope is defined —
    otherwise a crawl with an empty scope would wander the whole internet.

    Pages/emails known from earlier runs are kept, not re-inserted;
    `last_new_*` record what's new on *this* run, like `recon`/`fuzz`.
    """

    name = 'spider'
    description = 'Bounded crawl of a web target: pages and email addresses.'

    def __init__(self, db_session, crawler=CrawlerTool, workspace_id=DEFAULT_WORKSPACE_ID):
        self.session = db_session
        self.workspace_id = workspace_id
        self.crawler = crawler
        self.last_new_pages: list[str] = []
        self.last_all_pages: list = []
        self.last_new_emails: list[str] = []
        self.last_all_emails: dict[str, str] = {}

    def run(
        self,
        name: str,
        url: str,
        max_depth: int,
        max_pages: int,
        delay: float,
        user_agent: str,
        scope_allows=None,
        on_progress=None,
    ) -> Host:
        if on_progress:
            on_progress(f'Crawling {url} (depth <= {max_depth}, pages <= {max_pages})...')

        start_host = (urlparse(url).hostname or url).lower()
        host = get_or_create_host(self.session, name, start_host, self.workspace_id)

        def in_scope(candidate: str) -> bool:
            parsed = urlparse(candidate)
            if parsed.scheme not in ('http', 'https') or not _same_site(start_host, parsed.hostname):
                return False
            return scope_allows(parsed.hostname) if scope_allows else True

        result = self.crawler.crawl(
            start_url=url, in_scope=in_scope, max_depth=max_depth, max_pages=max_pages,
            delay=delay, user_agent=user_agent,
        )

        known_urls = {p.url for p in self.session.query(CrawledPage).filter_by(host_id=host.id)}
        new_pages = [p for p in result.pages if p.url not in known_urls]
        for page in new_pages:
            self.session.add(CrawledPage(
                host_id=host.id, url=page.url, status_code=page.status_code, depth=page.depth,
            ))

        known_emails = {e.email for e in self.session.query(HarvestedEmail).filter_by(host_id=host.id)}
        new_emails = sorted(e for e in result.emails if e not in known_emails)
        for email in new_emails:
            self.session.add(HarvestedEmail(host_id=host.id, email=email, source_url=result.emails[email]))

        if new_pages or new_emails:
            self.session.commit()

        self.last_new_pages = [p.url for p in new_pages]
        self.last_all_pages = result.pages
        self.last_new_emails = new_emails
        self.last_all_emails = result.emails
        return host
