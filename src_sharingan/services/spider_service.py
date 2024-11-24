from core.spider_core import Spider
from view.banner import Banner
from view.display import Parserdisplay


class Spider_service:
    def __init__(self, url, domain) -> None:
        self.url = url
        self.domain = domain
        self.parser = Spider(self.url, self.domain)

        self.emails_found = self.parser.emails_found
        self.visited_links = self.parser.visited_links

    def get_parser(self):

        Banner.sharingan()

        self.parser.crawling(self.url)

        Parserdisplay(self.emails_found, self.visited_links).display_parser()
