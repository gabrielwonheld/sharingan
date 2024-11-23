from core.htmlparser_core import Parser
from view.display import Parserdisplay
from view.banner import Banner


class Parser_service():
    
    def __init__(self,url,domain) -> None:
        self.url = url
        self.domain = domain
        self.parser = Parser(self.url, self.domain)

        self.emails_found = self.parser.emails_found
        self.visited_links = self.parser.visited_links

    def get_parser(self):

        Banner.sharingan()
        '''parser = Parser(self.url, self.domain)
        
        emails_found = parser.emails_found
        visited_links = parser.visited_links'''
        self.parser.crawling(self.url)

        Parserdisplay(self.emails_found,self.visited_links).display_parser()


        
