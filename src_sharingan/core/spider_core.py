import re
import sys
from urllib.parse import urljoin

import requests
from bs4 import BeautifulSoup


class Spider:
    def __init__(self, url, domain=None):

        self.url = url
        self.href_list = []
        self.email_list = []
        self.visited_links = set()  # Armazena URLs já visitados
        self.emails_found = set()   # Armazena emails únicos encontrados
        # Compila o padrão de domínio para corresponder ao domínio principal
        self.domain = re.compile(rf'(.*{domain}.*)')

    def fetch_page(self, url):
        try:
            response = requests.get(url, timeout=10)
            return response.text
        except requests.RequestException as e:
            # print(f"Erro ao acessar {url}: {e}")
            return None

    def link_extractor(self, html):
        soup = BeautifulSoup(html, 'html.parser')
        href_soup = soup.find_all('a', href=True)
        links = []

        for element in href_soup:
            full_link = urljoin(self.url, element['href'])
            links.append(full_link)

        return links

    def email_extractor(self, html):
        email_pattern = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
        emails = re.findall(email_pattern, html)
        self.emails_found.update(emails)

    def crawling(self, url):
        if url in self.visited_links:
            return

        print(f'\rAcessando: {url}', end='\r')
        self.visited_links.add(url)
        page_content = self.fetch_page(url)

        if page_content:
            self.email_extractor(page_content)
            ip_define = re.compile(
                r'^([\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3})(:\d+)?(.*)$'
            )
            links = self.link_extractor(page_content)
            for link in links:
                if link not in self.visited_links:
                    if self.domain.search(link) or ip_define.match(link):
                        self.crawling(link)
