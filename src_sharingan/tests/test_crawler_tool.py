from phases.web.tools.crawler import CrawlerTool, FetchResponse

PAGES = {
    'http://example.com/': FetchResponse(200, (
        '<a href="/a">a</a><a href="/b#frag">b</a><a href="http://evil.net/x">x</a>'
        '<a href="mailto:Admin@Example.com">mail</a>'
    )),
    'http://example.com/a': FetchResponse(200, '<a href="/deep">d</a> contact: sales@example.com'),
    'http://example.com/b': FetchResponse(200, '<a href="/">home</a>'),
    'http://example.com/deep': FetchResponse(200, '<a href="/deeper">dd</a>'),
    'http://example.com/deeper': FetchResponse(200, ''),
}


def make_fetch(pages=PAGES, seen=None):
    def fetch(url, user_agent):
        if seen is not None:
            seen.append((url, user_agent))
        return pages.get(url)
    return fetch


def crawl(**overrides):
    options = dict(
        start_url='http://example.com/',
        in_scope=lambda url: 'example.com' in url,
        max_depth=5, max_pages=100, delay=0, user_agent='UA',
        fetch=make_fetch(), sleep=lambda s: None,
    )
    options.update(overrides)
    return CrawlerTool.crawl(**options)


def test_crawl_follows_in_scope_links_and_dedups_fragments_and_revisits():
    result = crawl()

    assert [p.url for p in result.pages] == [
        'http://example.com/', 'http://example.com/a', 'http://example.com/b',
        'http://example.com/deep', 'http://example.com/deeper',
    ]


def test_crawl_never_requests_out_of_scope_urls():
    seen = []
    crawl(fetch=make_fetch(seen=seen))

    assert all('evil.net' not in url for url, _ in seen)


def test_crawl_respects_max_depth():
    result = crawl(max_depth=1)

    assert {p.url for p in result.pages} == {
        'http://example.com/', 'http://example.com/a', 'http://example.com/b',
    }
    assert {p.url: p.depth for p in result.pages}['http://example.com/a'] == 1


def test_crawl_respects_max_pages():
    result = crawl(max_pages=2)

    assert len(result.pages) == 2


def test_crawl_sends_the_configured_user_agent():
    seen = []
    crawl(fetch=make_fetch(seen=seen))

    assert {ua for _, ua in seen} == {'UA'}


def test_crawl_sleeps_between_requests_but_not_before_the_first():
    sleeps = []
    result = crawl(delay=0.5, sleep=sleeps.append)

    assert sleeps == [0.5] * (len(result.pages) - 1)


def test_crawl_collects_emails_from_text_and_mailto_with_the_first_page_found_on():
    result = crawl()

    assert result.emails == {
        'admin@example.com': 'http://example.com/',
        'sales@example.com': 'http://example.com/a',
    }


def test_crawl_ignores_image_filenames_that_look_like_emails():
    pages = {'http://example.com/': FetchResponse(200, '<img src="logo@2x.png"> logo@2x.png')}

    result = crawl(fetch=make_fetch(pages))

    assert result.emails == {}


def test_crawl_follows_redirects_only_if_the_target_is_in_scope():
    pages = {
        'http://example.com/': FetchResponse(302, None, location='http://evil.net/login'),
    }
    seen = []

    result = crawl(fetch=make_fetch(pages, seen))

    assert [(p.url, p.status_code) for p in result.pages] == [('http://example.com/', 302)]
    assert [url for url, _ in seen] == ['http://example.com/']


def test_crawl_follows_an_in_scope_redirect_without_spending_depth():
    pages = {
        'http://example.com/': FetchResponse(301, None, location='/home'),
        'http://example.com/home': FetchResponse(200, '<a href="/x">x</a>'),
        'http://example.com/x': FetchResponse(200, ''),
    }

    result = crawl(fetch=make_fetch(pages), max_depth=1)

    assert {p.url: p.depth for p in result.pages} == {
        'http://example.com/': 0, 'http://example.com/home': 0, 'http://example.com/x': 1,
    }


def test_crawl_skips_pages_that_failed_to_fetch():
    result = crawl(fetch=make_fetch({}))

    assert result.pages == []


def test_crawl_ignores_non_http_links():
    pages = {'http://example.com/': FetchResponse(200, '<a href="javascript:void(0)">j</a><a href="tel:1">t</a>')}
    seen = []

    crawl(fetch=make_fetch(pages, seen))

    assert [url for url, _ in seen] == ['http://example.com/']
