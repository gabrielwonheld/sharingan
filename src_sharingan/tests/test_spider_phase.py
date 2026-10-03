from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from db.extensions import Base
from model.crawl_model import CrawledPage, HarvestedEmail
from model.host import Host
from phases.base import PhaseModule
from phases.web.spider_phase import SpiderPhase
from phases.web.tools.crawler import CrawledUrl, CrawlResult


class FakeCrawler:
    result = CrawlResult(
        pages=[
            CrawledUrl('http://example.com/', 200, 0),
            CrawledUrl('http://example.com/a', 404, 1),
        ],
        emails={'admin@example.com': 'http://example.com/'},
    )
    kwargs = None

    @classmethod
    def crawl(cls, **kwargs):
        cls.kwargs = kwargs
        return cls.result


def make_session():
    engine = create_engine('sqlite:///:memory:')
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine)()


def run(session, **overrides):
    options = dict(
        name='alvo', url='http://example.com/', max_depth=3, max_pages=50,
        delay=0.5, user_agent='UA',
    )
    options.update(overrides)
    return SpiderPhase(session, crawler=FakeCrawler).run(**options)


def test_spider_phase_is_a_phase_module():
    assert issubclass(SpiderPhase, PhaseModule)


def test_spider_phase_persists_pages_and_emails_linked_to_the_host():
    session = make_session()

    host = run(session)

    assert host.addr == 'example.com'
    pages = {(p.url, p.status_code, p.depth) for p in session.query(CrawledPage).filter_by(host_id=host.id)}
    assert pages == {('http://example.com/', 200, 0), ('http://example.com/a', 404, 1)}
    email = session.query(HarvestedEmail).filter_by(host_id=host.id).one()
    assert (email.email, email.source_url) == ('admin@example.com', 'http://example.com/')


def test_spider_phase_rerun_does_not_duplicate_but_tracks_whats_new():
    session = make_session()
    phase = SpiderPhase(session, crawler=FakeCrawler)
    kwargs = dict(name='alvo', url='http://example.com/', max_depth=3, max_pages=50, delay=0, user_agent='UA')
    phase.run(**kwargs)

    FakeCrawler.result = CrawlResult(
        pages=FakeCrawler.result.pages + [CrawledUrl('http://example.com/new', 200, 1)],
        emails={'admin@example.com': 'http://example.com/', 'new@example.com': 'http://example.com/new'},
    )
    try:
        phase.run(**kwargs)
    finally:
        FakeCrawler.result = CrawlResult(FakeCrawler.result.pages[:2], {'admin@example.com': 'http://example.com/'})

    assert session.query(CrawledPage).count() == 3
    assert phase.last_new_pages == ['http://example.com/new']
    assert [p.url for p in phase.last_all_pages] == [
        'http://example.com/', 'http://example.com/a', 'http://example.com/new',
    ]
    assert phase.last_new_emails == ['new@example.com']
    assert set(phase.last_all_emails) == {'admin@example.com', 'new@example.com'}


def test_spider_phase_reuses_the_host_other_phases_created():
    session = make_session()
    existing = Host(nome='alvo', addr='example.com')
    session.add(existing)
    session.commit()

    assert run(session).id == existing.id


def test_spider_phase_passes_limits_delay_and_user_agent_to_the_crawler():
    session = make_session()

    run(session, max_depth=2, max_pages=7, delay=1.5, user_agent='Custom/1.0')

    kwargs = FakeCrawler.kwargs
    assert (kwargs['max_depth'], kwargs['max_pages'], kwargs['delay'], kwargs['user_agent']) == (2, 7, 1.5, 'Custom/1.0')
    assert kwargs['start_url'] == 'http://example.com/'


def test_spider_phase_only_lets_the_crawler_stay_on_the_start_site():
    session = make_session()

    run(session)
    in_scope = FakeCrawler.kwargs['in_scope']

    assert in_scope('http://example.com/x')
    assert in_scope('https://api.example.com/x')
    assert not in_scope('https://badexample.com/x')
    assert not in_scope('https://evil.net/?r=example.com')
    assert not in_scope('ftp://example.com/x')


def test_spider_phase_also_applies_the_scope_callback_to_every_hostname():
    session = make_session()
    asked = []

    run(session, scope_allows=lambda hostname: asked.append(hostname) or hostname != 'api.example.com')
    in_scope = FakeCrawler.kwargs['in_scope']

    assert in_scope('http://example.com/x')
    assert not in_scope('http://api.example.com/x')
    assert asked == ['example.com', 'api.example.com']


def test_spider_phase_stays_on_the_ip_when_the_target_is_an_ip():
    session = make_session()

    run(session, url='http://127.0.0.1:8090/')
    in_scope = FakeCrawler.kwargs['in_scope']

    assert in_scope('http://127.0.0.1:8090/login')
    assert not in_scope('http://127.0.0.2/')


def test_spider_phase_reports_the_crawl_as_progress():
    session = make_session()
    progress = []

    run(session, on_progress=progress.append)

    assert progress == ['Crawling http://example.com/ (depth <= 3, pages <= 50)...']
