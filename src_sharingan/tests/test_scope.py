import pytest

from core.scope import decide, parse_scope_value


@pytest.mark.parametrize('raw,expected', [
    ('Example.COM', ('domain', 'example.com')),
    ('example.com.', ('domain', 'example.com')),
    ('*.example.com', ('domain', 'example.com')),
    ('localhost', ('domain', 'localhost')),
    ('192.0.2.10', ('ip', '192.0.2.10')),
    ('192.0.2.77/24', ('cidr', '192.0.2.0/24')),
    ('2001:db8::1', ('ip', '2001:db8::1')),
])
def test_parse_scope_value_detects_and_normalizes_the_kind(raw, expected):
    assert parse_scope_value(raw) == expected


@pytest.mark.parametrize('raw', ['', '  ', 'bad host', 'http://example.com', '-x.com', '300.1.1.1/8x', 'a..b'])
def test_parse_scope_value_rejects_invalid_input(raw):
    with pytest.raises(ValueError):
        parse_scope_value(raw)


def rules(*items):
    """items: ('domain', 'example.com', True) -> (kind, value, allow)"""
    return list(items)


def test_no_include_rules_means_unrestricted():
    decision = decide('anything.test', [])

    assert decision.allowed and decision.unrestricted


def test_domain_rule_covers_the_apex_and_subdomains_only_on_label_boundaries():
    scope = rules(('domain', 'example.com', True))

    assert decide('example.com', scope).allowed
    assert decide('erp.example.com', scope).allowed
    assert decide('A.B.EXAMPLE.com.', scope).allowed
    assert not decide('badexample.com', scope).allowed
    assert not decide('example.com.evil.net', scope).allowed


def test_ip_and_cidr_rules_match_addresses_not_hostnames():
    scope = rules(('ip', '192.0.2.10', True), ('cidr', '198.51.100.0/24', True))

    assert decide('192.0.2.10', scope).allowed
    assert decide('198.51.100.200', scope).allowed
    assert not decide('192.0.2.11', scope).allowed
    assert not decide('203.0.113.5', scope).allowed
    assert not decide('example.com', scope).allowed


def test_domain_rules_do_not_match_ip_targets():
    assert not decide('192.0.2.10', rules(('domain', 'example.com', True))).allowed


def test_exclusion_beats_inclusion():
    scope = rules(
        ('domain', 'example.com', True),
        ('domain', 'admin.example.com', False),
        ('cidr', '10.0.0.0/8', True),
        ('ip', '10.0.0.5', False),
    )

    excluded = decide('x.admin.example.com', scope)
    assert not excluded.allowed and 'excluded' in excluded.reason
    assert not decide('10.0.0.5', scope).allowed
    assert decide('10.0.0.6', scope).allowed


def test_exclusion_still_applies_when_there_are_no_include_rules():
    decision = decide('10.0.0.5', rules(('ip', '10.0.0.5', False)))

    assert not decision.allowed


def test_out_of_scope_reason_is_explicit():
    decision = decide('evil.net', rules(('domain', 'example.com', True)))

    assert not decision.allowed and 'out of scope' in decision.reason
