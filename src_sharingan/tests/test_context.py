import pytest

from core.context import SessionContext


def test_defaults_are_available_and_marked_as_default():
    ctx = SessionContext()

    assert ctx.get('rustscan_batch') == 4500
    assert ctx.get('rustscan_timeout') == 3000
    assert ctx.get('user_agent') == 'Sharingan'


def test_set_converts_to_the_option_type():
    ctx = SessionContext()

    ctx.set('rustscan_batch', '500')
    ctx.set('user_agent', 'Mozilla/5.0 (X11; Linux x86_64)')

    assert ctx.get('rustscan_batch') == 500
    assert ctx.get('user_agent') == 'Mozilla/5.0 (X11; Linux x86_64)'


def test_set_rejects_unknown_option_listing_the_valid_ones():
    ctx = SessionContext()

    with pytest.raises(ValueError, match='rustscan_batch'):
        ctx.set('nope', '1')


@pytest.mark.parametrize('value', ['abc', '0', '-5', '1.5'])
def test_set_rejects_invalid_integer_values(value):
    ctx = SessionContext()

    with pytest.raises(ValueError):
        ctx.set('rustscan_timeout', value)
    assert ctx.get('rustscan_timeout') == 3000  # unchanged


def test_set_rejects_empty_user_agent():
    with pytest.raises(ValueError):
        SessionContext().set('user_agent', '  ')


def test_unset_restores_the_default():
    ctx = SessionContext()
    ctx.set('rustscan_batch', '100')

    ctx.unset('rustscan_batch')

    assert ctx.get('rustscan_batch') == 4500


def test_unset_rejects_unknown_option():
    with pytest.raises(ValueError):
        SessionContext().unset('nope')


def test_rows_lists_every_option_with_value_default_and_description():
    ctx = SessionContext()
    ctx.set('rustscan_batch', '100')

    rows = {name: (value, default, desc) for name, value, default, desc in ctx.rows()}

    assert rows['rustscan_batch'][0] == '100' and rows['rustscan_batch'][1] == '4500'
    assert all(desc for _, _, desc in rows.values())
    assert set(rows) == {'rustscan_batch', 'rustscan_timeout', 'user_agent'}
