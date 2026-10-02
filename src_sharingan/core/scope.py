import ipaddress
import re
from dataclasses import dataclass

_HOSTNAME_LABEL = re.compile(r'^(?!-)[a-z0-9-]{1,63}(?<!-)$')


def parse_scope_value(raw: str) -> tuple[str, str]:
    """Detects what a scope entry is and normalizes it -> (kind, value).

    CIDR and IP are checked first; anything else must be a hostname. A leading
    `*.` is accepted and means the same as the bare domain.
    """
    value = raw.strip().lower()
    if not value:
        raise ValueError('Scope value must not be empty.')

    if '/' in value:
        try:
            return 'cidr', str(ipaddress.ip_network(value, strict=False))
        except ValueError:
            raise ValueError(f"'{raw}' is not a valid CIDR range.") from None
    try:
        return 'ip', str(ipaddress.ip_address(value))
    except ValueError:
        pass

    hostname = value.removeprefix('*.').rstrip('.')
    labels = hostname.split('.')
    if not hostname or not all(_HOSTNAME_LABEL.match(label) for label in labels):
        raise ValueError(f"'{raw}' is not a valid domain, IP or CIDR range.")
    return 'domain', hostname


@dataclass(frozen=True)
class ScopeDecision:
    allowed: bool
    reason: str
    # True when there are no include rules at all (nothing restricts the target)
    unrestricted: bool = False


def _matches(target: str, kind: str, value: str) -> bool:
    try:
        address = ipaddress.ip_address(target)
    except ValueError:
        address = None

    if address is not None:
        if kind == 'ip':
            return address == ipaddress.ip_address(value)
        if kind == 'cidr':
            network = ipaddress.ip_network(value)
            return address.version == network.version and address in network
        return False

    if kind == 'domain':
        return target == value or target.endswith('.' + value)
    return False


def decide(target: str, rules) -> ScopeDecision:
    """Whether `target` may be scanned. `rules` is an iterable of (kind, value, allow).

    Matching is literal (no DNS resolution): a hostname only matches domain
    rules, an IP only matches ip/cidr rules. Exclusions always win. With no
    include rules at all, scope is unrestricted (apart from exclusions).
    """
    target = target.strip().lower().rstrip('.')
    rules = list(rules)
    excludes = [r for r in rules if not r[2]]
    includes = [r for r in rules if r[2]]

    for kind, value, _ in excludes:
        if _matches(target, kind, value):
            return ScopeDecision(False, f"'{target}' is excluded from scope ({value}).")

    if not includes:
        return ScopeDecision(True, 'No scope defined.', unrestricted=True)

    for kind, value, _ in includes:
        if _matches(target, kind, value):
            return ScopeDecision(True, f"'{target}' is in scope ({value}).")
    return ScopeDecision(False, f"'{target}' is out of scope.")
