from dataclasses import dataclass
from typing import Callable


def _positive_int(raw: str) -> int:
    try:
        value = int(raw)
    except ValueError:
        raise ValueError(f"'{raw}' is not a whole number.") from None
    if value <= 0:
        raise ValueError('must be greater than zero.')
    return value


def _non_negative_float(raw: str) -> float:
    try:
        value = float(raw)
    except ValueError:
        raise ValueError(f"'{raw}' is not a number.") from None
    if value < 0:
        raise ValueError('must not be negative.')
    return value


def _non_empty_text(raw: str) -> str:
    value = raw.strip()
    if not value:
        raise ValueError('must not be empty.')
    return value


def _optional_text(raw: str) -> str:
    # Unlike `_non_empty_text`, an empty value is valid here: it means
    # "not configured yet" (e.g. `fuzz_wordlist` has no sane universal
    # default — there's no wordlist Sharingan can assume is on disk).
    return raw.strip()


@dataclass(frozen=True)
class OptionSpec:
    default: object
    parse: Callable[[str], object]
    description: str


# Every option the console accepts with `set`. Add new ones here only: `set`,
# `unset` and `options` all read from this table.
OPTIONS: dict[str, OptionSpec] = {
    'rustscan_batch': OptionSpec(
        4500, _positive_int,
        'Ports rustscan probes at once (lower it for slow or filtered remote hosts).',
    ),
    'rustscan_timeout': OptionSpec(
        3000, _positive_int,
        'Milliseconds rustscan waits for each port (raise it for distant hosts).',
    ),
    'user_agent': OptionSpec(
        'Sharingan', _non_empty_text,
        "User-Agent for HTTP requests ('crawl' sends it; port scans don't use HTTP).",
    ),
    'fuzz_wordlist': OptionSpec(
        '', _optional_text,
        "Path to the wordlist 'fuzz' passes to gobuster (-w). Required before running fuzz.",
    ),
    'fuzz_extensions': OptionSpec(
        '', _optional_text,
        "Comma-separated extensions 'fuzz' passes to gobuster (-x), e.g. 'php,txt,bak'. Optional.",
    ),
    'fuzz_threads': OptionSpec(
        10, _positive_int,
        "Concurrent threads 'fuzz' passes to gobuster (-t).",
    ),
    'spider_max_depth': OptionSpec(
        3, _positive_int,
        "How many links deep 'crawl' follows from the start URL.",
    ),
    'spider_max_pages': OptionSpec(
        100, _positive_int,
        "Most pages 'crawl' fetches in one run.",
    ),
    'spider_delay': OptionSpec(
        0.5, _non_negative_float,
        "Seconds 'crawl' waits between requests (0 = no pause).",
    ),
}


class SessionContext:
    """The console session's settings (`set` / `unset` / `options`).

    Lives in memory for the session only. Values are validated and converted to
    the option's type on `set`, so consumers can trust them.
    """

    def __init__(self) -> None:
        self._values: dict[str, object] = {}

    @staticmethod
    def _spec(name: str) -> OptionSpec:
        if name not in OPTIONS:
            raise ValueError(f"Unknown option '{name}'. Valid options: {', '.join(OPTIONS)}.")
        return OPTIONS[name]

    def get(self, name: str):
        spec = self._spec(name)
        return self._values.get(name, spec.default)

    def set(self, name: str, raw_value: str) -> None:
        spec = self._spec(name)
        try:
            value = spec.parse(raw_value)
        except ValueError as e:
            raise ValueError(f"Invalid value for {name}: {e}") from None
        self._values[name] = value

    def unset(self, name: str) -> None:
        self._spec(name)
        self._values.pop(name, None)

    def rows(self) -> list[tuple[str, str, str, str]]:
        """(name, current value, default, description), all as strings, for display."""
        return [
            (name, str(self.get(name)), str(spec.default), spec.description)
            for name, spec in OPTIONS.items()
        ]
