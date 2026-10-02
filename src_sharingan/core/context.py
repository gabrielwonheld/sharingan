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


def _non_empty_text(raw: str) -> str:
    value = raw.strip()
    if not value:
        raise ValueError('must not be empty.')
    return value


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
        'User-Agent for HTTP requests (used by the web phase, not by port scans).',
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
