import re
import shutil
import subprocess
from dataclasses import dataclass


@dataclass(frozen=True)
class FuzzMatch:
    path: str
    status_code: int
    size: int | None
    redirect: str | None


# `gobuster dir`'s default (non-expanded) result line, confirmed against a real
# gobuster 3.6 run — e.g.:
#   /admin                (Status: 301) [Size: 169] [--> http://target/admin/]
#   /index.html           (Status: 200) [Size: 1234]
# [Size: ...] and [--> ...] are each only printed when relevant, so both are
# optional in the pattern.
_LINE_RE = re.compile(
    r'^(?P<path>\S+)\s+\(Status:\s*(?P<status>\d+)\)'
    r'(?:\s+\[Size:\s*(?P<size>\d+)\])?'
    r'(?:\s+\[-->\s*(?P<redirect>\S+)\])?'
)

# Without `-q`, gobuster prefixes each result line with a "clear line" escape
# (`\x1b[2K`) — it clears its own live progress counter before printing a hit —
# and may colorize the status even with `--no-color` off on some builds. Strip
# any CSI escape before matching so the control bytes don't become part of the
# captured path. (Confirmed in real output: result lines arrive as
# `\r\x1b[2K/path  (Status: 200) [Size: N]`.)
_ANSI_RE = re.compile(r'\x1b\[[0-9;]*[A-Za-z]')


class GobusterError(RuntimeError):
    """gobuster ran but exited with a non-zero status (e.g. a wildcard/catch-all
    target it refuses to enumerate). Carries a human-readable, actionable message;
    the console surfaces it instead of silently reporting zero findings."""


class GobusterTool:
    """Thin wrapper around `gobuster dir` (directory/file enumeration).

    Unlike rustscan/nmap/subfinder, this sends a real, sizeable volume of
    HTTP requests to the target — it's active enumeration, not passive
    recon. The console checks scope before this ever runs, same as it does
    for `scan`'s target; it is never invoked automatically as part of
    `scan` or `recon`.

    On the stdout/stderr split: we capture **stdout** (the result lines, which
    we parse) but deliberately let **stderr inherit the terminal**. gobuster
    only prints its live `Progress: X / Y (pct%)` counter when stderr is a real
    TTY (it suppresses it entirely when piped) and only when `-q` is *not*
    passed, so dropping `-q` and not capturing stderr is what gives the user
    gobuster's native progress for free — the signal that it's running and not
    stuck. Any fatal error (e.g. the wildcard abort) also shows on the terminal
    live, and we detect it via the non-zero exit code.
    """

    binary = 'gobuster'

    @classmethod
    def is_available(cls) -> bool:
        return shutil.which(cls.binary) is not None

    @classmethod
    def enumerate(
        cls,
        url: str,
        wordlist: str,
        extensions: str | None = None,
        threads: int = 10,
        status_codes: str | None = None,
        exclude_length: str | None = None,
        timeout: int = 600,
    ) -> list[FuzzMatch]:
        if not cls.is_available():
            raise RuntimeError(
                f"'{cls.binary}' not found in PATH. Install gobuster "
                '(https://github.com/OJ/gobuster) before using the fuzz phase.'
            )

        # `--no-error` keeps per-request connection errors off the terminal
        # (the fatal wildcard abort still shows). `--no-color` keeps the result
        # lines on stdout free of color escapes. `-q` is intentionally NOT used:
        # it would suppress gobuster's own progress counter (see class docstring).
        command = [
            cls.binary, 'dir',
            '-u', url,
            '-w', wordlist,
            '--no-error', '--no-color',
            '-t', str(threads),
        ]
        if extensions:
            command += ['-x', extensions]
        if status_codes:
            command += ['-s', status_codes]
        if exclude_length:
            command += ['--exclude-length', exclude_length]

        # stdout captured for parsing; stderr left to inherit the terminal so
        # gobuster's live progress counter reaches the user.
        result = subprocess.run(command, stdout=subprocess.PIPE, text=True, timeout=timeout)
        if result.returncode != 0:
            raise GobusterError(
                f'gobuster exited with status {result.returncode} (see its error above). '
                'A common cause is a wildcard/catch-all target that answers every path the '
                'same way: if the error above mentions a matching length, tell gobuster to '
                'ignore it with set fuzz_exclude_length <size> (e.g. '
                "'set fuzz_exclude_length 459'), then run fuzz again."
            )
        return cls._parse_output(result.stdout)

    @staticmethod
    def _parse_output(output: str) -> list[FuzzMatch]:
        matches = []
        for line in output.splitlines():
            line = _ANSI_RE.sub('', line).strip()
            match = _LINE_RE.match(line)
            if not match:
                continue
            matches.append(FuzzMatch(
                path=match.group('path'),
                status_code=int(match.group('status')),
                size=int(match.group('size')) if match.group('size') else None,
                redirect=match.group('redirect'),
            ))
        return matches
