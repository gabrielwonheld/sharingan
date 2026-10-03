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


# `gobuster dir`'s default (non-expanded) output line, confirmed against
# gobuster 3.6's own `-h` flag reference — e.g.:
#   /admin                (Status: 301) [Size: 169] [--> http://target/admin/]
#   /index.html           (Status: 200) [Size: 1234]
# [Size: ...] and [--> ...] are each only printed when relevant, so both are
# optional in the pattern.
_LINE_RE = re.compile(
    r'^(?P<path>\S+)\s+\(Status:\s*(?P<status>\d+)\)'
    r'(?:\s+\[Size:\s*(?P<size>\d+)\])?'
    r'(?:\s+\[-->\s*(?P<redirect>\S+)\])?'
)


class GobusterTool:
    """Thin wrapper around `gobuster dir` (directory/file enumeration).

    Unlike rustscan/nmap/subfinder, this sends a real, sizeable volume of
    HTTP requests to the target — it's active enumeration, not passive
    recon. The console checks scope before this ever runs, same as it does
    for `scan`'s target; it is never invoked automatically as part of
    `scan` or `recon`.
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
        timeout: int = 600,
    ) -> list[FuzzMatch]:
        if not cls.is_available():
            raise RuntimeError(
                f"'{cls.binary}' not found in PATH. Install gobuster "
                '(https://github.com/OJ/gobuster) before using the fuzz phase.'
            )

        # `-q`/`--no-error` keep stdout to just result lines (no banner, no
        # progress, no connection-error noise) so `_parse_output` doesn't
        # need to guess what's a result and what isn't.
        command = [
            cls.binary, 'dir',
            '-u', url,
            '-w', wordlist,
            '-q', '--no-error',
            '-t', str(threads),
        ]
        if extensions:
            command += ['-x', extensions]
        if status_codes:
            command += ['-s', status_codes]

        result = subprocess.run(command, capture_output=True, text=True, timeout=timeout)
        return cls._parse_output(result.stdout)

    @staticmethod
    def _parse_output(output: str) -> list[FuzzMatch]:
        matches = []
        for line in output.splitlines():
            line = line.strip()
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
