import re
import shutil
import subprocess
import sys
import threading
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

# gobuster's wildcard/catch-all abort names the exact response length it saw, e.g.:
#   Error: the server returns a status code that matches ... => 301 (Length: 795).
# We parse that number straight from gobuster's own message and retry with
# `--exclude-length <N>` — using gobuster's own measurement guarantees the value
# matches what it compares against (far more reliable than probing the length
# ourselves), which is how we auto-calibrate past a wildcard the way feroxbuster
# does on its own.
_WILDCARD_LENGTH_RE = re.compile(r'=>\s*\d+\s*\(Length:\s*(\d+)\)')


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
    we parse) and we also capture **stderr** while still streaming it to the
    terminal live (see `_run_streaming`). gobuster only prints its live
    `Progress: X / Y (pct%)` counter when stderr is a real TTY (it suppresses it
    entirely when piped) and only when `-q` is *not* passed, so dropping `-q` and
    forwarding stderr byte-for-byte is what gives the user gobuster's native
    progress — the signal that it's running and not stuck. Capturing stderr as
    well lets us read gobuster's wildcard/catch-all abort message and
    auto-calibrate past it (`--exclude-length`), the way feroxbuster does.
    """

    binary = 'gobuster'

    @classmethod
    def is_available(cls) -> bool:
        return shutil.which(cls.binary) is not None

    @staticmethod
    def _build_command(url, wordlist, extensions, threads, status_codes, exclude_length):
        # `--no-error` keeps per-request connection errors off the terminal (the
        # fatal wildcard abort still shows). `--no-color` keeps the result lines
        # on stdout free of color escapes. `-q` is intentionally NOT used: it
        # would suppress gobuster's own progress counter (see class docstring).
        command = [
            GobusterTool.binary, 'dir',
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
        return command

    @staticmethod
    def _run_streaming(command, timeout):
        """Runs gobuster, streaming stderr to the terminal live (byte for byte,
        so the `\\r`-updated progress counter keeps working) while also capturing
        it, and capturing stdout for parsing. Returns (returncode, stdout, stderr).

        Injected via `enumerate(..., runner=...)` in tests, so the test suite
        never spawns a real process or touches the network.
        """
        proc = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        captured: list[bytes] = []

        def pump_stderr():
            # One byte at a time so a `\r`-terminated progress line reaches the
            # terminal immediately instead of being buffered until a newline.
            for chunk in iter(lambda: proc.stderr.read(1), b''):
                try:
                    sys.stderr.buffer.write(chunk)
                    sys.stderr.buffer.flush()
                except Exception:
                    pass
                captured.append(chunk)

        pump = threading.Thread(target=pump_stderr, daemon=True)
        pump.start()
        killer = threading.Timer(timeout, proc.kill)
        killer.start()
        try:
            out_bytes = proc.stdout.read()
            proc.wait()
        finally:
            killer.cancel()
        pump.join(timeout=1)
        return (
            proc.returncode,
            out_bytes.decode(errors='replace'),
            b''.join(captured).decode(errors='replace'),
        )

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
        auto_calibrate: bool = True,
        on_notice=None,
        runner=None,
    ) -> list[FuzzMatch]:
        if not cls.is_available():
            raise RuntimeError(
                f"'{cls.binary}' not found in PATH. Install gobuster "
                '(https://github.com/OJ/gobuster) before using the fuzz phase.'
            )

        run = runner or cls._run_streaming
        command = cls._build_command(url, wordlist, extensions, threads, status_codes, exclude_length)
        returncode, stdout, stderr = run(command, timeout)

        if returncode != 0:
            length = cls._wildcard_length(stderr) or cls._wildcard_length(stdout)
            # Auto-calibrate past a wildcard/catch-all exactly once, and only when
            # the user hasn't pinned an exclude-length themselves: re-run telling
            # gobuster to ignore the length it just reported.
            if auto_calibrate and not exclude_length and length is not None:
                if on_notice:
                    on_notice(
                        f'Catch-all detected (gobuster saw length {length}); '
                        f'retrying with --exclude-length {length}.'
                    )
                return cls.enumerate(
                    url, wordlist, extensions=extensions, threads=threads,
                    status_codes=status_codes, exclude_length=str(length),
                    timeout=timeout, auto_calibrate=False, on_notice=on_notice, runner=run,
                )
            raise GobusterError(cls._failure_message(exclude_length, length))

        return cls._parse_output(stdout)

    @staticmethod
    def _wildcard_length(text: str) -> int | None:
        if not text:
            return None
        match = _WILDCARD_LENGTH_RE.search(text)
        return int(match.group(1)) if match else None

    @staticmethod
    def _failure_message(exclude_length, length) -> str:
        if exclude_length:
            # The user already set an exclude-length and gobuster still refuses —
            # usually a catch-all whose length varies per path (so a single value
            # can't match). gobuster's --exclude-length takes a comma list / ranges.
            extra = f' (gobuster now reports length {length})' if length else ''
            return (
                f'gobuster still exits non-zero with fuzz_exclude_length={exclude_length}{extra}. '
                'The catch-all length probably varies per path; try a range or several '
                "values, e.g. 'set fuzz_exclude_length 780-810'."
            )
        return (
            'gobuster exited non-zero (see its error above). A common cause is a '
            'wildcard/catch-all target that answers every path the same way. If the '
            "error above mentions a matching length, set 'fuzz_exclude_length <size>' "
            'and run fuzz again.'
        )

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
