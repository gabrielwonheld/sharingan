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

    On the stdout/stderr split: gobuster only prints its live
    `Progress: X / Y (pct%)` counter when stderr is a **real TTY** — it suppresses
    it entirely when stderr is a pipe — and only when `-q` is *not* passed. So the
    normal run leaves **stderr inherited** (the child writes straight to the
    terminal fd, below prompt_toolkit, exactly as before) to keep that live
    progress, and only captures **stdout** (the result lines we parse). Piping
    stderr would silently kill the counter (that was a real regression). To learn
    *why* a run failed (the wildcard/catch-all abort names the length to exclude),
    we re-run once with stderr captured — the abort happens immediately at
    startup, before any enumeration, so there's no progress to lose on that
    throwaway run. That's what lets us auto-calibrate past a wildcard
    (`--exclude-length`), the way feroxbuster does, without sacrificing progress.
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
    def _run(command, timeout, capture_stderr):
        """Runs gobuster once. With `capture_stderr=False` (the normal run) stderr
        is **inherited** — the child writes its live progress counter straight to
        the terminal. With `capture_stderr=True` (a throwaway run after a failure)
        stderr is piped so we can read the abort message. Returns
        (returncode, stdout, stderr); stderr is '' when not captured.

        Injected via `enumerate(..., runner=...)` in tests, so the test suite
        never spawns a real process or touches the network.
        """
        stderr = subprocess.PIPE if capture_stderr else None
        result = subprocess.run(
            command, stdout=subprocess.PIPE, stderr=stderr, text=True, timeout=timeout
        )
        return result.returncode, result.stdout, (result.stderr or '')

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

        run = runner or cls._run
        command = cls._build_command(url, wordlist, extensions, threads, status_codes, exclude_length)

        # Normal run: stderr inherited, so gobuster's progress counter shows live.
        returncode, stdout, _ = run(command, timeout, False)
        if returncode == 0:
            return cls._parse_output(stdout)

        # Failed — re-run capturing stderr (a wildcard abort is immediate, no
        # progress to lose) to read *why*, so we can auto-calibrate or explain.
        _, _, stderr = run(command, timeout, True)
        length = cls._wildcard_length(stderr) or cls._wildcard_length(stdout)

        # Auto-calibrate past a wildcard/catch-all exactly once, and only when the
        # user hasn't pinned an exclude-length themselves: re-run telling gobuster
        # to ignore the length it just reported.
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

        # A connection timeout/refusal is a different failure than a wildcard — and
        # a common one right after aggressive fuzzing, when the target firewalls the
        # source IP. Say that, instead of the misleading "set fuzz_exclude_length".
        if length is None and cls._looks_like_connectivity_failure(stderr):
            raise GobusterError(cls._connectivity_message(url))

        raise GobusterError(cls._failure_message(exclude_length, length))

    # gobuster's own wording when it can't reach the target (Go's net/http): a
    # timeout, a refused connection, or an unresolvable/unreachable host.
    _CONNECTIVITY_MARKERS = (
        'context deadline exceeded',
        'client.timeout',
        'unable to connect',
        'connection refused',
        'no such host',
        'no route to host',
        'network is unreachable',
    )

    @classmethod
    def _looks_like_connectivity_failure(cls, text: str) -> bool:
        if not text:
            return False
        low = text.lower()
        return any(marker in low for marker in cls._CONNECTIVITY_MARKERS)

    @staticmethod
    def _connectivity_message(url: str) -> str:
        return (
            f"gobuster could not connect to {url} (timeout/refused). The target may be "
            'down or — common right after fuzzing — may have blocked your source IP '
            '(firewall/fail2ban). Check connectivity (e.g. curl the URL), wait for any '
            'ban to lift, and lower the request rate (set fuzz_threads to a small value) '
            'before retrying.'
        )

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
