import shutil
import subprocess
from typing import Callable


class RustscanTool:
    """Thin wrapper around the `rustscan` binary (fast open-TCP-port discovery).

    Only does port discovery — service/version fingerprinting is NmapTool's
    job, called next by the scan phase only on the ports rustscan found open.
    """

    binary = 'rustscan'

    @classmethod
    def is_available(cls) -> bool:
        return shutil.which(cls.binary) is not None

    @classmethod
    def scan_ports(
        cls,
        target: str,
        timeout_ms: int = 3000,
        batch_size: int = 4500,
        on_line: Callable[[str], None] | None = None,
    ) -> list[int]:
        if not cls.is_available():
            raise RuntimeError(
                f"'{cls.binary}' not found in PATH. Install rustscan "
                '(https://github.com/RustScan/RustScan) before using the scan phase.'
            )

        # Two flags deliberately NOT here:
        #  - `--no-nmap` was removed from RustScan (no longer in src/input.rs, see the open
        #    "Bring back --no-nmap!" issue #650) — passing it makes clap reject the arguments
        #    and the process exit with status 2.
        #  - `-g/--greppable` *does* skip the embedded nmap, but it also suppresses rustscan's
        #    incremental `Open host:port` lines, so during a long full-range scan the user got
        #    no feedback at all and couldn't tell a working scan from a hung one. `--scripts none`
        #    skips the embedded nmap the same way, while rustscan still prints each `Open ...`
        #    line as it finds the port. We stream those lines out through `on_line` so the
        #    console can show ports appearing live; the trailing `host -> [ports]` summary line
        #    rustscan prints is still there, and that's what we parse for the result.
        command = [
            cls.binary,
            '-a', target,
            '-b', str(batch_size),
            '-t', str(timeout_ms),
            '--scripts', 'none',
            '--no-banner',
        ]

        collected: list[str] = []
        with subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            bufsize=1,
        ) as proc:
            for raw in proc.stdout:
                line = raw.rstrip('\n')
                collected.append(line)
                if on_line is not None and line.startswith('Open '):
                    on_line(line)
            returncode = proc.wait()

        if returncode != 0:
            raise subprocess.CalledProcessError(returncode, command, output='\n'.join(collected))

        return cls._parse_greppable_output('\n'.join(collected))

    @staticmethod
    def _parse_greppable_output(output: str) -> list[int]:
        """rustscan prints a summary line per host, `host -> [port,port,...]`."""
        ports: list[int] = []
        for line in output.splitlines():
            if '->' not in line:
                continue
            _, _, ports_part = line.partition('->')
            ports_part = ports_part.strip().strip('[]')
            for item in ports_part.split(','):
                item = item.strip()
                if item.isdigit():
                    ports.append(int(item))
        return sorted(set(ports))
