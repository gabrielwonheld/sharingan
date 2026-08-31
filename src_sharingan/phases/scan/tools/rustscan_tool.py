import shutil
import subprocess


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
    def scan_ports(cls, target: str, timeout_ms: int = 3000, batch_size: int = 4500) -> list[int]:
        if not cls.is_available():
            raise RuntimeError(
                f"'{cls.binary}' not found in PATH. Install rustscan "
                '(https://github.com/RustScan/RustScan) before using the scan phase.'
            )

        # `--no-nmap` was removed from RustScan (no longer exists in the project's
        # `src/input.rs`, and there's an open issue — "Bring back --no-nmap!" — asking
        # for it to come back). Passing a flag clap doesn't recognize makes the process
        # exit with status 2 (usage error), which `check=True` turns into a
        # `CalledProcessError`. `-g/--greppable` alone is already enough: it makes
        # rustscan just print `host -> [ports]`, without invoking its embedded nmap
        # (the actual fingerprinting is still done afterward by NmapTool).
        result = subprocess.run(
            [
                cls.binary,
                '-a', target,
                '-b', str(batch_size),
                '-t', str(timeout_ms),
                '-g',
            ],
            capture_output=True,
            text=True,
            check=True,
        )
        return cls._parse_greppable_output(result.stdout)

    @staticmethod
    def _parse_greppable_output(output: str) -> list[int]:
        """rustscan's greppable format (`-g`): one line per host, `host -> [port,port,...]`."""
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
