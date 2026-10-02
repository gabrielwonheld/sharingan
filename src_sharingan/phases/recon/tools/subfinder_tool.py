import json
import shutil
import subprocess


class SubfinderTool:
    """Thin wrapper around ProjectDiscovery's `subfinder` (passive subdomain discovery).

    Purely passive: it only queries public sources (certificate transparency
    logs, search engines, DNS aggregators) — unlike rustscan/nmap, it never
    sends traffic to the target itself.
    """

    binary = 'subfinder'

    @classmethod
    def is_available(cls) -> bool:
        return shutil.which(cls.binary) is not None

    @classmethod
    def find_subdomains(cls, domain: str, timeout: int = 120) -> list[str]:
        if not cls.is_available():
            raise RuntimeError(
                f"'{cls.binary}' not found in PATH. Install subfinder "
                '(https://github.com/projectdiscovery/subfinder) before using the recon phase.'
            )

        # `-silent` suppresses the banner/stats lines so stdout is clean NDJSON;
        # `-json` gives one JSON object per line (no `check=True`: some passive
        # sources can fail individually without subfinder's own exit code
        # reliably reflecting that, and a partial result is still useful).
        result = subprocess.run(
            [cls.binary, '-d', domain, '-silent', '-json'],
            capture_output=True, text=True, timeout=timeout,
        )
        return cls._parse_ndjson(result.stdout)

    @staticmethod
    def _parse_ndjson(output: str) -> list[str]:
        names = set()
        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
            except json.JSONDecodeError:
                continue
            host = data.get('host')
            if host:
                names.add(host.strip().lower())
        return sorted(names)
