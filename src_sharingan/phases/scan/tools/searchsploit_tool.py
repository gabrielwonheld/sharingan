import json
import shutil
import subprocess


class SearchsploitTool:
    """Thin wrapper around `searchsploit -t <product>` (exploitdb package).

    Runs one title-only text search per product/service `ScanPhase` already
    fingerprinted, returning the exploit-db entries that match. Deliberately
    not `searchsploit --nmap <xml>`: that mode does its own per-service text
    search internally with no way to know which result came from which
    service (see CLAUDE.md's "exploit<->service association" note) and
    depends on `xmllint` to parse the XML file — a plain product search has
    neither problem.
    """

    binary = 'searchsploit'

    @classmethod
    def is_available(cls) -> bool:
        return shutil.which(cls.binary) is not None

    @classmethod
    def search_product(cls, product: str) -> list[dict]:
        if shutil.which(cls.binary) is None:
            raise RuntimeError(
                f"'{cls.binary}' not found in PATH. Install exploitdb "
                '(apt install exploitdb, or https://github.com/offensive-security/exploitdb) '
                'before using exploit correlation.'
            )

        result = subprocess.run(
            [cls.binary, '-t', product, '-j'],
            capture_output=True,
            text=True,
            check=True,
        )
        return cls._parse_json(result.stdout)

    @staticmethod
    def _parse_json(output: str) -> list[dict]:
        # A direct product search normally returns exactly one JSON object on
        # stdout, but decode it as a stream rather than a single `json.loads()`
        # call anyway: that's what it took to fix a real bug in the `--nmap`
        # mode this method replaces (multiple concatenated JSON objects on
        # stdout silently lost real matches to a `JSONDecodeError`), and
        # staying robust to it here is free insurance.
        text = output.strip()
        if not text:
            return []
        decoder = json.JSONDecoder()
        results: list[dict] = []
        seen_ids: set[str] = set()
        pos = 0
        length = len(text)
        while pos < length:
            while pos < length and text[pos].isspace():
                pos += 1
            if pos >= length:
                break
            try:
                data, end = decoder.raw_decode(text, pos)
            except json.JSONDecodeError:
                break
            for exploit in data.get('RESULTS_EXPLOIT', []):
                edb_id = exploit.get('EDB-ID')
                if edb_id in seen_ids:
                    continue
                seen_ids.add(edb_id)
                results.append(exploit)
            pos = end
        return results
