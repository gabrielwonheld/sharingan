import shutil
import subprocess
import xml.etree.ElementTree as ET
from dataclasses import dataclass


@dataclass
class ServiceFingerprint:
    port: int
    protocol: str
    state: str
    product: str | None
    version: str | None
    banner: str | None
    # nmap's own guess at the service running on this port (the XML `<service
    # name="...">` attribute) — populated even when `product`/`version` are None,
    # e.g. when `-sV` can't grab a banner but still maps the port number against
    # nmap-services (`method="table"` in the XML, vs. a confirmed `method="probed"`
    # when a version probe actually matched). Defaulted so existing positional
    # `ServiceFingerprint(...)` call sites (tests, fakes) keep working unchanged.
    name: str | None = None


class NmapTool:
    """Thin wrapper around `nmap -sV` (service/version fingerprinting).

    Takes the list of already-discovered ports (normally from RustscanTool) to
    run only on them — it doesn't do port discovery on its own.
    """

    binary = 'nmap'

    @classmethod
    def is_available(cls) -> bool:
        return shutil.which(cls.binary) is not None

    @classmethod
    def fingerprint(
        cls,
        target: str,
        ports: list[int],
        xml_output_path: str,
        extra_args: list[str] | None = None,
    ) -> list[ServiceFingerprint]:
        """extra_args lets NSE scripts (e.g. `--script vulners`) be embedded in the
        same `-sV` command, without NmapTool needing to know anything about that
        script — the caller decides what to pass (see `VulnersTool.build_nmap_args`)."""
        if not ports:
            return []

        if not cls.is_available():
            raise RuntimeError(
                f"'{cls.binary}' not found in PATH. Install nmap before using the scan phase."
            )

        port_arg = ','.join(str(p) for p in ports)
        command = [cls.binary, '-sV', '-p', port_arg]
        if extra_args:
            command.extend(extra_args)
        command.extend(['-oX', xml_output_path, target])

        subprocess.run(command, capture_output=True, text=True, check=True)
        return cls._parse_xml(xml_output_path)

    @staticmethod
    def _parse_xml(xml_path: str) -> list[ServiceFingerprint]:
        tree = ET.parse(xml_path)
        root = tree.getroot()

        services: list[ServiceFingerprint] = []
        for host in root.findall('host'):
            ports_el = host.find('ports')
            if ports_el is None:
                continue

            for port_el in ports_el.findall('port'):
                port_num = int(port_el.get('portid'))
                protocol = port_el.get('protocol', 'tcp')

                state_el = port_el.find('state')
                state = state_el.get('state') if state_el is not None else 'unknown'

                service_el = port_el.find('service')
                product = service_el.get('product') if service_el is not None else None
                version = service_el.get('version') if service_el is not None else None
                name = service_el.get('name') if service_el is not None else None

                banner = None
                if service_el is not None:
                    parts = [
                        p for p in (
                            service_el.get('product'),
                            service_el.get('version'),
                            service_el.get('extrainfo'),
                        ) if p
                    ]
                    banner = ' '.join(parts) if parts else None

                services.append(ServiceFingerprint(port_num, protocol, state, product, version, banner, name))

        return services
