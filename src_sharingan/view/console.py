import sys
from prompt_toolkit import PromptSession
from prompt_toolkit.completion import WordCompleter
from prompt_toolkit.styles import Style
from rich.console import Console as RichConsole
from rich.prompt import Confirm
from rich.table import Table

from db.database import init_db, get_session
from services.whois_service import WhoisService
from services.set_env_service import SetEnvService
from model.host import Host
from model.service_model import ExploitMatch, Service, Vulnerability
from phases.scan.scan_phase import ScanPhase
from phases.scan.tools.installer import ToolInstaller

class InteractiveConsole:
    def __init__(self):
        self.console = RichConsole()
        self.session_db = get_session()
        self.env = {}
        self.cmds = {
            'clear': self.command_clear,
            'options': self.command_options,
            'exit': self.command_exit,
            'quit': self.command_exit,
            'help': self.command_help,
            'whois': self.command_whois,
            'set': self.command_set,
            'scan': self.command_scan,
            'hosts': self.command_hosts,
            'services': self.command_services,
            'vulns': self.command_vulns,
        }

        # Start the DB (creates tables if they don't exist yet)
        init_db()

        self.completer = WordCompleter([
            'whois', 'scan', 'help', 'exit', 'quit', 'clear', 'set', 'options',
            'hosts', 'services', 'vulns',
        ], ignore_case=True)

        self.style = Style.from_dict({
            'prompt': 'bold #ff2b2b',
        })

        self.prompt_session = PromptSession(
            completer=self.completer,
            style=self.style
        )

    def print_welcome(self):
        self.console.print("[bold red]Sharingan Advanced Enum Tool[/bold red]")
        self.console.print("Type [green]'help'[/green] to display available commands.")

    def run(self):
        self.print_welcome()

        while True:
            try:
                text = self.prompt_session.prompt([('class:prompt', 'Sharingan > ')])
                self.process_command(text)
            except KeyboardInterrupt:
                continue
            except EOFError:
                break

    def process_command(self, text: str):
        parts = text.strip().split()
        if not parts:
            return

        cmd_name = parts[0].lower()
        args = parts[1:]

        # Look up the command in the map. If it doesn't exist, fall back to the error handler.
        handler = self.cmds.get(cmd_name, self._cmd_unknown)
        handler(args)

    def _cmd_unknown(self, args):
        self.console.print("[red]Unknown command.[/red]")

    def command_whois(self, args):
        if not args:
            self.console.print("[red]Usage: whois <domain>[/red]")
            return

        domain = args[0]
        self.handle_whois(domain)

    def command_set(self, args):
        key = args[0]
        value = args[1]

        self.env = SetEnvService().set_env(key, value)

    def command_scan(self, args):
        if len(args) < 2:
            self.console.print("[red]Usage: scan <name> <ip/host>[/red]")
            return

        name, target = args[0], args[1]
        self.handle_scan(name, target)

    # -----------------------------------------------------------------
    # `hosts` / `services` / `vulns` — inspired by msfconsole's commands of the
    # same name: no argument lists, `-d <addr>` deletes one host's data,
    # `-d all` deletes everything (with confirmation, since it can't be undone).
    # -----------------------------------------------------------------

    def _confirm_delete_all(self, subject: str) -> bool:
        return Confirm.ask(
            f"This will delete {subject} for ALL hosts. Confirm?",
            default=False,
            console=self.console,
        )

    def _find_host_or_warn(self, addr: str):
        host = self.session_db.query(Host).filter_by(addr=addr).first()
        if not host:
            self.console.print(f"[red]Host '{addr}' not found.[/red]")
        return host

    def command_hosts(self, args):
        if args and args[0] == '-d':
            if len(args) < 2:
                self.console.print("[red]Usage: hosts -d <addr|all>[/red]")
                return
            target = args[1]
            if target == 'all':
                if not self._confirm_delete_all('all hosts'):
                    self.console.print("[yellow]Cancelled.[/yellow]")
                    return
                for host in self.session_db.query(Host).all():
                    self.session_db.delete(host)
                self.session_db.commit()
                self.console.print("[green]All hosts have been deleted.[/green]")
                return

            host = self._find_host_or_warn(target)
            if not host:
                return
            self.session_db.delete(host)
            self.session_db.commit()
            self.console.print(f"[green]Host '{target}' deleted.[/green]")
            return

        hosts = self.session_db.query(Host).order_by(Host.addr).all()
        if not hosts:
            self.console.print("[yellow]No hosts registered yet. Run 'scan' first.[/yellow]")
            return

        table = Table(title="Hosts")
        table.add_column("Name", style="cyan")
        table.add_column("Address", style="white")
        table.add_column("Active ports", style="green")
        for host in hosts:
            table.add_row(host.nome, host.addr, host.ports_active or '-')
        self.console.print(table)

    def command_services(self, args):
        if args and args[0] == '-d':
            if len(args) < 2:
                self.console.print("[red]Usage: services -d <addr|all>[/red]")
                return
            target = args[1]
            if target == 'all':
                if not self._confirm_delete_all('all services'):
                    self.console.print("[yellow]Cancelled.[/yellow]")
                    return
                for service in self.session_db.query(Service).all():
                    self.session_db.delete(service)
                self.session_db.commit()
                self.console.print("[green]All services have been deleted.[/green]")
                return

            host = self._find_host_or_warn(target)
            if not host:
                return
            for service in self.session_db.query(Service).filter_by(host_id=host.id).all():
                self.session_db.delete(service)
            self.session_db.commit()
            self.console.print(f"[green]Services for '{target}' deleted.[/green]")
            return

        query = self.session_db.query(Service).join(Host)
        if args:
            host = self._find_host_or_warn(args[0])
            if not host:
                return
            query = query.filter(Service.host_id == host.id)

        services = query.order_by(Host.addr, Service.port).all()
        table = Table(title="Services")
        table.add_column("Host", style="cyan")
        table.add_column("Port", justify="right")
        table.add_column("State", style="white")
        table.add_column("Service", style="white")
        for service in services:
            service_label = f"{service.product or service.name or '?'} {service.version or ''}".strip()
            table.add_row(service.host.addr, str(service.port), service.state, service_label)
        self.console.print(table)

    def command_vulns(self, args):
        if args and args[0] == '-d':
            if len(args) < 2:
                self.console.print("[red]Usage: vulns -d <addr|all>[/red]")
                return
            target = args[1]
            if target == 'all':
                if not self._confirm_delete_all('all vulnerabilities'):
                    self.console.print("[yellow]Cancelled.[/yellow]")
                    return
                for vuln in self.session_db.query(Vulnerability).all():
                    self.session_db.delete(vuln)
                self.session_db.commit()
                self.console.print("[green]All vulnerabilities have been deleted.[/green]")
                return

            host = self._find_host_or_warn(target)
            if not host:
                return
            vulns = (
                self.session_db.query(Vulnerability)
                .join(Service)
                .filter(Service.host_id == host.id)
                .all()
            )
            for vuln in vulns:
                self.session_db.delete(vuln)
            self.session_db.commit()
            self.console.print(f"[green]Vulnerabilities for '{target}' deleted.[/green]")
            return

        query = self.session_db.query(Vulnerability).join(Service).join(Host)
        if args:
            host = self._find_host_or_warn(args[0])
            if not host:
                return
            query = query.filter(Service.host_id == host.id)

        vulns = query.order_by(Vulnerability.cvss.desc()).all()
        if not vulns:
            self.console.print("[yellow]No vulnerabilities registered.[/yellow]")
            return

        table = Table(title="Vulnerabilities")
        table.add_column("Host", style="cyan")
        table.add_column("Port", justify="right")
        table.add_column("Service", style="white")
        table.add_column("CVE", style="white")
        table.add_column("CVSS", justify="right")
        table.add_column("Reference", style="white")
        for vuln in vulns:
            cvss_str = f"{vuln.cvss:.1f}" if vuln.cvss is not None else '-'
            service_label = f"{vuln.service.product or vuln.service.name or '?'} {vuln.service.version or ''}".strip()
            table.add_row(
                vuln.service.host.addr,
                str(vuln.service.port),
                service_label,
                vuln.cve,
                cvss_str,
                vuln.reference or '-',
            )
        self.console.print(table)

    def command_exit(self, args):
        sys.exit()

    def command_clear(self, args):
        self.console.clear()

    def command_options(self, args):
        self.console.print(args)
        self.handle_options()

    def command_help(self, args):
        self.print_help(args)

    def handle_options(self):
        table = Table(title="Options")
        table.add_column("Option", style="cyan")
        table.add_column("Value", style="white")
        for key, value in self.env.items():
            table.add_row(key, value)
        self.console.print(table)

    def handle_whois(self, domain: str):
        self.console.print(f"[*] Running whois on [bold cyan]{domain}[/bold cyan]...")
        whois_service = WhoisService(self.session_db)

        try:
            record = whois_service.perform_whois(domain)
            table = Table(title=f"WHOIS Result: {domain}")
            table.add_column("Property", justify="right", style="cyan")
            table.add_column("Value", style="white")

            table.add_row("Registrar", str(record.registrar))
            table.add_row("Creation Date", str(record.creation_date))
            table.add_row("Expiration Date", str(record.expiration_date))

            self.console.print(table)
            self.console.print("[green]Saved to database successfully![/green]")

        except Exception as e:
            self.console.print(f"[red]Error fetching whois data: {e}[/red]")

    def _ensure_tool_available(self, tool_name: str, tool_cls, required: bool) -> bool:
        """Makes sure (by asking the user) that an external tool is available.

        Returns True if the scan can proceed regarding this tool — it was
        already installed, the user just installed it, or it's optional and
        was declined/failed (in that case the phase just skips its step).
        Returns False only when a required tool is still unavailable.
        """
        if tool_cls.is_available():
            return True

        wants_to_install = Confirm.ask(
            f"'{tool_name}' was not found in PATH. Install it now?",
            default=True,
            console=self.console,
        )

        if wants_to_install:
            self.console.print(f"[*] Installing {tool_name}...")
            ToolInstaller.install(tool_name)

        if tool_cls.is_available():
            self.console.print(f"[green]{tool_name} available.[/green]")
            return True

        hint = ToolInstaller.manual_install_hint(tool_name)
        if required:
            self.console.print(
                f"[red]{tool_name} is still unavailable — can't run the scan without it.[/red]"
                + (f" Manual install: {hint}" if hint else '')
            )
            return False

        self.console.print(
            f"[yellow]Proceeding without {tool_name} — that step will be skipped.[/yellow]"
            + (f" Manual install: {hint}" if hint else '')
        )
        return True

    def _report_scan_progress(self, step: str) -> None:
        """Callback passed to `ScanPhase.run` — prints each step (rustscan /
        nmap / searchsploit) as it actually starts, instead of a single static
        message sitting there until the whole scan finishes."""
        self.console.print(f"[*] {step}")

    def handle_scan(self, name: str, target: str):
        """Scan phase: rustscan (discovery) -> nmap -sV (fingerprint) -> searchsploit (exploits)."""
        scan_phase = ScanPhase(self.session_db)

        if not self._ensure_tool_available('rustscan', scan_phase.rustscan, required=True):
            return
        if not self._ensure_tool_available('nmap', scan_phase.nmap, required=True):
            return
        self._ensure_tool_available('searchsploit', scan_phase.searchsploit, required=False)

        if not scan_phase.vulners.is_available():
            hint = ToolInstaller.manual_install_hint('vulners')
            self.console.print(
                "[yellow]NSE script 'vulners' not found — skipping CVE/CVSS correlation "
                "(searchsploit still runs normally).[/yellow]"
                + (f" Setup: {hint}" if hint else '')
            )

        self.console.print(f"[*] Starting scan of [bold cyan]{target}[/bold cyan]...")

        try:
            host_record = scan_phase.run(name=name, target=target, on_progress=self._report_scan_progress)
        except RuntimeError as e:
            # External tool missing from PATH (rustscan/nmap/searchsploit) — not a
            # bug, an environment prerequisite.
            self.console.print(f"[red]{e}[/red]")
            return
        except Exception as e:
            self.console.print(f"[red]Error during scan: {e}[/red]")
            return

        services = (
            self.session_db.query(Service)
            .filter_by(host_id=host_record.id)
            .order_by(Service.port)
            .all()
        )

        table = Table(title=f"Scan Result: {name} ({target})")
        table.add_column("Port", justify="right", style="cyan")
        table.add_column("State", justify="left")
        table.add_column("Service", style="white")

        for service in services:
            state_label = "[green]Open[/green]" if service.state == 'open' else f"[red]{service.state}[/red]"
            service_label = f"{service.product or service.name or '?'} {service.version or ''}".strip()
            table.add_row(str(service.port), state_label, service_label)

        self.console.print(table)

        vulnerabilities = (
            self.session_db.query(Vulnerability)
            .join(Service)
            .filter(Service.host_id == host_record.id)
            .order_by(Vulnerability.cvss.desc())
            .all()
        )

        if vulnerabilities:
            vuln_table = Table(title="Vulnerabilities (CVE/CVSS via vulners)")
            vuln_table.add_column("Port", justify="right", style="cyan")
            vuln_table.add_column("CVE", style="white")
            vuln_table.add_column("CVSS", justify="right")
            vuln_table.add_column("Reference", style="white")
            for vuln in vulnerabilities:
                cvss_str = f"{vuln.cvss:.1f}" if vuln.cvss is not None else '-'
                vuln_table.add_row(str(vuln.service.port), vuln.cve, cvss_str, vuln.reference or '-')
            self.console.print(vuln_table)
        elif scan_phase.last_vulners_enabled:
            # vulners ran (embedded in nmap -sV) and found nothing relevant —
            # make that explicit, otherwise it's indistinguishable from "the
            # step never ran at all".
            self.console.print(
                "[green]No relevant vulnerabilities found (vulners).[/green]"
            )

        exploits = (
            self.session_db.query(ExploitMatch)
            .join(Service)
            .filter(Service.host_id == host_record.id)
            .all()
        )

        if exploits:
            exploit_table = Table(title="Exploits found (searchsploit)")
            exploit_table.add_column("EDB-ID", style="cyan")
            exploit_table.add_column("Title", style="white")
            for exploit in exploits:
                exploit_table.add_row(exploit.edb_id or '-', exploit.title)
            self.console.print(exploit_table)
        elif scan_phase.last_searchsploit_error:
            # searchsploit was available but failed at runtime (e.g. missing
            # xmllint) — ScanPhase already absorbed the exception and kept the
            # rest of the scan standing; here we just warn, instead of
            # pretending nothing was found.
            self.console.print(
                f"[red]searchsploit failed to run: {scan_phase.last_searchsploit_error}[/red]"
            )
        elif scan_phase.last_searchsploit_ran:
            self.console.print("[yellow]No matching exploit found in searchsploit.[/yellow]")
        elif scan_phase.last_vulners_enabled:
            # vulners available but no relevant finding -> by design searchsploit
            # doesn't even run (see ScanPhase.run). Making this explicit avoids
            # the "where's the searchsploit result?" confusion when it was
            # never executed.
            self.console.print(
                "[yellow]searchsploit did not run — vulners found nothing "
                "relevant (CVSS above the minimum) to make the search worthwhile.[/yellow]"
            )

        self.console.print("[green]Scan result saved to database![/green]")

    def print_help(self, args=None):
        table = Table(title="Available Commands")
        table.add_column("Command", style="cyan")
        table.add_column("Description", style="white")
        table.add_row("whois <domain>", "Run a whois query against the domain and save it.")
        table.add_row("scan <name> <ip/host>", "Rustscan + nmap -sV + searchsploit; save to DB.")
        table.add_row("hosts [-d <addr|all>]", "List hosts, or delete one host (cascades) / all hosts.")
        table.add_row("services [addr] [-d <addr|all>]", "List services (optionally by host), or delete them.")
        table.add_row("vulns [addr] [-d <addr|all>]", "List vulnerabilities (optionally by host), or delete them.")
        table.add_row("set <key> <value>", "Set a session variable.")
        table.add_row("options", "Show session variables.")
        table.add_row("clear", "Clear the terminal screen.")
        table.add_row("exit / quit", "Exit the console.")
        self.console.print(table)
