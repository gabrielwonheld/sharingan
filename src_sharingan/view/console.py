import sys
from prompt_toolkit import PromptSession
from prompt_toolkit.completion import WordCompleter
from prompt_toolkit.styles import Style
from rich.console import Console as RichConsole
from rich.prompt import Confirm
from rich.table import Table

from db.database import init_db, get_session
from core.context import SessionContext
from core.scope import decide, parse_scope_value
from phases.recon.recon_phase import ReconPhase
from phases.scan.scan_diff import diff_scan_runs
from services.whois_service import WhoisService
from model.host import Host
from model.scope_model import ScopeRule
from model.service_model import ScanRun, Service, Vulnerability, current_services_filter
from phases.scan.scan_phase import ScanPhase
from phases.scan.tools.installer import ToolInstaller

# `searchsploit -t <product>` does plain text matching with no version
# awareness, so a common product can return dozens of hits spanning every
# version ever published. Capping keeps the table scannable; anyone who wants
# the full list can still run `searchsploit <product>` themselves.
EXPLOIT_DISPLAY_CAP = 10


def _exploit_matched_cve(exploit, known_cves: set) -> str | None:
    """Returns the CVE from `exploit.cve_codes` (exploit-db's own `Codes`
    field, e.g. "CVE-2008-3234;OSVDB-48791") that overlaps with `known_cves`
    (the CVEs vulners already confirmed for this same service), or None.

    This is the noise-reduction signal picked with the user over version-string
    parsing (fragile — exploit-db titles express version ranges as free text
    in wildly inconsistent formats) or an exclusive CVE filter (verified
    empirically to often leave nothing at all, since vulners and exploit-db
    are independent data sources with no guaranteed overlap)."""
    if not exploit.cve_codes:
        return None
    for code in exploit.cve_codes.split(';'):
        if code in known_cves:
            return code
    return None


class InteractiveConsole:
    def __init__(self):
        self.console = RichConsole()
        self.session_db = get_session()
        self.context = SessionContext()
        self.cmds = {
            'clear': self.command_clear,
            'options': self.command_options,
            'exit': self.command_exit,
            'quit': self.command_exit,
            'help': self.command_help,
            'whois': self.command_whois,
            'set': self.command_set,
            'unset': self.command_unset,
            'scope': self.command_scope,
            'scan': self.command_scan,
            'scans': self.command_scans,
            'recon': self.command_recon,
            'hosts': self.command_hosts,
            'services': self.command_services,
            'vulns': self.command_vulns,
        }

        # Start the DB (creates tables if they don't exist yet)
        init_db()

        self.completer = WordCompleter([
            'whois', 'scan', 'scans', 'recon', 'help', 'exit', 'quit', 'clear', 'set', 'unset', 'scope', 'options',
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
        if len(args) < 2:
            self.console.print("[red]Usage: set <option> <value>  (see 'options')[/red]")
            return
        # Everything after the option name is the value, so a User-Agent with
        # spaces works without quoting.
        name, value = args[0], ' '.join(args[1:])
        try:
            self.context.set(name, value)
        except ValueError as e:
            self.console.print(f"[red]{e}[/red]")
            return
        self.console.print(f"[green]{name} => {self.context.get(name)}[/green]")

    def command_unset(self, args):
        if not args:
            self.console.print("[red]Usage: unset <option>[/red]")
            return
        try:
            self.context.unset(args[0])
        except ValueError as e:
            self.console.print(f"[red]{e}[/red]")
            return
        self.console.print(f"[green]{args[0]} reset to {self.context.get(args[0])}[/green]")

    def command_scope(self, args):
        """`scope` lists; `scope add|exclude <value>`; `scope remove <value>`."""
        if not args:
            self._print_scope()
            return

        action, values = args[0], args[1:]
        if action in ('add', 'exclude'):
            if not values:
                self.console.print(f"[red]Usage: scope {action} <domain|ip|cidr>[/red]")
                return
            try:
                kind, value = parse_scope_value(values[0])
            except ValueError as e:
                self.console.print(f"[red]{e}[/red]")
                return
            rule = self.session_db.query(ScopeRule).filter_by(value=value).first()
            if rule is None:
                rule = ScopeRule(kind=kind, value=value)
            rule.allow = action == 'add'
            self.session_db.add(rule)
            self.session_db.commit()
            label = 'included in' if rule.allow else 'excluded from'
            self.console.print(f"[green]{value} {label} scope.[/green]")
        elif action == 'remove':
            if not values:
                self.console.print("[red]Usage: scope remove <value>[/red]")
                return
            try:
                _, value = parse_scope_value(values[0])
            except ValueError as e:
                self.console.print(f"[red]{e}[/red]")
                return
            rule = self.session_db.query(ScopeRule).filter_by(value=value).first()
            if rule is None:
                self.console.print(f"[yellow]'{value}' is not in the scope.[/yellow]")
                return
            self.session_db.delete(rule)
            self.session_db.commit()
            self.console.print(f"[green]{value} removed from scope.[/green]")
        else:
            self.console.print("[red]Usage: scope [add|exclude|remove <value>][/red]")

    def _print_scope(self):
        rules = self.session_db.query(ScopeRule).order_by(ScopeRule.allow.desc(), ScopeRule.value).all()
        if not rules:
            self.console.print("[yellow]No scope defined: any target can be scanned. Use 'scope add <domain|ip|cidr>'.[/yellow]")
            return
        table = Table(title="Scope")
        table.add_column("Rule", style="white")
        table.add_column("Type", style="white")
        table.add_column("Value", style="cyan")
        for rule in rules:
            table.add_row('include' if rule.allow else 'exclude', rule.kind, rule.value)
        self.console.print(table)

    def _target_allowed_by_scope(self, target: str) -> bool:
        """Checks the scope before anything touches the target; prints why when blocked."""
        rules = [(r.kind, r.value, r.allow) for r in self.session_db.query(ScopeRule)]
        decision = decide(target, rules)
        if not decision.allowed:
            self.console.print(f"[red]{decision.reason} Review it with 'scope'.[/red]")
            return False
        if decision.unrestricted:
            self.console.print("[yellow]No scope defined: scanning without restriction (see 'scope add').[/yellow]")
        return True

    def command_scan(self, args):
        # `diff` is a subcommand, so it can't also be used as a scan name.
        if args and args[0] == 'diff':
            self.command_scan_diff(args[1:])
            return

        if len(args) < 2:
            self.console.print("[red]Usage: scan <name> <ip/host>  |  scan diff <name|addr>[/red]")
            return

        name, target = args[0], args[1]
        self.handle_scan(name, target)

    def command_scans(self, args):
        """Lists scan runs (history), newest first; optionally for one host."""
        query = self.session_db.query(ScanRun).join(Host)
        if args:
            host = self._find_host_or_warn(args[0])
            if not host:
                return
            query = query.filter(ScanRun.host_id == host.id)

        runs = query.order_by(ScanRun.id.desc()).all()
        if not runs:
            self.console.print("[yellow]No scan runs registered yet. Run 'scan' first.[/yellow]")
            return

        table = Table(title="Scan runs")
        table.add_column("Run", justify="right", style="cyan")
        table.add_column("Host", style="white")
        table.add_column("Status", style="white")
        table.add_column("Started", style="white")
        table.add_column("Duration", justify="right")
        table.add_column("Services", justify="right")
        for run in runs:
            duration = '-'
            if run.finished_at:
                duration = f"{(run.finished_at - run.started_at).total_seconds():.0f}s"
            table.add_row(
                str(run.id),
                run.host.addr,
                run.status,
                run.started_at.strftime('%Y-%m-%d %H:%M:%S'),
                duration,
                str(len(run.services)),
            )
        self.console.print(table)

    def command_scan_diff(self, args):
        """`scan diff <name|addr>`: compares the host's last two finished runs."""
        if not args:
            self.console.print("[red]Usage: scan diff <name|addr>[/red]")
            return
        host = self._find_host_or_warn(args[0])
        if not host:
            return

        # Failed/interrupted runs are skipped: they'd make ports look closed.
        runs = (
            self.session_db.query(ScanRun)
            .filter_by(host_id=host.id, status='ok')
            .order_by(ScanRun.id.desc())
            .limit(2)
            .all()
        )
        if len(runs) < 2:
            self.console.print(
                f"[yellow]Need at least two finished scans of '{host.addr}' to compare "
                f"(found {len(runs)}).[/yellow]"
            )
            return

        new, old = runs
        diff = diff_scan_runs(self.session_db, old, new)
        if diff.is_empty:
            self.console.print(f"[green]No changes between run {old.id} and run {new.id}.[/green]")
            return

        table = Table(title="Scan diff", caption=f"run {old.id} -> run {new.id} ({host.addr})")
        table.add_column("Change", style="white")
        table.add_column("Port", justify="right", style="cyan")
        table.add_column("Detail", style="white")
        for port in diff.opened:
            table.add_row('opened', str(port), '-')
        for port in diff.closed:
            table.add_row('closed', str(port), '-')
        for port, before, after in diff.version_changed:
            table.add_row('version', str(port), f"{before} -> {after}")
        for port, cve in diff.new_cves:
            table.add_row('new CVE', str(port), cve)
        for port, cve in diff.resolved_cves:
            table.add_row('resolved CVE', str(port), cve)
        self.console.print(table)

    def command_recon(self, args):
        """`recon <name> <domain>`: passive subdomain discovery (subfinder)."""
        if len(args) < 2:
            self.console.print("[red]Usage: recon <name> <domain>[/red]")
            return

        name, domain = args[0], args[1]
        if not self._target_allowed_by_scope(domain):
            return

        recon_phase = ReconPhase(self.session_db)
        if not self._ensure_tool_available('subfinder', recon_phase.subfinder, required=True):
            return

        try:
            host = recon_phase.run(name=name, domain=domain, on_progress=self._report_progress)
        except RuntimeError as e:
            self.session_db.rollback()
            self.console.print(f"[red]{e}[/red]")
            return
        except Exception as e:
            self.session_db.rollback()
            self.console.print(f"[red]Error during recon: {e}[/red]")
            return

        new = set(recon_phase.last_new_subdomains)
        table = Table(title="Subdomains", caption=f"{name} ({host.addr})")
        table.add_column("Name", style="cyan")
        table.add_column("Status", style="white")
        for subdomain in recon_phase.last_all_subdomains:
            status = "new" if subdomain in new else "known"
            table.add_row(subdomain, status)
        self.console.print(table)
        self.console.print(
            f"[*] {len(recon_phase.last_all_subdomains)} subdomain(s) total, "
            f"{len(new)} new this run."
        )

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

    def _find_host_or_warn(self, ident: str):
        """Finds a host by address or by the name it was scanned under.

        The address wins when both could match (it's the unique identity). A name
        can be reused across addresses, so an ambiguous one is reported instead
        of guessing.
        """
        host = self.session_db.query(Host).filter_by(addr=ident).first()
        if host:
            return host

        matches = self.session_db.query(Host).filter_by(nome=ident).order_by(Host.addr).all()
        if len(matches) == 1:
            return matches[0]
        if len(matches) > 1:
            addrs = ', '.join(h.addr for h in matches)
            self.console.print(
                f"[red]Name '{ident}' is ambiguous ({addrs}). Use the address instead.[/red]"
            )
            return None

        self.console.print(f"[red]Host '{ident}' not found.[/red]")
        return None

    def command_hosts(self, args):
        if args and args[0] == '-d':
            if len(args) < 2:
                self.console.print("[red]Usage: hosts -d <name|addr|all>[/red]")
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
                self.console.print("[red]Usage: services -d <name|addr|all>[/red]")
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

        query = self.session_db.query(Service).join(Host).filter(current_services_filter())
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
                self.console.print("[red]Usage: vulns -d <name|addr|all>[/red]")
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

        query = self.session_db.query(Vulnerability).join(Service).join(Host).filter(current_services_filter())
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
        table = Table(title="Options")
        table.add_column("Option", style="cyan")
        table.add_column("Value", style="white")
        table.add_column("Default", style="white")
        table.add_column("Description", style="white")
        for name, value, default, description in self.context.rows():
            table.add_row(name, value, default, description)
        self.console.print(table)

    def command_help(self, args):
        self.print_help(args)

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

    def _report_progress(self, step: str) -> None:
        """Callback passed to `ScanPhase.run`/`ReconPhase.run` — prints each
        step (and the actual command behind it) as it starts, instead of a
        single static message sitting there until the whole phase finishes."""
        self.console.print(f"[*] {step}")

    def _print_exploit_table(self, service: Service) -> None:
        """One table per service instead of one flat list mixing every
        service on the host — `ExploitMatch` rows are attributed to the exact
        service they were searched for (see `ScanPhase._persist_exploit_matches`).

        Rows are sorted with CVE-confirmed matches first (their own CVE shown
        in the CVE column), then exploit-db's own `verified` flag, then by
        title; capped at `EXPLOIT_DISPLAY_CAP` with a note for how many were
        left out, instead of dumping every version-agnostic text match."""
        known_cves = {v.cve for v in service.vulnerabilities}
        matches = sorted(
            service.exploit_matches,
            key=lambda m: (
                _exploit_matched_cve(m, known_cves) is None,
                not m.verified,
                m.title,
            ),
        )
        shown, hidden_count = matches[:EXPLOIT_DISPLAY_CAP], max(0, len(matches) - EXPLOIT_DISPLAY_CAP)

        service_label = f"{service.product or service.name or '?'} {service.version or ''}".strip()
        exploit_table = Table(title=f"Exploits — port {service.port} ({service_label})")
        exploit_table.add_column("EDB-ID", style="cyan")
        exploit_table.add_column("Title", style="white")
        exploit_table.add_column("CVE", style="green")
        for match in shown:
            exploit_table.add_row(match.edb_id or '-', match.title, _exploit_matched_cve(match, known_cves) or '-')
        self.console.print(exploit_table)

        if hidden_count:
            # Same first-word extraction ScanPhase used to search (see its
            # comment): the full `product` string is often multi-word and
            # `searchsploit -t` requires every word to literally appear, so
            # suggesting the full string here would be a command that finds
            # nothing.
            full_term = service.product or service.name
            search_term = full_term.split()[0] if full_term else full_term
            self.console.print(
                f"[dim]+{hidden_count} more — run 'searchsploit {search_term}' for the full list.[/dim]"
            )

    def handle_scan(self, name: str, target: str):
        """Scan phase: rustscan (discovery) -> nmap -sV (fingerprint) -> searchsploit (exploits)."""
        if not self._target_allowed_by_scope(target):
            return

        scan_phase = ScanPhase(
            self.session_db,
            rustscan_batch=self.context.get('rustscan_batch'),
            rustscan_timeout=self.context.get('rustscan_timeout'),
        )

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
            host_record = scan_phase.run(name=name, target=target, on_progress=self._report_progress)
        except RuntimeError as e:
            # External tool missing from PATH (rustscan/nmap/searchsploit) — not a
            # bug, an environment prerequisite.
            self.session_db.rollback()
            self.console.print(f"[red]{e}[/red]")
            return
        except Exception as e:
            # Without the rollback, a failed flush leaves the shared session
            # poisoned and every later command fails too.
            self.session_db.rollback()
            self.console.print(f"[red]Error during scan: {e}[/red]")
            return

        services = (
            self.session_db.query(Service)
            .filter(Service.host_id == host_record.id, current_services_filter())
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
            .filter(Service.host_id == host_record.id, current_services_filter())
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

        services_with_exploits = [s for s in services if s.exploit_matches]

        if services_with_exploits:
            for service in services_with_exploits:
                self._print_exploit_table(service)
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
        table.add_row("scope [add|exclude|remove <value>]", "Show or edit the scope (domain, IP or CIDR). Scans outside it are blocked.")
        table.add_row("scans [name|addr]", "List scan runs (history), optionally for one host.")
        table.add_row("recon <name> <domain>", "Passive subdomain discovery (subfinder); shows new vs. known.")
        table.add_row("scan diff <name|addr>", "Compare the host's last two finished scans.")
        table.add_row("hosts [-d <name|addr|all>]", "List hosts, or delete one host (cascades) / all hosts.")
        table.add_row("services [name|addr] [-d <name|addr|all>]", "List services (optionally by host), or delete them.")
        table.add_row("vulns [name|addr] [-d <name|addr|all>]", "List vulnerabilities (optionally by host), or delete them.")
        table.add_row("set <option> <value>", "Set a session option (rustscan_batch, rustscan_timeout, user_agent).")
        table.add_row("unset <option>", "Reset a session option to its default.")
        table.add_row("options", "Show session options, their defaults and what they do.")
        table.add_row("clear", "Clear the terminal screen.")
        table.add_row("exit / quit", "Exit the console.")
        self.console.print(table)
