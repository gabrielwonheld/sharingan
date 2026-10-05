import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

from prompt_toolkit import PromptSession
from prompt_toolkit.completion import WordCompleter
from prompt_toolkit.patch_stdout import patch_stdout
from prompt_toolkit.styles import Style
from rich.console import Console as RichConsole
from rich.markup import escape
from rich.prompt import Confirm
from rich.table import Table

from db.database import init_db, get_session
from core.context import SessionContext
from core.report import build_workspace_report
from core.scope import decide, parse_scope_value
from phases.fuzz.fuzz_phase import FuzzPhase
from phases.recon.recon_phase import ReconPhase
from phases.recon.whois_phase import WhoisPhase
from phases.scan.scan_diff import diff_scan_runs
from phases.web.spider_phase import SpiderPhase
from model.crawl_model import CrawledPage, HarvestedEmail
from model.finding_model import Finding
from model.host import Host
from model.scope_model import ScopeRule
from model.service_model import ScanRun, Service, Vulnerability, current_services_filter
from model.subdomain_model import Subdomain
from model.whois_model import WhoisRecord
from model.workspace_model import DEFAULT_WORKSPACE_ID, DEFAULT_WORKSPACE_NAME, Workspace
from view.catalog import HELP_SECTIONS, PHASES, PLANNED_NOTE
from phases.scan.scan_phase import ScanPhase
from phases.scan.tools.installer import ToolInstaller

# `searchsploit -t <product>` does plain text matching with no version
# awareness, so a common product can return dozens of hits spanning every
# version ever published. Capping keeps the table scannable; anyone who wants
# the full list can still run `searchsploit <product>` themselves.
EXPLOIT_DISPLAY_CAP = 10

# `info` is an overview, not the full listing: each section is capped and
# points to the dedicated command for the rest.
INFO_CAP_SUBDOMAINS = 25
INFO_CAP_VULNS = 10
INFO_CAP_EMAILS = 15
INFO_CAP_FINDINGS = 20


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
    # The workspace the session is working in (session-only, always starts in
    # `default`). Class-level defaults so a console built without __init__ works.
    workspace_id = DEFAULT_WORKSPACE_ID
    workspace_name = DEFAULT_WORKSPACE_NAME

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
            'subdomains': self.command_subdomains,
            'fuzz': self.command_fuzz,
            'crawl': self.command_crawl,
            'findings': self.command_findings,
            'workspace': self.command_workspace,
            'export': self.command_export,
            'phases': self.command_phases,
            'fases': self.command_phases,
            'info': self.command_info,
            'pages': self.command_pages,
            'emails': self.command_emails,
            'hosts': self.command_hosts,
            'services': self.command_services,
            'vulns': self.command_vulns,
        }

        # Start the DB (creates tables if they don't exist yet)
        init_db()

        self.completer = WordCompleter([
            'whois', 'scan', 'scans', 'recon', 'help', 'exit', 'quit', 'clear', 'set', 'unset', 'scope', 'options',
            'hosts', 'services', 'vulns', 'subdomains', 'fuzz', 'crawl',
            'findings', 'pages', 'emails', 'phases', 'fases', 'info', 'workspace', 'export',
        ], ignore_case=True)

        self.style = Style.from_dict({
            'prompt': 'bold #ff2b2b',
            'workspace': 'bold #5fafff',
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

        # Every `command_*` prints with `rich.Console.print`, straight to stdout,
        # while `PromptSession.prompt` separately manages the terminal's cursor
        # and redraws between prompts — neither library knows about the other's
        # writes. Without `patch_stdout()`, a wide/multi-row `rich` table (first
        # seen with the `fuzz` command's "Findings" table) can come out with its
        # left border silently missing on every data row, even though the table
        # itself is built correctly (confirmed by rendering the exact same table
        # standalone, outside the console, where it comes out fine). This wraps
        # every print made during the loop so prompt_toolkit redraws around it
        # safely instead of the two colliding.
        with patch_stdout(raw=True):
            while True:
                try:
                    text = self.prompt_session.prompt(self._prompt_message())
                    self.process_command(text)
                except KeyboardInterrupt:
                    continue
                except EOFError:
                    break

    def _prompt_message(self):
        """`Sharingan [workspace] > ` — the workspace name sits where a shell
        shows the current directory, so it's always clear which project the next
        command will touch."""
        return [
            ('class:prompt', 'Sharingan '),
            ('class:workspace', f'[{self.workspace_name}]'),
            ('class:prompt', ' > '),
        ]

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
        if not self._target_allowed_by_scope(domain):
            return
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
            rule = self._scope_rules_query().filter_by(value=value).first()
            if rule is None:
                rule = ScopeRule(kind=kind, value=value, workspace_id=self.workspace_id)
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
            rule = self._scope_rules_query().filter_by(value=value).first()
            if rule is None:
                self.console.print(f"[yellow]'{value}' is not in the scope.[/yellow]")
                return
            self.session_db.delete(rule)
            self.session_db.commit()
            self.console.print(f"[green]{value} removed from scope.[/green]")
        else:
            self.console.print("[red]Usage: scope [add|exclude|remove <value>][/red]")

    def _scope_rules_query(self):
        """Scope belongs to the workspace: each engagement keeps its own targets."""
        return self.session_db.query(ScopeRule).filter(ScopeRule.workspace_id == self.workspace_id)

    def _print_scope(self):
        rules = self._scope_rules_query().order_by(ScopeRule.allow.desc(), ScopeRule.value).all()
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
        rules = [(r.kind, r.value, r.allow) for r in self._scope_rules_query()]
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
        query = self._workspace_rows(ScanRun)
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

        recon_phase = ReconPhase(self.session_db, workspace_id=self.workspace_id)
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

    def command_fuzz(self, args):
        """`fuzz <name> <url>`: directory/file enumeration (gobuster), opt-in only —
        never run automatically by `scan`, since it sends a real, sizeable volume
        of requests to the target."""
        if len(args) < 2:
            self.console.print("[red]Usage: fuzz <name> <url>  (needs 'fuzz_wordlist' set — see 'options')[/red]")
            return

        name, url = args[0], args[1]
        hostname = urlparse(url).hostname
        if not hostname:
            self.console.print("[red]URL must include a scheme and host, e.g. http://example.com/base[/red]")
            return
        if not self._target_allowed_by_scope(hostname):
            return

        wordlist = self.context.get('fuzz_wordlist')
        if not wordlist:
            self.console.print(
                "[red]No wordlist configured. Set one first: set fuzz_wordlist <path>[/red]"
            )
            return

        fuzz_phase = FuzzPhase(self.session_db, workspace_id=self.workspace_id)
        if not self._ensure_tool_available('gobuster', fuzz_phase.gobuster, required=True):
            return

        try:
            host = fuzz_phase.run(
                name=name, url=url, wordlist=wordlist,
                extensions=self.context.get('fuzz_extensions') or None,
                threads=self.context.get('fuzz_threads'),
                status_codes=None,
                on_progress=self._report_progress,
            )
        except RuntimeError as e:
            self.session_db.rollback()
            self.console.print(f"[red]{e}[/red]")
            return
        except Exception as e:
            self.session_db.rollback()
            self.console.print(f"[red]Error during fuzz: {e}[/red]")
            return

        new = set(fuzz_phase.last_new_paths)
        table = Table(title="Findings", caption=f"{name} ({host.addr})")
        table.add_column("Path", style="cyan")
        table.add_column("Code", justify="right")
        table.add_column("Size", justify="right")
        table.add_column("Redirect", style="white")
        table.add_column("Status", style="white")
        for match in fuzz_phase.last_all_matches:
            status_label = "new" if match.path in new else "known"
            table.add_row(
                match.path, str(match.status_code),
                str(match.size) if match.size is not None else '-',
                match.redirect or '-',
                status_label,
            )
        self.console.print(table)
        self.console.print(
            f"[*] {len(fuzz_phase.last_all_matches)} finding(s) total, {len(new)} new this run."
        )

    def _scope_allows(self, hostname: str) -> bool:
        """Silent scope check (no printing), for phases that re-check every
        hostname they'd touch mid-run — e.g. each link `crawl` follows."""
        rules = [(r.kind, r.value, r.allow) for r in self._scope_rules_query()]
        return decide(hostname, rules).allowed

    def command_crawl(self, args):
        """`crawl <name> <url>`: bounded crawl (pages + emails). Sends real HTTP
        requests, so scope is checked on the start host first and again on every
        host the crawl would follow a link to."""
        if len(args) < 2:
            self.console.print("[red]Usage: crawl <name> <url>[/red]")
            return

        name, url = args[0], args[1]
        hostname = urlparse(url).hostname
        if not hostname:
            self.console.print("[red]URL must include a scheme and host, e.g. http://example.com/[/red]")
            return
        if not self._target_allowed_by_scope(hostname):
            return

        spider_phase = SpiderPhase(self.session_db, workspace_id=self.workspace_id)
        try:
            host = spider_phase.run(
                name=name, url=url,
                max_depth=self.context.get('spider_max_depth'),
                max_pages=self.context.get('spider_max_pages'),
                delay=self.context.get('spider_delay'),
                user_agent=self.context.get('user_agent'),
                scope_allows=self._scope_allows,
                on_progress=self._report_progress,
            )
        except Exception as e:
            self.session_db.rollback()
            self.console.print(f"[red]Error during crawl: {e}[/red]")
            return

        new_pages = set(spider_phase.last_new_pages)
        table = Table(title="Pages", caption=f"{name} ({host.addr})")
        table.add_column("URL", style="cyan")
        table.add_column("Code", justify="right")
        table.add_column("Depth", justify="right")
        table.add_column("Status", style="white")
        for page in spider_phase.last_all_pages:
            table.add_row(
                page.url, str(page.status_code), str(page.depth),
                "new" if page.url in new_pages else "known",
            )
        self.console.print(table)

        if spider_phase.last_all_emails:
            new_emails = set(spider_phase.last_new_emails)
            emails_table = Table(title="Emails", caption=f"{name} ({host.addr})")
            emails_table.add_column("Email", style="cyan")
            emails_table.add_column("Found on", style="white")
            emails_table.add_column("Status", style="white")
            for email, source in sorted(spider_phase.last_all_emails.items()):
                emails_table.add_row(email, source, "new" if email in new_emails else "known")
            self.console.print(emails_table)

        self.console.print(
            f"[*] {len(spider_phase.last_all_pages)} page(s), "
            f"{len(spider_phase.last_new_pages)} new this run; "
            f"{len(spider_phase.last_all_emails)} email(s), "
            f"{len(spider_phase.last_new_emails)} new."
        )

    def command_subdomains(self, args):
        """Lists/deletes `Subdomain` rows found by `recon`. Same shape as
        `services`/`vulns`: no argument lists everything, `-d <name|addr>`
        deletes one host's subdomains (keeps the Host), `-d all` deletes
        every subdomain for every host (asks for confirmation first)."""
        if args and args[0] == '-d':
            if len(args) < 2:
                self.console.print("[red]Usage: subdomains -d <name|addr|all>[/red]")
                return
            target = args[1]
            if target == 'all':
                if not self._confirm_delete_all('all subdomains'):
                    self.console.print("[yellow]Cancelled.[/yellow]")
                    return
                for subdomain in self._workspace_rows(Subdomain).all():
                    self.session_db.delete(subdomain)
                self.session_db.commit()
                self.console.print("[green]All subdomains have been deleted.[/green]")
                return

            host = self._find_host_or_warn(target)
            if not host:
                return
            for subdomain in self.session_db.query(Subdomain).filter_by(host_id=host.id).all():
                self.session_db.delete(subdomain)
            self.session_db.commit()
            self.console.print(f"[green]Subdomains for '{target}' deleted.[/green]")
            return

        query = self._workspace_rows(Subdomain)
        if args:
            host = self._find_host_or_warn(args[0])
            if not host:
                return
            query = query.filter(Subdomain.host_id == host.id)

        subdomains = query.order_by(Host.addr, Subdomain.name).all()
        if not subdomains:
            self.console.print("[yellow]No subdomains registered yet. Run 'recon' first.[/yellow]")
            return

        table = Table(title="Subdomains")
        table.add_column("Host", style="cyan")
        table.add_column("Name", style="white")
        table.add_column("Discovered", style="white")
        for subdomain in subdomains:
            table.add_row(subdomain.host.addr, subdomain.name, subdomain.discovered_at.strftime('%Y-%m-%d %H:%M:%S'))
        self.console.print(table)

    # -----------------------------------------------------------------
    # Workspaces: hosts (and everything the phases saved for them) and scope
    # rules belong to one workspace; every query below goes through these
    # helpers so a command can only ever see the current one.
    # -----------------------------------------------------------------

    def _hosts_query(self):
        return self.session_db.query(Host).filter(Host.workspace_id == self.workspace_id)

    def _workspace_rows(self, model):
        """Rows of `model` (anything hanging off a Host) that belong to hosts of
        the current workspace. The one place that knows how to reach `Host`
        from each model, so no listing/delete forgets the workspace filter."""
        if model is Host:
            return self._hosts_query()
        query = self.session_db.query(model)
        if model is Vulnerability:
            query = query.join(Service, Vulnerability.service_id == Service.id)
            query = query.join(Host, Service.host_id == Host.id)
        else:
            query = query.join(Host, model.host_id == Host.id)
        return query.filter(Host.workspace_id == self.workspace_id)

    @staticmethod
    def _valid_workspace_name(name: str) -> bool:
        reserved = {'add', 'delete'}  # subcommands, so they can't also be names
        return (
            bool(re.fullmatch(r'[A-Za-z0-9_.-]{1,40}', name))
            and name.lower() not in reserved
        )

    def _find_workspace(self, name: str):
        return self.session_db.query(Workspace).filter_by(name=name).first()

    def _switch_workspace(self, workspace: Workspace) -> None:
        self.workspace_id = workspace.id
        self.workspace_name = workspace.name

    def command_workspace(self, args):
        """`workspace` lists; `workspace <name>` switches; `workspace add <name>`
        creates (and switches to) one; `workspace delete <name>` removes one with
        everything in it."""
        if not args:
            self._print_workspaces()
            return

        action = args[0]
        if action == 'add':
            self._workspace_add(args[1:])
        elif action == 'delete':
            self._workspace_delete(args[1:])
        elif len(args) == 1:
            workspace = self._find_workspace(action)
            if workspace is None:
                self.console.print(
                    f"[red]Workspace '{action}' not found. Create it with 'workspace add {action}'.[/red]"
                )
                return
            self._switch_workspace(workspace)
            self.console.print(f"[green]Workspace: {workspace.name}[/green]")
        else:
            self.console.print("[red]Usage: workspace [<name> | add <name> | delete <name>][/red]")

    def command_export(self, args):
        """`export [path]`: writes the current workspace (every host and what the
        phases collected) as a Markdown report. With no path, a timestamped file
        goes in the current directory; a directory path gets that file inside it."""
        now = datetime.now(timezone.utc)
        default_name = f"sharingan-{self.workspace_name}-{now.strftime('%Y%m%d-%H%M%S')}.md"
        path = Path(' '.join(args)).expanduser() if args else Path(default_name)
        if path.is_dir():
            path = path / default_name
        if not path.parent.exists():
            self.console.print(f"[red]Directory '{path.parent}' doesn't exist.[/red]")
            return
        if path.exists() and not Confirm.ask(
            f"'{path}' already exists. Overwrite?", default=False, console=self.console,
        ):
            self.console.print("[yellow]Cancelled.[/yellow]")
            return

        report = build_workspace_report(self.session_db, self.workspace_id, self.workspace_name, now=now)
        try:
            path.write_text(report, encoding='utf-8')
        except OSError as e:
            self.console.print(f"[red]Could not write '{path}': {e}[/red]")
            return
        hosts = self._hosts_query().count()
        self.console.print(
            f"[green]Report of workspace '{self.workspace_name}' ({hosts} host(s)) written to "
            f"{path.resolve()}[/green]"
        )

    def _print_workspaces(self):
        table = Table(title="Workspaces")
        table.add_column("Current", justify="center", style="green")
        table.add_column("Name", style="cyan")
        table.add_column("Hosts", justify="right")
        table.add_column("Created", style="white")
        for workspace in self.session_db.query(Workspace).order_by(Workspace.id).all():
            table.add_row(
                '*' if workspace.id == self.workspace_id else '',
                workspace.name,
                str(len(workspace.hosts)),
                self._timestamp(workspace.created_at),
            )
        self.console.print(table)

    def _workspace_add(self, values):
        if not values:
            self.console.print("[red]Usage: workspace add <name>[/red]")
            return
        name = values[0]
        if not self._valid_workspace_name(name):
            self.console.print(
                "[red]Invalid workspace name: use 1-40 letters, digits, '.', '_' or '-' "
                "('add' and 'delete' are reserved).[/red]"
            )
            return
        if self._find_workspace(name):
            self.console.print(f"[red]Workspace '{name}' already exists. Switch to it with 'workspace {name}'.[/red]")
            return
        workspace = Workspace(name=name)
        self.session_db.add(workspace)
        self.session_db.commit()
        self._switch_workspace(workspace)
        self.console.print(f"[green]Workspace '{name}' created; now working in it.[/green]")

    def _workspace_delete(self, values):
        if not values:
            self.console.print("[red]Usage: workspace delete <name>[/red]")
            return
        name = values[0]
        workspace = self._find_workspace(name)
        if workspace is None:
            self.console.print(f"[red]Workspace '{name}' not found.[/red]")
            return
        if workspace.id == DEFAULT_WORKSPACE_ID:
            self.console.print("[red]The 'default' workspace cannot be deleted.[/red]")
            return
        if not Confirm.ask(
            f"This deletes workspace '{name}' with its {len(workspace.hosts)} host(s), "
            "everything collected for them and its scope. Confirm?",
            default=False,
            console=self.console,
        ):
            self.console.print("[yellow]Cancelled.[/yellow]")
            return

        was_current = workspace.id == self.workspace_id
        self.session_db.delete(workspace)
        self.session_db.commit()
        if was_current:
            self._switch_workspace(self._find_workspace(DEFAULT_WORKSPACE_NAME))
        self.console.print(f"[green]Workspace '{name}' deleted.[/green]")

    # -----------------------------------------------------------------
    # `phases` / `info` — orientation: what phases exist, what ran against a
    # host, and everything collected about it in one place.
    # -----------------------------------------------------------------

    def _phase_status(self, host: Host) -> dict[str, str | None]:
        """For each phase key: a short summary of what it saved for `host`, or
        None when it hasn't run."""
        db = self.session_db

        def count(model) -> int:
            return db.query(model).filter_by(host_id=host.id).count()

        whois, subdomains = count(WhoisRecord), count(Subdomain)
        recon = None
        if whois or subdomains:
            recon = f"{whois} whois record(s), {subdomains} subdomain(s)"

        last_run = (
            db.query(ScanRun).filter_by(host_id=host.id).filter(ScanRun.status != 'failed')
            .order_by(ScanRun.id.desc()).first()
        )
        services = db.query(Service).filter(Service.host_id == host.id, current_services_filter()).count()
        scan = None
        if last_run or services:
            when = f", {self._timestamp(last_run.started_at)}" if last_run else ''
            scan = f"{services} service(s){when}"

        pages, emails, findings = count(CrawledPage), count(HarvestedEmail), count(Finding)
        return {
            'recon': recon,
            'scan': scan,
            'crawl': f"{pages} page(s), {emails} email(s)" if pages or emails else None,
            'fuzz': f"{findings} finding(s)" if findings else None,
        }

    def command_phases(self, args):
        """`phases [name|addr]`: the methodology phases and how to run each;
        with a host, also which already ran on it and which are still missing."""
        status = None
        if args:
            host = self._find_host_or_warn(args[0])
            if not host:
                return
            status = self._phase_status(host)

        table = Table(title="Phases", title_justify="left")
        table.add_column("Phase", style="cyan")
        table.add_column("Traffic to target", style="white")
        table.add_column("Run with", style="white")
        table.add_column("Tools", style="white")
        table.add_column("See results with", style="white")
        if status is not None:
            table.add_column("Status", style="white")
        for phase in PHASES:
            row = [phase.title, phase.traffic, phase.run_with, phase.tools, phase.results]
            if status is not None:
                detail = status[phase.key]
                row.append(f"[green]done[/green] — {detail}" if detail
                           else f"[yellow]not run[/yellow] — {phase.not_run_hint}")
            table.add_row(*row)
        self.console.print(table)
        self.console.print(f"[dim]{PLANNED_NOTE}[/dim]")

    def _not_run(self, label: str, hint: str) -> None:
        self.console.print(f"[dim]{label}: not run yet — {hint}[/dim]")

    def _more_note(self, hidden: int, command: str, host: Host) -> None:
        if hidden > 0:
            self.console.print(f"[dim]+{hidden} more — run '{command} {host.addr}' for the full list.[/dim]")

    def command_info(self, args):
        """`info <name|addr>`: everything collected about one host, phase by phase."""
        if not args:
            self.console.print("[red]Usage: info <name|addr>[/red]")
            return
        host = self._find_host_or_warn(args[0])
        if not host:
            return

        self.console.print(f"[bold]{host.nome}[/bold] ({host.addr})")
        self._info_recon(host)
        self._info_scan(host)
        self._info_web(host)
        self._info_fuzz(host)
        self.console.print("[dim]Run 'phases " + host.addr + "' to see which phases are still missing.[/dim]")

    def _info_recon(self, host: Host) -> None:
        db = self.session_db
        whois = db.query(WhoisRecord).filter_by(host_id=host.id).order_by(WhoisRecord.id.desc()).first()
        if whois:
            table = Table(title="WHOIS", title_justify="left")
            table.add_column("Property", justify="right", style="cyan")
            table.add_column("Value", style="white")
            table.add_row("Registrar", str(whois.registrar))
            table.add_row("Creation Date", str(whois.creation_date))
            table.add_row("Expiration Date", str(whois.expiration_date))
            self.console.print(table)
        else:
            self._not_run("WHOIS", "whois <domain>")

        subdomains = db.query(Subdomain).filter_by(host_id=host.id).order_by(Subdomain.name).all()
        if subdomains:
            table = Table(title="Subdomains", title_justify="left")
            table.add_column("Name", style="cyan")
            for subdomain in subdomains[:INFO_CAP_SUBDOMAINS]:
                table.add_row(subdomain.name)
            self.console.print(table)
            self._more_note(len(subdomains) - INFO_CAP_SUBDOMAINS, 'subdomains', host)
        else:
            self._not_run("Subdomains", "recon <name> <domain>")

    def _info_scan(self, host: Host) -> None:
        db = self.session_db
        services = (
            db.query(Service).filter(Service.host_id == host.id, current_services_filter())
            .order_by(Service.port).all()
        )
        last_run = db.query(ScanRun).filter_by(host_id=host.id).order_by(ScanRun.id.desc()).first()
        if not services:
            if last_run:
                self.console.print(
                    f"[*] Last scan ({last_run.status}, {self._timestamp(last_run.started_at)}) found no open ports."
                )
            else:
                self._not_run("Scan", "scan <name> <ip/host>")
            return

        table = Table(title="Services", title_justify="left")
        table.add_column("Port", justify="right", style="cyan")
        table.add_column("State", style="white")
        table.add_column("Service", style="white")
        table.add_column("CVEs", justify="right")
        table.add_column("Exploits", justify="right")
        vulns = []
        for service in services:
            label = f"{service.product or service.name or '?'} {service.version or ''}".strip()
            table.add_row(
                str(service.port), service.state, label,
                str(len(service.vulnerabilities)), str(len(service.exploit_matches)),
            )
            vulns.extend((service, v) for v in service.vulnerabilities)
        self.console.print(table)

        if last_run:
            self.console.print(
                f"[*] Last scan: {last_run.status}, {self._timestamp(last_run.started_at)} "
                f"(run {last_run.id}); 'scans {host.addr}' shows the history."
            )
        if vulns:
            vulns.sort(key=lambda pair: pair[1].cvss or 0, reverse=True)
            table = Table(title="Top vulnerabilities", title_justify="left")
            table.add_column("CVE", style="cyan")
            table.add_column("CVSS", justify="right")
            table.add_column("Port", justify="right")
            for service, vuln in vulns[:INFO_CAP_VULNS]:
                table.add_row(vuln.cve, str(vuln.cvss) if vuln.cvss is not None else '-', str(service.port))
            self.console.print(table)
            self._more_note(len(vulns) - INFO_CAP_VULNS, 'vulns', host)

    def _info_web(self, host: Host) -> None:
        db = self.session_db
        pages = db.query(CrawledPage).filter_by(host_id=host.id).all()
        emails = db.query(HarvestedEmail).filter_by(host_id=host.id).order_by(HarvestedEmail.email).all()
        if not pages and not emails:
            self._not_run("Web crawl", "crawl <name> <url>")
            return

        codes: dict = {}
        for page in pages:
            codes[page.status_code] = codes.get(page.status_code, 0) + 1
        breakdown = ', '.join(f"{code}: {n}" for code, n in sorted(codes.items(), key=lambda kv: str(kv[0])))
        self.console.print(f"[*] Crawl: {len(pages)} page(s) ({breakdown}); 'pages {host.addr}' lists them.")

        if emails:
            table = Table(title="Emails", title_justify="left")
            table.add_column("Email", style="cyan")
            table.add_column("Found on", style="white")
            for email in emails[:INFO_CAP_EMAILS]:
                table.add_row(email.email, email.source_url or '-')
            self.console.print(table)
            self._more_note(len(emails) - INFO_CAP_EMAILS, 'emails', host)

    def _info_fuzz(self, host: Host) -> None:
        findings = (
            self.session_db.query(Finding).filter_by(host_id=host.id)
            .order_by(Finding.url, Finding.path).all()
        )
        if not findings:
            self._not_run("Fuzz", "fuzz <name> <url>")
            return

        table = Table(title="Findings", title_justify="left")
        table.add_column("Path", style="cyan")
        table.add_column("Code", justify="right")
        table.add_column("Size", justify="right")
        table.add_column("Redirect", style="white")
        for finding in findings[:INFO_CAP_FINDINGS]:
            table.add_row(
                finding.path, str(finding.status_code),
                str(finding.size) if finding.size is not None else '-', finding.redirect or '-',
            )
        self.console.print(table)
        self._more_note(len(findings) - INFO_CAP_FINDINGS, 'findings', host)

    def _list_or_delete_rows(self, args, command, model, noun, run_hint, title, columns, row_values, order_by):
        """Shared by `findings`/`pages`/`emails` (same shape as `subdomains`): no
        argument lists every row, `<name|addr>` filters by host, `-d <name|addr>`
        deletes one host's rows (keeps the Host), `-d all` deletes every row for
        every host (asks for confirmation first). `columns` is a list of
        (header, style) after the leading Host column; `row_values(row)` returns
        the matching strings."""
        if args and args[0] == '-d':
            if len(args) < 2:
                self.console.print(f"[red]Usage: {command} -d <name|addr|all>[/red]")
                return
            target = args[1]
            if target == 'all':
                if not self._confirm_delete_all(f'all {noun}'):
                    self.console.print("[yellow]Cancelled.[/yellow]")
                    return
                for row in self._workspace_rows(model).all():
                    self.session_db.delete(row)
                self.session_db.commit()
                self.console.print(f"[green]All {noun} have been deleted.[/green]")
                return

            host = self._find_host_or_warn(target)
            if not host:
                return
            for row in self.session_db.query(model).filter_by(host_id=host.id).all():
                self.session_db.delete(row)
            self.session_db.commit()
            self.console.print(f"[green]{noun.capitalize()} for '{target}' deleted.[/green]")
            return

        query = self._workspace_rows(model)
        if args:
            host = self._find_host_or_warn(args[0])
            if not host:
                return
            query = query.filter(model.host_id == host.id)

        rows = query.order_by(Host.addr, *order_by).all()
        if not rows:
            self.console.print(f"[yellow]No {noun} registered yet. Run '{run_hint}' first.[/yellow]")
            return

        table = Table(title=title)
        table.add_column("Host", style="cyan")
        for header, style in columns:
            table.add_column(header, style=style)
        for row in rows:
            table.add_row(row.host.addr, *row_values(row))
        self.console.print(table)

    @staticmethod
    def _timestamp(value) -> str:
        return value.strftime('%Y-%m-%d %H:%M:%S')

    def command_findings(self, args):
        """Lists/deletes `Finding` rows saved by `fuzz`."""
        self._list_or_delete_rows(
            args, 'findings', Finding, 'findings', 'fuzz', 'Findings',
            [("URL", "white"), ("Path", "cyan"), ("Code", "white"), ("Size", "white"),
             ("Redirect", "white"), ("Discovered", "white")],
            lambda f: (
                f.url, f.path, str(f.status_code),
                str(f.size) if f.size is not None else '-',
                f.redirect or '-', self._timestamp(f.discovered_at),
            ),
            [Finding.url, Finding.path],
        )

    def command_pages(self, args):
        """Lists/deletes `CrawledPage` rows saved by `crawl`."""
        self._list_or_delete_rows(
            args, 'pages', CrawledPage, 'pages', 'crawl', 'Pages',
            [("URL", "cyan"), ("Code", "white"), ("Depth", "white"), ("Discovered", "white")],
            lambda p: (p.url, str(p.status_code), str(p.depth), self._timestamp(p.discovered_at)),
            [CrawledPage.url],
        )

    def command_emails(self, args):
        """Lists/deletes `HarvestedEmail` rows saved by `crawl`."""
        self._list_or_delete_rows(
            args, 'emails', HarvestedEmail, 'emails', 'crawl', 'Emails',
            [("Email", "cyan"), ("Found on", "white"), ("Discovered", "white")],
            lambda e: (e.email, e.source_url or '-', self._timestamp(e.discovered_at)),
            [HarvestedEmail.email],
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
        host = self._hosts_query().filter_by(addr=ident).first()
        if host:
            return host

        matches = self._hosts_query().filter_by(nome=ident).order_by(Host.addr).all()
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
                for host in self._hosts_query().all():
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

        hosts = self._hosts_query().order_by(Host.addr).all()
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
                for service in self._workspace_rows(Service).all():
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

        query = self._workspace_rows(Service).filter(current_services_filter())
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
                for vuln in self._workspace_rows(Vulnerability).all():
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

        query = self._workspace_rows(Vulnerability).filter(current_services_filter())
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
        whois_phase = WhoisPhase(self.session_db, workspace_id=self.workspace_id)

        try:
            record = whois_phase.run(domain=domain, on_progress=self._report_progress)
        except Exception as e:
            self.session_db.rollback()
            self.console.print(f"[red]Error fetching whois data: {e}[/red]")
            return

        table = Table(title=f"WHOIS Result: {domain}")
        table.add_column("Property", justify="right", style="cyan")
        table.add_column("Value", style="white")

        table.add_row("Registrar", str(record.registrar))
        table.add_row("Creation Date", str(record.creation_date))
        table.add_row("Expiration Date", str(record.expiration_date))

        self.console.print(table)
        self.console.print("[green]Saved to database successfully![/green]")

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
            workspace_id=self.workspace_id,
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
        for section in HELP_SECTIONS:
            table = Table(title=section.title, title_justify="left")
            table.add_column("Command", style="cyan")
            table.add_column("Description", style="white")
            for syntax, description in section.commands:
                # `[name|addr]` would be read as a rich style tag and vanish
                table.add_row(escape(syntax), description)
            self.console.print(table)
        self.console.print(
            "[dim]New here? 'phases' shows the workflow; 'info <host>' shows everything "
            "collected about a host.[/dim]"
        )
