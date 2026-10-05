"""What the console tells the user about itself: `help` (commands grouped by
area) and `phases` (the methodology phases). Pure data, so both views read the
same source and a test can check it against the console's real command table.
"""
from dataclasses import dataclass


@dataclass(frozen=True)
class HelpSection:
    title: str
    commands: tuple[tuple[str, str], ...]  # (syntax, description)


@dataclass(frozen=True)
class PhaseInfo:
    key: str
    title: str
    traffic: str       # what the target sees
    run_with: str
    tools: str
    results: str       # commands that list what the phase saved
    not_run_hint: str  # shown when the phase hasn't run for a host


HELP_SECTIONS: tuple[HelpSection, ...] = (
    HelpSection('Overview', (
        ('phases [name|addr]', "List the phases; with a host, show which already ran on it (alias: fases)."),
        ('info <name|addr>', "Everything collected about one host, across all phases."),
        ('workspace [<name> | add <name> | delete <name>]', "List, switch to, create or delete workspaces (projects). The prompt shows the current one."),
        ('export [path]', "Write the current workspace as a Markdown report (default: a timestamped file in the current directory)."),
        ('hosts [-d <name|addr|all>]', "List hosts, or delete one host (cascades) / all hosts."),
        ('scope [add|exclude|remove <value>]', "Show or edit the scope (domain, IP or CIDR). Targets outside it are blocked."),
    )),
    HelpSection('Recon — passive, no traffic to the target', (
        ('whois <domain>', "WHOIS lookup; saved and linked to the domain's host."),
        ('recon <name> <domain>', "Passive subdomain discovery (subfinder); shows new vs. known."),
        ('subdomains [name|addr] [-d <name|addr|all>]', "List subdomains found by recon, or delete them."),
    )),
    HelpSection('Scan — active, probes the target', (
        ('scan <name> <ip/host>', "rustscan + nmap -sV (+ vulners) + searchsploit; saved to the DB."),
        ('scan diff <name|addr>', "Compare the host's last two finished scans."),
        ('scans [name|addr]', "List scan runs (history), optionally for one host."),
        ('services [name|addr] [-d <name|addr|all>]', "List services (optionally by host), or delete them."),
        ('vulns [name|addr] [-d <name|addr|all>]', "List vulnerabilities (optionally by host), or delete them."),
    )),
    HelpSection('Web — active, HTTP requests to the target', (
        ('crawl <name> <url>', "Bounded crawl: pages and emails; scope-checked, see the spider_* options."),
        ('pages [name|addr] [-d <name|addr|all>]', "List pages found by crawl, or delete them."),
        ('emails [name|addr] [-d <name|addr|all>]', "List emails found by crawl, or delete them."),
        ('fuzz <name> <url>', "Directory/file enumeration (gobuster); needs 'fuzz_wordlist' set."),
        ('findings [name|addr] [-d <name|addr|all>]', "List paths found by fuzz, or delete them."),
    )),
    HelpSection('Session', (
        ('set <option> <value>', "Set a session option (see 'options' for the full list)."),
        ('unset <option>', "Reset a session option to its default."),
        ('options', "Show session options, their defaults and what they do."),
        ('help', "Show this list."),
        ('clear', "Clear the terminal screen."),
        ('exit / quit', "Exit the console."),
    )),
)

PHASES: tuple[PhaseInfo, ...] = (
    PhaseInfo('recon', 'Recon', 'None — public sources only',
              'whois <domain>, recon <name> <domain>', 'python-whois, subfinder',
              'info, subdomains', 'whois <domain> / recon <name> <domain>'),
    PhaseInfo('scan', 'Scan', 'Active — port probes',
              'scan <name> <ip/host>', 'rustscan, nmap (+ vulners), searchsploit',
              'info, services, vulns, scans, scan diff', 'scan <name> <ip/host>'),
    PhaseInfo('crawl', 'Web crawl', 'Active — HTTP, bounded',
              'crawl <name> <url>', 'built-in (requests)',
              'info, pages, emails', 'crawl <name> <url>'),
    PhaseInfo('fuzz', 'Fuzz', 'Active — high request volume',
              'fuzz <name> <url>', 'gobuster',
              'info, findings', 'fuzz <name> <url>'),
)

PLANNED_NOTE = (
    "Planned: asm <domain> — run every phase above, in order, from just a domain "
    "(not available yet)."
)


def command_names() -> set[str]:
    """Every command word `help` documents ('exit / quit' counts as two)."""
    names: set[str] = set()
    for section in HELP_SECTIONS:
        for syntax, _ in section.commands:
            head = syntax.split('[')[0].split('<')[0]
            names.update(word for word in head.replace('/', ' ').split() if word != 'diff')
    names.add('fases')  # alias of `phases`, mentioned in its description
    return names
