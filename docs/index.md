# Sharingan

![Sharingan logo](assets/logo.png)

Sharingan is a Python pentest/reconnaissance framework, inspired by Metasploit's
`msfconsole`. It's an interactive console organized by **pentest methodology
phases** — recon, scan, vulnerability analysis — instead of a single script,
with all results persisted to a local database.

Rather than reimplementing scanners, crawlers or exploit databases, Sharingan
**orchestrates mature, community-trusted tools** (`rustscan`, `nmap`,
`searchsploit`, `subfinder`) and gives them one consistent console, a shared
scope, and a shared history.

## What it does today

- **Scope control** (`scope`): declare which domains, IPs and CIDR ranges are
  actually authorized to be touched. Every scan and recon run is checked
  against it first.
- **Surface scan** (`scan`): port discovery (`rustscan`) → service/version
  fingerprinting (`nmap -sV`) → CVE/CVSS correlation by CPE (`vulners`) →
  exploit-db cross-reference (`searchsploit`) → persistence.
- **Scan history** (`scans`, `scan diff`): every scan is kept, not
  overwritten — compare any host's last two scans to see what opened,
  closed, changed version, or gained/lost a CVE.
- **Passive subdomain discovery** (`recon`): queries public sources
  (certificate transparency, search engines, DNS aggregators) via
  `subfinder` — no traffic sent to the target itself.
- **Data queries** (`hosts`, `services`, `vulns`): msfconsole-style listing
  and deletion of what's been collected.
- **WHOIS lookups** (`whois`).
- **Session options** (`set`, `unset`, `options`): tune how the underlying
  tools behave (timeouts, batch sizes, user agent) for the session.

See **[Commands](commands.md)** for the full reference and
**[Session options](options.md)** for everything `set` accepts.

## Installation

Requires Python ≥ 3.12 and [`uv`](https://docs.astral.sh/uv/).

```bash
git clone <this repository>
cd sharingan
uv sync
```

The `scan` command also needs `rustscan`, `nmap`, and `searchsploit`
(`exploitdb` package) on the system `PATH`; `recon` needs `subfinder`. None
of these are Python packages. If a tool is missing, the console offers to
install it automatically where that's possible — see
[Getting started](getting-started.md).

## Running the console

```bash
uv run python src_sharingan/sharingan_repl.py
```

```text
Sharingan Advanced Enum Tool
Type 'help' to display available commands.
Sharingan >
```

## Ethical use

Sharingan is an offensive-security tool. Only run it against systems and
networks you are explicitly authorized to test. The `scope` command exists
specifically to make that boundary explicit and enforced, not just assumed.
