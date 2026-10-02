# Getting started

## Requirements

- Python ≥ 3.12
- [`uv`](https://docs.astral.sh/uv/) (`curl -LsSf https://astral.sh/uv/install.sh | sh`, or `pipx install uv`)

## Install

```bash
git clone <this repository>
cd sharingan
uv sync
```

This installs the Python dependencies (SQLAlchemy, `rich`, `prompt_toolkit`,
`requests`/`beautifulsoup4`, `scapy`, `python-whois`, ...). It does **not**
install the external, non-Python tools some commands orchestrate.

## External tools

| Tool | Used by | Required? |
|---|---|---|
| [`rustscan`](https://github.com/RustScan/RustScan) | `scan` (port discovery) | Yes |
| [`nmap`](https://nmap.org/) | `scan` (service/version fingerprinting, CVE correlation) | Yes |
| `searchsploit` (`exploitdb` package) + `xmllint` | `scan` (exploit-db cross-reference) | No — `scan` still runs without it |
| `vulners` NSE script | `scan` (CVE/CVSS via CPE, embedded in the `nmap -sV` call) | No — falls back to `searchsploit` running unconditionally |
| [`subfinder`](https://github.com/projectdiscovery/subfinder) | `recon` (passive subdomain discovery) | Yes, for `recon` only |

You don't need any of these to run the test suite or to use `whois`, `hosts`,
`services`, `vulns`, `scope`, `set`/`unset`/`options`.

**You don't have to install these by hand.** The first time a command needs a
missing tool, the console asks whether to install it and runs the
appropriate package-manager command for your system (apt/dnf/pacman/brew, or
`cargo`/`go install` for the tools that have no official Linux package).
Declining, or a tool with no automated path on your system, prints a manual
install hint and — for optional tools — the command still proceeds without
that step.

!!! note "Why isn't rustscan just `apt install`-able?"
    RustScan has no official package on apt/dnf/pacman on any mainstream
    distro, including Kali. The project deliberately does not auto-download
    its `.deb` from GitHub (a different trust surface than a distro's own
    package manager) — install it with `cargo install rustscan`, Homebrew,
    or manually from the [releases page](https://github.com/RustScan/RustScan/releases).

## Running the console

From the repository root, with dependencies installed:

```bash
uv run python src_sharingan/sharingan_repl.py
```

Type `help` to see the command list, `exit` or `quit` to leave.

!!! warning "Entry point"
    `src_sharingan/sharingan_repl.py` is the only supported way to run
    Sharingan today. `main.py` (repo root) and `src_sharingan/sharingan`
    (the legacy `argparse` CLI) still exist in the tree but are not
    integrated with the console or its database-backed phases.

## Running the tests

```bash
uv run pytest src_sharingan/tests -v
```

The suite needs none of the external tools above — every subprocess call is
mocked or injected with a fake, and no test touches the network.

## A first session

```text
Sharingan > scope add example.com
example.com included in scope.
Sharingan > scan myserver example.com
[*] Starting scan of example.com...
[*] Scanning open ports (rustscan)...
[*] Fingerprinting services and versions, with CVE/CVSS correlation (nmap -sV + vulners)...
...
Sharingan > recon myserver example.com
...
Sharingan > hosts
Sharingan > scan diff example.com
```

See [Commands](commands.md) for what each of these does in detail.
