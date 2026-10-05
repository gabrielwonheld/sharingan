# Commands

Every command below is typed at the `Sharingan >` prompt. Arguments in
`<angle brackets>` are required; `[square brackets]` are optional.
Autocomplete (Tab) and the `help` command list the same set.

## `help`

```text
help
```

Prints the commands grouped by area — Overview, Recon, Scan, Web and Session —
one table per area, with syntax and a one-line description. The prompt
(`Sharingan [workspace] >`) shows which [workspace](#workspace-name-add-name-delete-name) you're in.

## `workspace [<name> | add <name> | delete <name>]`

Workspaces are projects: each one has its own hosts, everything the phases
collected for them, and its own [scope](#scope-addexcluderemove-value). Use one
per engagement so the same address can be worked on twice without the results
mixing. The prompt shows the current workspace, the way a shell shows the
current directory:

```text
Sharingan [default] > workspace add client-a
Workspace 'client-a' created; now working in it.
Sharingan [client-a] > scan web 10.0.0.1
```

| Form | Effect |
|---|---|
| `workspace` | Lists the workspaces (`*` marks the current one) with their host count. |
| `workspace <name>` | Switches to that workspace. |
| `workspace add <name>` | Creates a workspace **and switches to it**. Names use 1-40 letters, digits, `.`, `_` or `-`; `add` and `delete` are reserved. |
| `workspace delete <name>` | Deletes the workspace with its hosts, everything collected for them and its scope. Asks for confirmation. `default` can't be deleted; deleting the current one returns to `default`. |

Every command only sees the current workspace: `hosts`, `services`, `info`,
`phases`, name lookups, `-d all` deletes and scope checks. The workspace is
**not remembered between runs** — the console always starts in `default`.

## `export [path]`

Writes the **current [workspace](#workspace-name-add-name-delete-name)** as a
Markdown report: its scope, a summary table (one row per host with counts) and
one section per host with everything the phases collected — WHOIS, subdomains,
services, vulnerabilities (by CVSS), exploits, scan history, crawled pages,
emails and directory findings. Sections a host has no data for are left out.

| Form | Effect |
|---|---|
| `export` | Writes `sharingan-<workspace>-<YYYYMMDD-HHMMSS>.md` in the directory you started the console from. |
| `export <path>` | Writes to that file. A path with spaces works as typed. |
| `export <directory>` | Writes the default filename inside that directory. |

If the file already exists you're asked before it's overwritten; a directory
that doesn't exist is reported, not created.

```text
Sharingan [client-a] > export ~/reports/client-a.md
Report of workspace 'client-a' (3 host(s)) written to /home/me/reports/client-a.md
```

Unlike `info`, the report is the full dump — nothing is capped. Because banners,
page URLs and emails come from the scanned targets, table cells have `|` and
newlines neutralised and `<`/`>` escaped, so a hostile value can't break a
table or inject HTML into a Markdown viewer. The report is a plain file in your
filesystem: treat it as sensitive client data.

## `phases [name|addr]`

Lists the methodology phases (Recon, Scan, Web crawl, Fuzz): how much traffic
each one sends to the target, the command that runs it, the external tools it
uses and which commands list what it saved (see [Hosts and phases](hosts-and-phases.md)). `fases` is an alias.

With a host (`phases myserver`), an extra **Status** column shows which phases
already ran against it — with a short summary of what was saved — and which are
still missing, with the command to run next.

```text
Sharingan > phases
Sharingan > phases myserver
```

A planned `asm <domain>` command (run every phase from just a domain) is
mentioned at the bottom; it isn't available yet.

## `info <name|addr>`

Everything collected about one host, phase by phase, in one place: the latest
WHOIS record, subdomains, the current services (with CVE and exploit counts per
port), the top vulnerabilities by CVSS, a crawl summary with harvested emails,
and fuzz findings. A phase that hasn't run says so and names the command to run.

Each section is capped (25 subdomains, 10 vulnerabilities, 15 emails, 20
findings) and points to the dedicated command (`subdomains`, `vulns`, `emails`,
`findings`) for the full list. Services always reflect the host's latest scan.

```text
Sharingan > info myserver
```

## `whois <domain>`

Runs a WHOIS lookup against `domain` and prints registrar, creation date and
expiration date. The domain must pass the [scope](#scope-addexcluderemove-value)
check. The result is saved (`WhoisRecord`) and linked to the host for that
domain — the same host `scan` and `recon` use — so `hosts -d` removes it too.
Each lookup stores a new record, so changes over time stay visible. Only talks
to public WHOIS servers, never to the target. Doesn't require any external tool.

```text
Sharingan > whois example.com
```

## `scope [add|exclude|remove <value>]`

Manages the scope of the **current [workspace](#workspace-name-add-name-delete-name)** — each workspace keeps its own rules: the domains, IPs and CIDR ranges `scan` and
`recon` are allowed to touch. `scan`/`recon` check the scope **before**
anything is sent to the target.

| Form | Effect |
|---|---|
| `scope` | Lists every rule (include/exclude, type, value). |
| `scope add <value>` | Includes a domain, IP or CIDR range. Re-adding a value that was excluded flips it back to included. |
| `scope exclude <value>` | Excludes a domain, IP or CIDR range — exclusions always win over inclusions. |
| `scope remove <value>` | Removes a rule entirely (neither included nor excluded). |

`<value>` can be a domain (`example.com`, `*.example.com` — equivalent to
the bare domain), an IP (`192.0.2.10`), or a CIDR range (`192.0.2.0/24`).

Rules:

- A domain rule covers the domain itself **and its subdomains** on label
  boundaries (`example.com` covers `erp.example.com`, not
  `badexample.com` or `example.com.evil.net`).
- Matching is **literal, with no DNS resolution**: a hostname target is only
  checked against domain rules, an IP target only against `ip`/`cidr` rules.
- **With no `include` rule at all, scope is unrestricted** — any target is
  allowed (apart from explicit exclusions) — and `scan`/`recon` print a
  yellow notice so that's never silent.

```text
Sharingan > scope add example.com
Sharingan > scope exclude admin.example.com
Sharingan > scope
```

## `scan <name> <ip/host>`

Runs the Scan phase against `target`, tagged with a human-readable `name`
(reusable across different targets — it's just a label, not an identity;
the address is what identifies the host).

Pipeline: `rustscan` (port discovery) → `nmap -sV` (+ the `vulners` NSE
script when installed, for CVE/CVSS correlation by CPE) → `searchsploit`
(exploit-db cross-reference, per discovered service) → persistence.

- `rustscan` and `nmap` are mandatory — if either is missing, the console
  offers to install it; declining or a failed install aborts the scan.
- `searchsploit` is optional — declining or a failed install just skips
  that step; a runtime failure (e.g. a broken install) is reported without
  discarding everything nmap already found.
- `vulners` has no automated install (it's a standalone nmap `.nse` script,
  not a package) — if it's missing, a yellow warning is shown and
  `searchsploit` runs unconditionally instead of only for CVSS ≥
  `min_cvss` findings.
- Progress is printed step by step as each tool actually starts.
- **Every run creates a new entry in that host's scan history** (see
  `scans`/`scan diff`) instead of overwriting the previous result.
- Honors the `rustscan_batch` and `rustscan_timeout` [session options](options.md).
- Blocked outright (no process is ever run) when `target` fails the
  [scope](#scope-addexcluderemove-value) check.

```text
Sharingan > scan myserver 192.0.2.10
```

The result table shows each port's state and fingerprinted service. If any
vulnerabilities or exploits were found, they're printed as further tables,
one exploit table per service (capped at 10 rows each, newest/CVE-confirmed
first — see `searchsploit <term>` yourself for the full list).

## `scan diff <name|addr>`

Compares a host's **last two finished (`ok`) scans** and reports what
changed: ports opened/closed, service version changes, and CVEs
gained/resolved. Failed/interrupted runs are skipped (they'd otherwise look
like every port closed).

```text
Sharingan > scan diff myserver
```

If the host has fewer than two finished scans, or nothing changed between
the two most recent ones, the console says so explicitly instead of
printing an empty table.

## `scans [name|addr]`

Lists scan runs (the history `scan diff` reads from), newest first: run id,
host, status (`running`/`ok`/`failed`), start time, duration, and how many
services that run found. With an argument, filters to one host.

```text
Sharingan > scans
Sharingan > scans myserver
```

## `recon <name> <domain>`

Runs the Recon phase: passive subdomain discovery via `subfinder` against
public sources only (certificate transparency logs, search engines, DNS
aggregators) — unlike `scan`, **no traffic is sent to the target itself**.
Still checked against [scope](#scope-addexcluderemove-value) first, since
even passive recon reveals information about a target.

Subdomains already known from a previous `recon` run on the same host are
kept, not re-inserted; the result table marks each row `new` or `known` so a
re-run highlights what just appeared.

`subfinder` is required — same ask-and-install flow as `rustscan`/`nmap`.

```text
Sharingan > recon myserver example.com
[*] Discovering subdomains (subfinder -d example.com)...
```

## `subdomains [name|addr] [-d <name|addr|all>]`

Lists or deletes `Subdomain` rows found by `recon` — host, name, and when it
was first discovered. Same shape as `services`/`vulns`.

| Form | Effect |
|---|---|
| `subdomains` | Lists every host's subdomains. |
| `subdomains <name\|addr>` | Lists only that host's subdomains. |
| `subdomains -d <name\|addr>` | Deletes that host's subdomains — keeps the `Host` itself. |
| `subdomains -d all` | Deletes every subdomain for every host. Asks for confirmation first. |

```text
Sharingan > subdomains
Sharingan > subdomains myserver
```

## `findings`, `pages`, `emails`

List or delete what `fuzz` and `crawl` saved, with the same forms as
[`subdomains`](#subdomains-nameaddr--d-nameaddrall):

| Command | Shows | Saved by |
|---|---|---|
| `findings` | host, base URL, path, status code, size, redirect, when discovered | `fuzz` |
| `pages` | host, URL, status code, depth, when discovered | `crawl` |
| `emails` | host, address, first page it appeared on, when discovered | `crawl` |

| Form | Effect |
|---|---|
| `<command>` | Lists every host's rows. |
| `<command> <name\|addr>` | Lists only that host's rows. |
| `<command> -d <name\|addr>` | Deletes that host's rows — keeps the `Host` itself. |
| `<command> -d all` | Deletes every row for every host. Asks for confirmation first. |

```text
Sharingan > findings myserver
Sharingan > pages
Sharingan > emails -d myserver
```

## `fuzz <name> <url>`

Directory/file enumeration against a web target, via `gobuster dir`. Unlike
`scan` and `recon`, this is **opt-in only** — it is never run automatically
as part of `scan`, because it sends a real, sizeable volume of HTTP
requests to the target (closer to an active brute-force than `scan`'s
banner-grabbing or `recon`'s fully passive lookups).

Requires the [`fuzz_wordlist` session option](options.md) to
be set first — there's no universal default wordlist Sharingan can assume
is on disk:

```text
Sharingan > set fuzz_wordlist /usr/share/seclists/Discovery/Web-Content/common.txt
Sharingan > fuzz myserver http://example.com
```

- `url` must include a scheme and host (`http://example.com`, not just
  `example.com`) — its hostname is what gets checked against
  [scope](#scope-addexcluderemove-value) before anything runs, and what
  `gobuster` is pointed at.
- `gobuster` is required — same ask-and-install flow as `rustscan`/`nmap`/`subfinder`.
- Honors `fuzz_extensions` and `fuzz_threads` ([session options](options.md)).
- Findings already known from a previous `fuzz` run against the same host
  and base URL are kept, not re-inserted; the result table marks each row
  `new` or `known`.

```text
Sharingan > fuzz myserver http://example.com
[*] Enumerating directories/files (gobuster dir -u http://example.com)...
```

## `crawl <name> <url>`

Bounded crawl of a web site, collecting the pages it reaches and any email
addresses found in them. Sends real HTTP requests, so it is opt-in and never
part of `scan`.

```text
Sharingan > crawl myserver http://example.com/
```

- The start host is checked against the [scope](#scope-addexcluderemove-value)
  first, and **every host a link points to is checked again** before it's
  requested. Independently of scope, the crawl never leaves the start site (its
  host or subdomains) — even with no scope defined.
- Limits come from the `spider_max_depth`, `spider_max_pages` and
  `spider_delay` [session options](options.md); requests carry the
  `user_agent` option.
- Redirects aren't followed blindly: a `Location` is treated like any other
  link, so an out-of-scope redirect is never requested.
- Shows a **Pages** table (URL, code, depth) and an **Emails** table (address,
  first page it appeared on), each row marked `new` or `known` against earlier
  crawls of the same host.

## `hosts [-d <name|addr|all>]`

A host is identified by its address; the name is only a label. See [Hosts and
phases](hosts-and-phases.md) for how every phase attaches its results to a host.

| Form | Effect |
|---|---|
| `hosts` | Lists every host: name, address, active ports. |
| `hosts -d <name\|addr>` | Deletes one host — cascades to its services, vulnerabilities and exploit matches. |
| `hosts -d all` | Deletes **every** host (and everything linked to them). Asks for confirmation first. |

## `services [name|addr] [-d <name|addr|all>]`

Lists or deletes `Service` rows (port + fingerprinted product/version),
scoped to each host's **current** scan (its latest non-failed run — older
history stays queryable via `scans`/`scan diff`, just not shown here by
default).

| Form | Effect |
|---|---|
| `services` | Lists every host's current services. |
| `services <name\|addr>` | Lists only that host's current services. |
| `services -d <name\|addr>` | Deletes that host's services (all runs, including history) — keeps the `Host` itself. |
| `services -d all` | Deletes every service for every host. Asks for confirmation first. |

## `vulns [name|addr] [-d <name|addr|all>]`

Same shape as `services`, for `Vulnerability` rows (CVE/CVSS via `vulners`,
sorted by descending CVSS), also scoped to each host's current scan.

```text
Sharingan > vulns
Sharingan > vulns myserver
Sharingan > vulns -d myserver
```

## `set <option> <value>`

Sets a [session option](options.md). Everything after the option name is
the value — no quoting needed for a value with spaces (e.g. a full
User-Agent string).

```text
Sharingan > set rustscan_batch 500
Sharingan > set user_agent Mozilla/5.0 (X11; Linux x86_64)
```

## `unset <option>`

Resets a session option back to its default.

```text
Sharingan > unset rustscan_batch
```

## `options`

Shows every session option: current value, default, and what it does. See
[Session options](options.md) for the full reference.

## `clear`

Clears the terminal screen.

## `exit` / `quit`

Exits the console.
