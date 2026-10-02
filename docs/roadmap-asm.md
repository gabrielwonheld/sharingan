# Roadmap discussion: pentest console vs. ASM (2026-10-01)

Notes from a planning conversation. Nothing here is implemented yet.

## Where we stopped (2026-10-01)

- The per-service exploit grouping feature (searchsploit `-t` per service, CVE cross-reference, display cap) is done and tested (118 tests passing) but **not committed**.
- Untracked/noisy files to deal with before committing: `src_sharingan/msfinstall`, `src_sharingan/nmap.xml`, and the modified, versioned `src_sharingan/sharingan.db` (consider untracking it).
- Dead code to delete: `phases/scan/tools/ubuntu_cve_tool.py` and `tests/test_ubuntu_cve_tool.py`.

## Progress (2026-10-02)

- Done: `ScanRun` model + migration, `ScanPhase` writes per run (history kept), `current_services_filter`, `scans` and `scan diff` console commands.
- Done: commits, dead code removal, `set`/`unset`/`options` (`SessionContext`), scope (`scope` command + enforcement in `scan`).
- Done: Recon phase (`phases/recon/`) — passive subdomain discovery via subfinder, reusing Host, tracking new-vs-known per run.
- Pending: web phase (crawl + directory enumeration), DNS resolution of discovered subdomains, change-detection alerts across recon runs.

## What the project is today

An msf-style console that orchestrates rustscan -> nmap -sV (+ vulners) -> searchsploit and persists results in SQLite. It works as a manual-recon assistant: it automates the repetitive work and leaves decisions to the human.

## What an ASM (Attack Surface Management) would require

ASM means continuous asset discovery with history and change alerts. Gaps versus today:

1. **Asset discovery**: subdomains (subfinder/amass/crt.sh), DNS resolution (dnsx), IP/ASN mapping, HTTP fingerprinting (httpx), cloud assets (open buckets, subdomain takeover). This is the `phases/recon/` roadmap item at scale.
2. **Temporal data model**: `Asset` with `first_seen`/`last_seen`, `ScanRun` history, `Finding` with state (new/persistent/resolved). This contradicts today's behavior, where `_clear_previous_scan_data` wipes the previous snapshot. Needs real migrations (consider Alembic).
3. **Scope entity** (`Target`/`Organization`): root domains/ranges, in-scope vs. out-of-scope. Mandatory for legal safety.
4. **Scheduled execution**: scheduler plus a non-interactive/daemon mode.
5. **Change detection and alerts**: new port, new subdomain, version change, new critical CVE; webhook/Slack/email.
6. **Prioritization**: CVSS + exposure + public exploit availability.
7. **UI**: API and dashboard.

## Decision: evolution, not a parallel project

Keep one shared core (`phases/`, tools, models, db) with two front-ends:

```
core (phases, tools, models, db)
   |-- interactive console  (today)
   '-- ASM mode             (scheduler + diff + alerts + API)
```

The temporal model also benefits the console (diff between scans, per-host history). Only split into a separate package/repo if ASM grows its own dashboard, multi-user support, Postgres and deployment.

## Which is more useful now

The pentest console, because it already works, ASM has strong existing competition (Censys, runZero, ProjectDiscovery, etc.), and a polished console is easier to ship as open source. The continuous-monitoring idea is the project's most differentiating angle.

## Suggested order

1. Close out the console: commit, cleanup, workspaces, report export, basic recon.
2. In parallel and cheap: introduce scan history (`ScanRun`), keeping the ASM option open.
3. Asset discovery, diff and alerts (light ASM).
4. Only later: API, dashboard, possible package split.

## Goal (answered 2026-10-02)

Open-source portfolio first, with a possible path to commercial use (open-core style, as other security tools do). This favors the shared-core design and building the temporal model (`ScanRun`) and scope entity early. Licensing choice and multi-tenancy become relevant before any commercial step.

## Constraints to keep

- Orchestrate mature tools instead of reimplementing them.
- Any phase that can exploit or open a shell requires explicit human confirmation (no automatic recon -> exploit chain).
- TDD, English-only code/docs/UI, no network calls in tests.
