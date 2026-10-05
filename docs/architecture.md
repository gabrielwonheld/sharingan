# Architecture

This page is a short map for contributors. The full, continuously-updated
history of decisions, bugs and their fixes lives in `CLAUDE.md` at the
repository root — read that first before changing anything.

## Phases

Each step of the pentest methodology is a self-contained module implementing
`PhaseModule` (`phases/base.py`): a `name`, a `description`, and a
`run(**options)` method. The console discovers and runs phases through this
one interface, the same way Metasploit's modules work.

```text
phases/
├── base.py            # PhaseModule interface
├── common.py           # shared helpers (e.g. get_or_create_host)
├── scan/
│   ├── scan_phase.py    # rustscan -> nmap(+vulners) -> searchsploit -> persistence
│   ├── scan_diff.py      # pure diff between two ScanRuns
│   └── tools/              # one thin subprocess wrapper per external tool
└── recon/
    ├── recon_phase.py    # subfinder -> persistence
    └── tools/
        └── subfinder_tool.py
```

## The external-tool pattern

Every external tool (`rustscan`, `nmap`, `searchsploit`, `subfinder`, ...)
is wrapped in its own class with:

- `is_available()` — checks the binary on `PATH` (`shutil.which`), nothing
  more.
- One method that runs the `subprocess` call and parses its output into
  plain Python objects/dataclasses.

Phases receive these classes via dependency injection (constructor
defaults point at the real implementation), which is what lets the whole
orchestration be tested with fakes — **no test ever touches the network, a
real subprocess, or a real binary.**

## Data model

How the phases share one `Host` per address is explained in [Hosts and phases](hosts-and-phases.md).

- `Host` — one row per scanned/reconned address (the address is the
  identity; the name is just a label).
- `ScanRun` — one row per `scan` execution. `Service` rows (and, through
  them, `Vulnerability`/`ExploitMatch`) belong to the run that found them,
  so history isn't overwritten. `current_services_filter()` is the query
  helper that selects each host's latest non-failed run.
- `Subdomain` — one row per subdomain `recon` has found for a `Host`,
  deduplicated across runs.
- `ScopeRule` — one include/exclude row (domain/ip/cidr) consulted by
  `core/scope.py`'s `decide()` before `scan`/`recon` touch a target.

## Database

SQLAlchemy 2.x + local SQLite by default (`DATABASE_URL` env var to
override). There's no Alembic: `db/migrations.py`'s
`run_lightweight_migrations()` runs after `create_all()` on every startup
and knows how to add columns a model gained since the database was created —
it never renames or removes anything.

## Console

`view/console.py`'s `InteractiveConsole` wires every command to a
`command_*` method, all listed in [Commands](commands.md). It's the only
place that talks to `rich`/`prompt_toolkit` — phases themselves are UI-free
(progress is reported through a plain `str -> None` callback, not a direct
print).
