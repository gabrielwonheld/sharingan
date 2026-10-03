# Session options

Managed with [`set`, `unset` and `options`](commands.md#set-option-value).
They live in memory for the current console session only — they reset to
their defaults the next time you start Sharingan. The source of truth is the
`OPTIONS` table in `src_sharingan/core/context.py`; this page mirrors it.

| Option | Default | Type | Used by | Description |
|---|---|---|---|---|
| `rustscan_batch` | `4500` | positive integer | `scan` | Ports `rustscan` probes at once. Lower it for slow or filtered remote hosts. |
| `rustscan_timeout` | `3000` | positive integer | `scan` | Milliseconds `rustscan` waits for each port. Raise it for distant hosts. |
| `user_agent` | `Sharingan` | non-empty text | *(reserved)* | User-Agent for HTTP requests. Not consumed by any command yet — `scan`'s port discovery and fingerprinting (`rustscan`/`nmap`) make no HTTP requests at all, so setting it has no effect today. It's wired in ahead of the planned crawler (see `CLAUDE.md`'s pending-items list for the spider migration). |
| `fuzz_wordlist` | *(empty)* | text, empty allowed | `fuzz` | Path to the wordlist `fuzz` passes to `gobuster -w`. **Required** before `fuzz` will run — there's no universal default wordlist Sharingan can assume is on disk. |
| `fuzz_extensions` | *(empty)* | text, empty allowed | `fuzz` | Comma-separated extensions passed to `gobuster -x`, e.g. `php,txt,bak`. Optional — leave unset to not filter by extension. |
| `fuzz_threads` | `10` | positive integer | `fuzz` | Concurrent threads passed to `gobuster -t`. |

## Why change these

A scan that comes back with no open ports at all against a host you *know*
is reachable is often a timing issue, not a dead target: a slow or
filtered network path can need a smaller `rustscan_batch` and/or a larger
`rustscan_timeout` than the defaults (tuned for a fast, local/LAN target).

```text
Sharingan > set rustscan_batch 500
rustscan_batch => 500
Sharingan > set rustscan_timeout 8000
rustscan_timeout => 8000
Sharingan > scan myserver erp.example.com
```

## Validation

`set` converts and validates the value before accepting it — an invalid
value leaves the option unchanged and prints why:

```text
Sharingan > set rustscan_batch abc
Invalid value for rustscan_batch: 'abc' is not a whole number.
Sharingan > set rustscan_batch 0
Invalid value for rustscan_batch: must be greater than zero.
Sharingan > set nope 1
Unknown option 'nope'. Valid options: rustscan_batch, rustscan_timeout, user_agent.
```
