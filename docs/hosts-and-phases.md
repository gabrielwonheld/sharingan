# How phases and hosts relate

Every phase (`whois`, `recon`, `scan`, `crawl`, `fuzz`) is a separate command,
but they don't produce separate piles of data: they all attach what they find
to the same **host** record. That's what lets `info <host>` show everything at
once and `phases <host>` show what's still missing.

## One host, many results

```text
                  Workspace → Host  (identity = address within the workspace)
                           │
   ┌──────────┬────────────┼─────────────┬──────────────┬───────────┐
WhoisRecord  Subdomain   ScanRun      CrawledPage    Finding   HarvestedEmail
 (whois)     (recon)       │            (crawl)       (fuzz)     (crawl)
                         Service
                           ├── Vulnerability  (vulners CVEs)
                           └── ExploitMatch   (searchsploit)
```

Each result row stores a `host_id`. Nothing is matched by name or searched by
text: `info` and `phases` simply ask the database for "every row whose
`host_id` is this host". Deleting a host (`hosts -d`) deletes all of its rows.

## What identifies a host: the address

A host is identified by its **address** (`addr`) **within a workspace**: the
address is unique per workspace. The first command that touches an address
creates the host in the current workspace; every later command, from any phase,
reuses it. The same address in another [workspace](commands.md#workspace-name-add-name-delete-name)
is a different host.

What each command uses as the address:

| Command | Address used |
|---|---|
| `scan <name> <target>` | `<target>` exactly as typed (IP or hostname). |
| `whois <domain>` | `<domain>` exactly as typed. |
| `recon <name> <domain>` | `<domain>` exactly as typed. |
| `crawl <name> <url>` / `fuzz <name> <url>` | The URL's **hostname** only, lowercased: scheme, port and path are dropped. |

So `recon myproject example.com`, `whois example.com` and
`crawl myproject http://example.com/` all land on the same host,
`example.com`.

## What the name is for

The `<name>` you type is just a **label** for you: it's shown in tables and
accepted wherever a command takes `<name|addr>`. It is not the identity.

- The **first** name given to an address sticks. Running
  `scan other-name 192.0.2.10` on an address first scanned as `web` keeps `web`
  and adds the new results to that same host.
- Several addresses can share a name (`web` for `10.0.0.1` and `10.0.0.2`).
- When a command takes `<name|addr>`, Sharingan tries the **address first**,
  then the name, **inside the current workspace only**. If a name matches more
  than one host there, the command stops and asks for the address instead of
  guessing:

```text
Sharingan > info web
Name 'web' is ambiguous (10.0.0.1, 10.0.0.2). Use the address instead.
```

## How `phases <host>` and `info <host>` read it

| Phase | Counts as "done" when the host has... |
|---|---|
| Recon | at least one WHOIS record or subdomain |
| Scan | a scan run that didn't fail, or services from before scan history existed |
| Web crawl | at least one crawled page or harvested email |
| Fuzz | at least one finding |

Services shown by `info` are always the ones from the host's **latest** scan;
older scans stay available through `scans` and `scan diff`.

## Things to know

- **Same address, same host.** Two web apps on `127.0.0.1` (ports 8090 and
  3000) share one host. Their `fuzz` findings stay apart because findings are
  also keyed by base URL, but `info` shows them together.
- **A domain and its IP are different hosts.** There's no DNS resolution:
  `scan 192.0.2.10` and `recon example.com` create two hosts even if the domain
  points at that IP. Matching is literal, the same rule `scope` follows.
- **Addresses are case-sensitive.** `scan`, `whois` and `recon` use what you
  type, while `crawl` and `fuzz` lowercase the hostname, so `Example.com` and
  `example.com` can end up as two hosts. Type domains in lowercase.
- **Workspaces keep projects apart.** `workspace add client-a` creates a
  project and switches to it; its hosts, results and scope are invisible from
  any other workspace, so scanning the same address for two clients gives two
  separate hosts. Names only need to be unique within a workspace.
  Pre-existing data lives in `default`. If you want a hard boundary on disk too
  (to archive or hand over one project), give it its own database:

  ```bash
  DATABASE_URL="sqlite:////home/me/projects/client-a.db" uv run python src_sharingan/sharingan_repl.py
  ```
