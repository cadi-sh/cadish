# `cadish logs` — live debug logging (access tail + decision trace)

Two tools for watching a running cadish and understanding *why* a request did what
it did — the NCSA-style access tail and the per-request decision trace.

| Tool | What it shows |
|---|---|
| `cadish logs [-f]` | one line per request — method, host, path, status, cache result, bytes, latency, upstream — with filters and an optional Apache/NCSA format. |
| `cadish run -trace` | a multi-line **decision trace** per request — matched route, computed cache key, LOOKUP outcome, `cache_ttl` ttl/grace/hit-for-miss, pass reason, routed upstream, body transforms. |

---

## The access tail: `cadish logs`

cadish keeps one **structured access record per request** in memory and fans it out
to attached consumers — it **never writes the access log to disk** (a
memory-only access-log model: the hot path touches only memory; viewing/persisting is the
consumer's job). `cadish logs` is that consumer: it streams the live log, filters
it, and renders it.

### The source: a live unix socket (or a saved file / pipe)

By default `cadish logs` **dials the running server's access-log unix socket** and
streams the **live** access log (NDJSON, one JSON object per line). `cadish run`
always listens on this socket; its path is **per-instance** — derived from the
instance's `-addr` so two cadish instances on the same host don't collide
(`${TMPDIR}/cadish-access-<hash>.sock`), overridable verbatim with `-log-socket PATH`
or the `$CADISH_ACCESS_SOCKET` env var. The socket is local-only and created with
`0600` permissions. The hub is **idle-free** until a consumer attaches and
**live-only** — no history is replayed on connect.

`cadish logs` derives the same per-instance path from its own `-addr` (default
`:80`), so a single-instance tail needs no flags; point it at another instance by
matching that instance's `-addr`, or pass `-log-socket PATH` explicitly.

```bash
cadish run -config Cadishfile                          # always serves the socket
cadish logs                                            # stream the live access log
cadish logs > access.log                               # persist the live stream
cadish logs -log-socket /run/cadish/access.sock        # custom socket path
```

To read a **previously-saved** NDJSON log, pass a `FILE` (or pipe NDJSON on stdin):

```bash
cadish logs -f /var/log/cadish/access.json             # follow a saved file (tail -f)
cat access.log | cadish logs -format ncsa              # piped/stdin
```

> **Migration from `-access-log FILE` (removed).** The server no longer writes the
> access log to a file. To persist it, redirect the consumer:
> `cadish logs > /var/log/cadish/access.log` (or pipe it to your log shipper). To
> turn the access log off entirely (zero hot-path cost), use the global
> `access_log off` option or `cadish run -access-log off`.

### Usage

```
cadish logs [-format text|ncsa|json] [filters]              # live (socket)
cadish logs [-f] [-from-start] [-format …] [filters] FILE   # saved file
```

| Flag | Effect |
|---|---|
| `-addr ADDR` | The listen address of the cadish instance to tail (default `:80`); selects its per-instance access-log socket. Must match the instance's `-addr`. |
| `-log-socket PATH` | The access-log socket to stream live from when no `FILE` is given. Overrides the per-instance path derived from `-addr` (also settable via `$CADISH_ACCESS_SOCKET`). |
| `-f` | Follow a `FILE` and stream new lines (like `tail -f`), until interrupted. Requires a `FILE` (the socket is already a live stream; you cannot tail stdin). Polls the file (no `inotify` dependency) and survives log rotation/truncation. |
| `-from-start` | With `-f`, emit the whole file first, then tail (default: tail from the end). |
| `-format` | Output rendering: `text` (default, compact human line), `ncsa` (Apache "combined"-style), or `json` (echo the original object — a filtered pass-through). |

**Filters** (combined with AND; an unset filter matches everything):

| Flag | Effect |
|---|---|
| `-host SUB` | host contains `SUB` (case-insensitive substring). |
| `-path SUB` | path contains `SUB` (case-insensitive substring). |
| `-cache TOKEN` | exact cache status: `HIT`, `MISS`, `HIT-STALE`, `HIT-STALE-ERROR`, `PASS`, `SYNTH`, `PURGE`, `DENY`, `RATELIMIT`, `REDIRECT`. |
| `-status CODE` | exact HTTP status (e.g. `404`). |
| `-status-class N` | status class `N` in `1..5` (e.g. `5` for `5xx`). |
| `-min-status CODE` | statuses `>= CODE` (e.g. `400` for "errors only"). |

### Examples

```bash
# Live cache misses for one host (streams the socket):
cadish logs -host shop.example.com -cache MISS

# Only errors, Apache format, persisted to a file:
cadish logs -min-status 400 -format ncsa > errors.ncsa

# Everything for an asset path, replayed from the top of a SAVED file:
cadish logs -f -from-start access.json -path /img/
```

### The NCSA format

`-format ncsa` renders the Apache "combined"-style line. cadish's access log
deliberately omits the **client IP** and the **query string** (signed-URL
signatures are sensitive), so those fields render as `-`; the cache status and
upstream are appended as extra quoted fields:

```
shop.example.com - - [23/Jun/2026:13:00:00 +0000] "GET /img/a.png HTTP/1.1" 200 1024 "-" "-" "HIT" "cache:ram"
```

---

## The transaction trace: `cadish run -trace`

To understand *why* a request did what it did — which rule fired, what cache key was
computed, what TTL decision the response phase made — run cadish with `-trace`:

```bash
cadish run -config Cadishfile -trace            # trace -> stderr
# or:  CADISH_TRACE=1 cadish run -config Cadishfile
```

Each request emits one decision-trace transaction block to stderr:

```
* << Request >> 13:00:00.123
-   ReqLine     GET shop.example.com/img/a.png
-   RECV        upstream=assets
-   KEY         GET shop.example.com /img/a.png
-   LOOKUP      MISS
-   ORIGIN      fetch upstream=assets
-   RESP        status=200 cacheable ttl=1h0m0s grace=10m0s store=yes
-   DELIVER     replace "http://" -> "https://"
-   End         status=200 cache=MISS dur_ms=7
```

The lines map to the handler's decision points:

| Tag | Decision point | Detail |
|---|---|---|
| `RECV` | `EvalRequest` | routed upstream; `respond`/`purge`/`pass`; request-header ops (`REQHDR`). |
| `KEY` | `cache_key` | the computed cache key. |
| `LOOKUP` | freshness index | `FRESH` / `STALE` / `MISS` / `HIT-FOR-MISS` / `PASS`. |
| `ORIGIN` | origin fetch | the upstream actually fetched. |
| `RESP` | `EvalResponse` | `cacheable ttl=… grace=…` or `hit_for_miss=…` or `uncacheable`; `tier=…`; `store=yes/no`. |
| `DELIVER` | `EvalDeliver` | body transforms (`replace`) applied. |
| `End` | — | final status, cache outcome, wall-clock ms. |

### Zero cost when off

Tracing is **opt-in**. The trace seam is a nil-checked `*Tracer` on the handler
(`internal/server/tracer.go`); when `-trace` is not set it is `nil`, every
per-request hook is a no-op on a `nil` record, and the datapath does **no
allocation and no formatting** — exactly how the metrics seam is gated. A
non-tracing cadish pays nothing.

> The trace is verbose (one block per request) and goes to stderr — it is a
> **debugging** tool, not a production firehose. For steady-state observability use
> the access log (`cadish logs`, optionally redirected to a file) or the `admin`
> dashboard/metrics.
