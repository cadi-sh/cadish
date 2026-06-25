# Integration harness (real-binary end-to-end)

Backlog **#4 / task #34**. Brings up the **real** cadish image (built from
[`deploy/Dockerfile`](../../deploy/Dockerfile), distroless-nonroot) in front of the
[`test/origin`](../origin) HTTP origin and a **MinIO** S3 bucket, then drives the actual
binary over the network. The in-process httptest suite in [`test/e2e`](../e2e) already
covers request/response behavior; this harness validates what httptest can't: the built
artifact, the container/volume wiring, and the S3-compatible upstream path.

Gated behind `//go:build integration`, so the default `go test ./...` never touches
Docker.

## Run

Needs a working Docker daemon (`docker` + `docker compose`). The Go test orchestrates
everything — bring-up, readiness wait, and teardown:

```bash
go test -tags integration ./test/integration -v -timeout 15m
```

If Docker is not installed the suite **skips** (it is opt-in infrastructure, not part of
the correctness gate).

To inspect the stack by hand:

```bash
docker compose -f test/integration/docker-compose.yml up --build -d
curl -H 'Host: http.local' http://localhost:18080/obj/alpha?size=4096 -D -   # MISS then HIT
curl -H 'Host: s3.local'   http://localhost:18080/greeting.txt -D -          # S3 origin
docker compose -f test/integration/docker-compose.yml down -v
```

## What it asserts

| Test | Proves |
|---|---|
| `TestHTTPMissThenHit` | a plain-HTTP upstream object is fetched once then served from cache (`X-Cache: HIT`), byte-identical. |
| `TestRequestCoalescing` | many concurrent requests for one uncached key collapse into a **single** origin fetch (origin `/_stats` delta == 1). |
| `TestS3OriginAnonymous` | the S3 upstream fetches a MinIO object and caches it. Cadishfile S3 upstreams carry **no credentials**, so the bucket is public-read and the SDK fetches anonymously. |

## Stack ([`docker-compose.yml`](docker-compose.yml))

- **origin** — `test/origin` with `-latency 200ms` (makes coalescing observable);
  `/_stats` exposed on the host at `:19000`.
- **minio** + **minio-seed** — a public-read `media` bucket seeded with `greeting.txt`.
- **cadish** — the real image, config [`Cadishfile`](Cadishfile) (two sites: `http.local`
  → origin, `s3.local` → the bucket), published on the host at `:18080`. Runs as `0:0`
  (test-only) so a fresh cache volume's permissions never block startup.
