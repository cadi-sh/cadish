# Contributing to cadish

cadish is an open-source single-binary HTTP cache server. Contributions are
welcome — especially real-world config migrations (VCL → Cadishfile) that stress
the language, and modules.

## Ground rules

- **Every change keeps the build green:** `go build ./...`, `go vet ./...`,
  `gofmt -s -l .` (must list nothing), and `go test ./... -race` must all pass.
  CI enforces this plus `govulncheck`.
- **Tests come with the code.** New behavior needs table-driven tests; parsing
  and matching code should add fuzz seeds where relevant.
- **Small, auditable dependencies.** A cache server's supply chain must stay
  tiny. Adding a dependency needs a clear justification in the PR description.
- **Document the why.** Explain the rationale for an architectural choice in the
  PR; document user-facing behavior in `docs/` and note user-visible changes in
  `CHANGELOG.md`.

## Layout

```
cmd/cadish/        the binary (thin; dispatches subcommands)
internal/cli        run/check/fmt/adapt/version subcommands
internal/cadishfile parser/formatter for the Cadishfile (semantics-free AST)
internal/check      `cadish check` complexity report
internal/pipeline   matcher + directive evaluation (pure); normalizer key tokens
internal/cache      two-tier RAM+NVMe cache (tier override, negative entries)
internal/origin     HTTP + S3 origins, composable `origin chain`
internal/cfsign     CloudFront canned-policy URL signing (the `sign` directive)
internal/lb         upstreams, health, sticky/sharded load balancing
internal/tlsacme    TLS termination + automatic ACME
internal/classify   UA → device class ({device} normalizer)
internal/geo        client IP → geo class ({geo} normalizer)
internal/vcladapt   VCL → Cadishfile converter (`cadish adapt`)
internal/config     Cadishfile → runtime sites
internal/server     the caching reverse-proxy handler (wires it all together)
docs/               user-facing documentation (grammar, reference, guides)
test/migration/     VCL→Cadishfile migration targets + golden behavior specs
test/origin/        a configurable test origin for end-to-end scenarios
test/e2e/           httptest end-to-end suite (storefront parity)
```

## Dev loop

```bash
make build && ./build/cadish version
make race            # go test ./... -race
make check           # vet + test
go run ./cmd/cadish check -config examples/s3-cdn.Cadishfile
```

## Commits & PRs

- Conventional, imperative commit subjects (`feat(cache): …`, `fix(server): …`).
- One logical change per PR; explain the user-visible effect.
- By contributing you agree your work is licensed under Apache-2.0 (see LICENSE).
