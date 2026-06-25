# Releasing cadish

Releases are built by [GoReleaser](https://goreleaser.com) and published by the
[`release` workflow](../.github/workflows/release.yml) on a version-tag push. The
config is [`.goreleaser.yaml`](../.goreleaser.yaml).

## Cutting a release

1. Land everything for the release on `main` and update
   [`CHANGELOG.md`](../CHANGELOG.md) with the new version's entry.
2. Tag and push:
   ```sh
   git tag v0.2.0
   git push origin v0.2.0
   ```
3. The `release` workflow runs `goreleaser release --clean`, which:
   - builds `cmd/cadish` for **linux** and **darwin**, **amd64** and **arm64**,
     with the version stamped into `internal/version.Version` (so
     `cadish version` reports `cadish v0.2.0 (…)`);
   - produces `.tar.gz` archives (each bundling `LICENSE`, `NOTICE`, `README.md`,
     `CHANGELOG.md`, `docs/`, `examples/`) and a `checksums.txt`;
   - generates release notes (Features / Fixes grouped from the commit log);
   - creates the **GitHub Release** with all artifacts attached.

   A separate `docker` job in the same workflow then builds and pushes a
   **multi-arch** (linux/amd64 + linux/arm64) container image to
   `ghcr.io/cadi-sh/cadish:0.2.0` (the tag's `v` prefix is stripped) and
   `:latest`.

Tags must be semver-ish (`vMAJOR.MINOR.PATCH`); a `-rc`/`-beta` suffix is
auto-marked as a prerelease.

## Test it locally first (no tag, no publish)

```sh
make snapshot      # = goreleaser release --snapshot --clean
ls dist/           # archives, checksums, binaries
```

`make snapshot` validates the binary pipeline (builds every target, archives,
checksums) into `dist/` without tagging or pushing anything. You can also just
lint the config:

```sh
goreleaser check
```

## Prerequisites

- **CI:** none beyond the defaults — the workflow uses the built-in
  `GITHUB_TOKEN` (with `contents: write` for the Release and `packages: write`
  for GHCR). No extra secrets.
- **Local:** install `goreleaser` (`brew install goreleaser` or see their docs)
  and Docker if you want the image built in a snapshot.

## The container image

The release image is built by the workflow's `docker` job **directly from
[`deploy/Dockerfile`](../deploy/Dockerfile)** (the same from-source multi-stage
build you'd use for a manual `docker build`) via `docker buildx`, for **both
linux/amd64 and linux/arm64**. The tag's version is passed as the `VERSION`
build-arg so the image's `cadish version` matches the release.

It is built outside goreleaser because goreleaser's `dockers` integration copies
a prebuilt binary into a context — it can't reuse a from-source Dockerfile. Build
the same image locally with:

```sh
docker build -f deploy/Dockerfile --build-arg VERSION=v0.2.0 -t cadish:dev .
```

## Version stamping

`internal/version.Version` defaults to `"dev"`; GoReleaser overrides it via
`-ldflags -X …version.Version={{ .Version }}`. Non-release `go build`/`make build`
keeps `"dev"` and falls back to the VCS revision embedded in the build info, so
`cadish version` is always meaningful.
