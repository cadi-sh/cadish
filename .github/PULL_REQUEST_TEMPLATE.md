<!--
Thanks for contributing to cadish! Please read CONTRIBUTING.md first.
Keep PRs small and auditable — a cache server's supply chain and behavior must
stay easy to review.
-->

## What & why

<!-- What does this change, and what problem does it solve? Link any issue. -->

Closes #

## Type of change

- [ ] Bug fix
- [ ] New feature (directive / matcher / capability)
- [ ] Performance
- [ ] Docs / examples only
- [ ] Refactor / internal

## Checklist

- [ ] One logical change (split unrelated changes into separate PRs).
- [ ] `go build ./...`, `go vet ./...`, `gofmt -s -l .` (clean), and
      `go test ./... -race` all pass.
- [ ] New behavior has table-driven tests (and fuzz seeds for parsing/matching).
- [ ] Any new/changed directive is documented in `docs/cadishfile-reference.md`
      (and the cookbook if it warrants a recipe).
- [ ] If a Cadishfile directive changed, an example still passes `cadish check`.
- [ ] No new dependency, or it's justified in the PR description.
- [ ] `CHANGELOG.md` updated for user-visible changes; notable design choices
      explained in the PR description.

## Notes for reviewers

<!-- Anything non-obvious: tradeoffs, follow-ups, things you're unsure about. -->
