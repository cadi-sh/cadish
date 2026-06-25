// Package integration holds the real-binary, Docker-based end-to-end harness
// (backlog #4 / task #34). The actual tests live in integration_test.go behind a
// `//go:build integration` tag, so the default `go test ./...` never starts Docker.
// This untagged file keeps the package non-empty (and thus loadable) when the tag is
// absent, so `go test ./test/integration` reports "no test files" rather than failing
// to build. See README.md to run the harness.
package integration
