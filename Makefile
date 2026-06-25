.PHONY: build test check race fmt vet clean install tidy cover release snapshot

BIN := build/cadish
PKG := ./...
LDFLAGS :=

build:
	@mkdir -p $(dir $(BIN))
	go build -ldflags "$(LDFLAGS)" -o $(BIN) ./cmd/cadish

install:
	go install ./cmd/cadish

test:
	go test $(PKG)

race:
	go test -race $(PKG)

cover:
	go test -coverprofile=coverage.out $(PKG)
	go tool cover -func=coverage.out | tail -1

vet:
	go vet $(PKG)

check: vet test

fmt:
	gofmt -s -w .

tidy:
	go mod tidy

clean:
	rm -f coverage.out
	rm -rf build/ dist/

# Build a local release into dist/ without tagging or publishing (smoke-test the
# goreleaser config). Requires goreleaser (https://goreleaser.com).
snapshot:
	goreleaser release --snapshot --clean

# Publish a real release. Normally run by the release workflow on a tag push;
# locally it needs a tag checked out + GITHUB_TOKEN. Prefer: git tag vX.Y.Z && git push --tags
release:
	goreleaser release --clean
