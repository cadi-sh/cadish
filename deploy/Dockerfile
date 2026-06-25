# Multi-stage build for cadish. Produces a small static image.
#
#   docker build -f deploy/Dockerfile -t cadish:dev .
#   docker run --rm -p 80:80 -p 443:443 -v $PWD/Cadishfile:/etc/cadish/Cadishfile cadish:dev
#
# cadish needs CAP_NET_BIND_SERVICE for :80/:443 (compose/k8s grant it) and a
# writable cert cache + disk cache volume in production.

# Base images pinned by digest (supply-chain: a tag is mutable, a digest is not).
# Keep the human tag in the comment so Dependabot can bump both together.
FROM golang:1.26.4@sha256:32c0e6e5c4f6707717051091b4d0b077464a679eaab563e11474efc5328e2aa5 AS build
WORKDIR /src
# Cache module downloads separately from the source for faster rebuilds.
COPY go.mod go.sum* ./
RUN go mod download
COPY . .
ARG VERSION=dev
ARG COMMIT=unknown
ARG DATE=unknown
RUN CGO_ENABLED=0 go build -trimpath \
      -ldflags "-s -w \
        -X github.com/cadi-sh/cadish/internal/version.Version=${VERSION} \
        -X github.com/cadi-sh/cadish/internal/version.Commit=${COMMIT} \
        -X github.com/cadi-sh/cadish/internal/version.Date=${DATE}" \
      -o /out/cadish ./cmd/cadish

# distroless static-debian12:nonroot, pinned by digest (see note above).
FROM gcr.io/distroless/static-debian12:nonroot@sha256:d093aa3e30dbadd3efe1310db061a14da60299baff8450a17fe0ccc514a16639
COPY --from=build /out/cadish /usr/bin/cadish
# Carry the Apache-2.0 LICENSE + NOTICE in the image (NOTICE is required by
# §4(d) for the bundled AWS SDK / smithy-go / yaml dependencies).
COPY --from=build /src/LICENSE /src/NOTICE /usr/share/doc/cadish/
# Cert cache and disk cache live on volumes in real deployments. The image runs as
# uid 65532 (nonroot), so a FRESH named volume — created root-owned — must be made
# writable by that uid or cadish can't create /var/cache/cadish/blobs:
#   docker run --rm -v <volume>:/data busybox chown -R 65532:65532 /data
# (Kubernetes: the chart/manifests set securityContext fsGroup: 65532.) See deploy/README.md.
VOLUME ["/var/lib/cadish", "/var/cache/cadish"]
EXPOSE 80 443
ENTRYPOINT ["/usr/bin/cadish"]
CMD ["run", "-config", "/etc/cadish/Cadishfile"]
