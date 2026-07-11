# syntax=docker/dockerfile:1.7

# --- base: shared module cache layer -----------------------------------
FROM golang:1.26-alpine AS base
WORKDIR /src
ENV CGO_ENABLED=0 GOFLAGS=-mod=mod
RUN apk add --no-cache git
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download

# --- test: go vet + go test, this is what `make test` runs -------------
FROM base AS test
COPY . .
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    go vet ./... && go test ./... -count=1

# --- build: static binary ------------------------------------------------
FROM base AS build
ARG VERSION=dev
COPY . .
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    go build -trimpath -ldflags "-s -w -X github.com/0xcyberghost/pwnlibc/internal/cli.Version=${VERSION}" \
    -o /out/pwnlibc ./cmd/pwnlibc

# --- runtime: slim final image -------------------------------------------
FROM alpine:3.22 AS runtime
# docker-cli is only exercised by `build`/`run`, which additionally require
# the build-src compose profile to mount the host's Docker socket in; its
# presence here is inert (and harmless) without that mount.
RUN apk add --no-cache ca-certificates patchelf xz zstd docker-cli \
    && addgroup -S pwnlibc && adduser -S -G pwnlibc pwnlibc \
    && mkdir -p /data/libs /data/workdir /home/pwnlibc/.cache/pwnlibc \
    && chown -R pwnlibc:pwnlibc /data /home/pwnlibc

COPY --from=build /out/pwnlibc /usr/local/bin/pwnlibc

USER pwnlibc
ENV HOME=/home/pwnlibc
WORKDIR /data/workdir
VOLUME ["/data/libs", "/home/pwnlibc/.cache/pwnlibc"]

ENTRYPOINT ["pwnlibc"]
CMD ["--help"]
