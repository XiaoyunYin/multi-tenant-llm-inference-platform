#!/bin/sh
# Cached cpu-ci-linux-head:0e76 (Go 1.26.6), read-only /src and /gomod;
# disposable /work and compiler cache. REDIS_TEST_ADDR must name local Redis.
set -eu
: "${REDIS_TEST_ADDR:?disposable real Redis is required}"
mkdir -p /work
tar -C /src -cf - go.mod go.sum cmd internal deploy/local python/tests/fixtures/inf037b_gateway_sse.json | tar -C /work -xf -
cd /work
export GOTOOLCHAIN=local GOMODCACHE=/gomod GOCACHE=/tmp/go-build GOPROXY=off GOSUMDB=off
go version
test -z "$(gofmt -l cmd internal)"
go vet ./...
go test -count=1 ./...
go test -race -count=1 -v ./internal/admission ./internal/gateway
