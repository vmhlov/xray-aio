.PHONY: build test lint vet fmt clean integration

BIN ?= bin/xray-aio
PKG := github.com/vmhlov/xray-aio
GOFLAGS := -trimpath
LDFLAGS := -s -w \
	-X $(PKG)/internal/version.Version=$(shell git describe --tags --always --dirty 2>/dev/null || echo dev) \
	-X $(PKG)/internal/version.Commit=$(shell git rev-parse --short HEAD 2>/dev/null || echo unknown) \
	-X $(PKG)/internal/version.Date=$(shell date -u +%Y-%m-%dT%H:%M:%SZ)

build:
	mkdir -p bin
	go build $(GOFLAGS) -ldflags '$(LDFLAGS)' -o $(BIN) ./cmd/xray-aio

test:
	go test ./... -race -count=1

vet:
	go vet ./...

fmt:
	gofmt -s -w .

lint:
	golangci-lint run ./...

clean:
	rm -rf bin dist

# Boots a privileged debian:12 container with systemd as PID 1 and
# runs the full home-stealth install + probe checklist. Requires
# Docker on the host. ~30s end-to-end.
integration:
	bash test/integration/run.sh

ci: vet test build
