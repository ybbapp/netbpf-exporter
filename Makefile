GO ?= go
DOCKER ?= docker
BPF2GO ?= bpf2go
GOPROXY ?= https://proxy.golang.org,direct

BIN_DIR ?= bin
BIN ?= $(BIN_DIR)/netbpf-exporter

.PHONY: all generate build test fmt docker-build docker-test clean

all: generate build

generate:
	cd internal/bpf && GOPACKAGE=bpf $(BPF2GO) -cc clang -cflags "-O2 -g -Wall -Werror" Bpf ../../bpf/peer.c -- -I/usr/include/$(shell uname -m)-linux-gnu

build: generate
	mkdir -p $(BIN_DIR)
	GOPROXY=$(GOPROXY) $(GO) build -trimpath -o $(BIN) ./cmd/netbpf-exporter

test:
	GOPROXY=$(GOPROXY) $(GO) test ./...

fmt:
	gofmt -w $$(find . -name '*.go' -type f -not -path './vendor/*')

docker-build:
	$(DOCKER) build --build-arg GOPROXY=$(GOPROXY) --target build -t netbpf-exporter:build .

docker-test:
	$(DOCKER) build --build-arg GOPROXY=$(GOPROXY) --target test -t netbpf-exporter:test .
	$(DOCKER) run --rm netbpf-exporter:test go test ./...

clean:
	rm -f $(BIN) internal/bpf/bpf_bpfel.go internal/bpf/bpf_bpfel.o internal/bpf/bpf_bpfeb.go internal/bpf/bpf_bpfeb.o
