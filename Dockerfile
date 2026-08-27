# syntax=docker/dockerfile:1.7

FROM golang:1.24-bookworm AS build

ARG GOPROXY=https://proxy.golang.org,direct
ENV GOPROXY=${GOPROXY}

RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt,sharing=locked \
    --mount=type=cache,target=/go/pkg/mod,sharing=locked \
    --mount=type=cache,target=/root/.cache/go-build,sharing=locked \
    apt-get update \
    && apt-get install -y --no-install-recommends clang llvm libbpf-dev linux-libc-dev \
    && GOPROXY=${GOPROXY} go install github.com/cilium/ebpf/cmd/bpf2go@v0.19.0

WORKDIR /src
COPY go.mod go.sum* ./
RUN --mount=type=cache,target=/go/pkg/mod,sharing=locked \
    --mount=type=cache,target=/root/.cache/go-build,sharing=locked \
    GOPROXY=${GOPROXY} go mod download
COPY . .
RUN --mount=type=cache,target=/go/pkg/mod,sharing=locked \
    --mount=type=cache,target=/root/.cache/go-build,sharing=locked \
    make generate && CGO_ENABLED=0 GOPROXY=${GOPROXY} go build -trimpath -o /out/netbpf-exporter ./cmd/netbpf-exporter

FROM build AS test
RUN go test ./...

FROM debian:bookworm-slim AS runtime
COPY --from=build /out/netbpf-exporter /usr/local/bin/netbpf-exporter
USER root
ENTRYPOINT ["/usr/local/bin/netbpf-exporter"]
