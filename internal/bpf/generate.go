package bpf

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -Werror" Bpf ../../bpf/peer.c -- -I/usr/include/$(uname -m)-linux-gnu
