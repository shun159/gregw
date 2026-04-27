package main

//go:generate go tool bpf2go -tags linux bpf bpf/datapath.bpf.c -- -Wno-compare-distinct-pointer-types -Wno-int-conversion -Wnull-character -g -c -O2 -D__KERNEL__
