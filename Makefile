CURDIR := $(abspath .)
BPFDIR := $(CURDIR)/bpf

BPFTOOL ?= bpftool
CLANG ?= clang
GO ?= go
RM ?= rm

GOOS ?= linux
GOARCH ?= amd64
CGO_ENABLED ?= 0

VMLINUX_BTF ?= $(wildcard /sys/kernel/btf/vmlinux)
ifeq ($(VMLINUX_BTF),)
$(error Cannot find a vmlinux)
endif

GO_BUILD_ENV := CGO_ENABLED=$(CGO_ENABLED) GOOS=$(GOOS) GOARCH=$(GOARCH)
GO_LDFLAGS := -trimpath -buildvcs=false -ldflags='-s -w'

bin/agre: vmlinux build-bpf
	@mkdir -p bin
	@$(GO_BUILD_ENV) $(GO) build $(GO_LDFLAGS) -o $@ .

.PHONY: vmlinux
vmlinux: $(BPFDIR)/vmlinux.h

.PHONY: build-bpf
build-bpf:
	@$(GO_BUILD_ENV) $(GO) generate .

$(BPFDIR)/vmlinux.h:
	@$(BPFTOOL) btf dump file $(VMLINUX_BTF) format c > $@

.PHONY: clean
clean:
	-@$(RM) -f $(BPFDIR)/vmlinux.h
	-@$(RM) -f bin/*
	-@$(RM) -f ./*.o
	-@$(RM) -f ./bpf_x86_*.go
