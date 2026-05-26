BPFTOOL := $(shell command -v bpftool 2>/dev/null || echo /usr/lib/linux-tools/$(shell uname -r)/bpftool)
CLANG   := clang
CC      := gcc

build/vmlinux.h:
	mkdir -p build
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@

build/syscall.bpf.o: bpf/syscall.bpf.c bpf/common.h build/vmlinux.h
	$(CLANG) -g -O2 -target bpf -D__TARGET_ARCH_x86 \
		-Ibuild -I/usr/include/x86_64-linux-gnu \
		-c $< -o $@

build/syscall.skel.h: build/syscall.bpf.o
	$(BPFTOOL) gen skeleton $< > $@

build/loader: src/loader/loader.c build/syscall.skel.h
	$(CC) -g -O2 -Ibuild $< -lbpf -lelf -lz -o $@

.PHONY: all clean

all: build/loader

clean:
	rm -rf build
