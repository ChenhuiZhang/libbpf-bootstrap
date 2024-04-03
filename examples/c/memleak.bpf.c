// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2020 Facebook */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

SEC("uprobe")
int BPF_KPROBE(malloc_enter, size_t size)
{
	bpf_printk("malloc ENTRY: size = %d", size);
	return 0;
}

SEC("uretprobe")
int BPF_KRETPROBE(malloc_exit, int ret)
{
	bpf_printk("malloc EXIT: return = %p", ret);
	return 0;
}
