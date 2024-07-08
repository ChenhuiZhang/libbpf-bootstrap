// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2020 Facebook */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "memleak.h"

#define KERN_STACKID_FLAGS (0 | BPF_F_FAST_STACK_CMP)
#define USER_STACKID_FLAGS (0 | BPF_F_FAST_STACK_CMP | BPF_F_USER_STACK)

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, pid_t); // pid
	__type(value, u64); // size for alloc
	__uint(max_entries, 1024);
} malloc_sizes SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, u64); /* alloc return address */
	__type(value, struct alloc_info);
	__uint(max_entries, 10240);
} allocs SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_STACK_TRACE);
	__type(key, u32); /* stack id */
	__uint(max_entries, 10240);
} stack_traces SEC(".maps");

char LICENSE[] SEC("license") = "Dual BSD/GPL";

SEC("uprobe")
int BPF_KPROBE(malloc_enter, size_t size)
{
	const pid_t pid = bpf_get_current_pid_tgid() >> 32;

	bpf_map_update_elem(&malloc_sizes, &pid, &size, BPF_ANY);

	//bpf_printk("malloc ENTRY: size = %d", size);

	return 0;
}

SEC("uretprobe")
int BPF_KRETPROBE(malloc_exit, void *address)
{
	struct alloc_info info;
	const pid_t pid = bpf_get_current_pid_tgid() >> 32;

	const u64 *size = bpf_map_lookup_elem(&malloc_sizes, &pid);
	if (!size) {
		return 0;
	}

	bpf_map_delete_elem(&malloc_sizes, &pid);

	__builtin_memset(&info, 0, sizeof(info));
	info.size = *size;
	info.address = (u64)address;

	if (address) {
		const u64 addr = (u64)address;

		info.stack_id = bpf_get_stackid(ctx, &stack_traces, USER_STACKID_FLAGS);

		bpf_map_update_elem(&allocs, &addr, &info, BPF_ANY);

		bpf_printk("malloc EXIT: address = %p with id: %u", address, info.stack_id);
	}

	//bpf_printk("malloc EXIT: address = %p", ret);
	return 0;
}

SEC("uprobe")
int BPF_KPROBE(free_enter, void *address)
{
	const struct alloc_info *info;
	const pid_t pid = bpf_get_current_pid_tgid() >> 32;
	const u64 addr = (u64)address;

	//bpf_printk("free ENTRY: address = %p", address);

	info = bpf_map_lookup_elem(&allocs, &addr);
	if (!info) {
		return 0;
	}

	bpf_map_delete_elem(&allocs, &addr);

	return 0;
}
