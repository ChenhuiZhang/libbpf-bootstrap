// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "memdump.h"

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
	__type(key, u64); /* stack_id */
	__type(value, struct malloc_info);
	__uint(max_entries, 10240);
} allocs SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_STACK_TRACE);
	__type(key, u32); /* stack id */
	__uint(max_entries, 10240);
} stack_traces SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} events SEC(".maps");

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
	const pid_t pid = bpf_get_current_pid_tgid() >> 32;

	const u64 *size = bpf_map_lookup_elem(&malloc_sizes, &pid);
	if (!size) {
		return 0;
	}

	bpf_map_delete_elem(&malloc_sizes, &pid);

	if (address) {
		//const u64 addr = (u64)address;
		int stack_id = bpf_get_stackid(ctx, &stack_traces, USER_STACKID_FLAGS);

#if 0
		struct malloc_event *event;

		event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
		if (!event)
			return 1;
		//bpf_map_update_elem(&allocs, &addr, &info, BPF_ANY);
		event->pid = pid;
		event->stack_id = bpf_get_stackid(ctx, &stack_traces, USER_STACKID_FLAGS);

		if (bpf_get_current_comm(event->comm, sizeof(event->comm)))
			event->comm[0] = 0;

		event->ustack_sz = bpf_get_stack(ctx, event->ustack, sizeof(event->ustack), BPF_F_USER_STACK);

		//bpf_printk("malloc EXIT: address = %p with id: %u", address, event->stack_id);

		bpf_ringbuf_submit(event, 0);
#else
		struct malloc_info *info;

		info = bpf_map_lookup_elem(&allocs, &stack_id);
    if (info) {
      info->count++;
		  bpf_printk("malloc EXIT: stack_id = %d with count: %d", stack_id, info->count);
    } else {
			struct malloc_info new;
			new.pid = pid;
			new.stack_id = stack_id;

			if (bpf_get_current_comm(new.comm, sizeof(new.comm)))
				new.comm[0] = 0;

			//new.ustack_sz = bpf_get_stack(ctx, new.ustack, sizeof(new.ustack), BPF_F_USER_STACK);
      new.count = 1;

			bpf_map_update_elem(&allocs, &stack_id, &new, BPF_ANY);
    }

#endif
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

	bpf_printk("free ENTRY: address = %p", address);

  #if 0
	info = bpf_map_lookup_elem(&allocs, &addr);
	if (!info) {
		return 0;
	}

	bpf_map_delete_elem(&allocs, &addr);
  #endif

	return 0;
}