/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

#include "i2c.h"

typedef unsigned int u32;
typedef int pid_t;
typedef char stringkey[16];

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4);
	stringkey* key;
	__type(value, u32);
} i2c_opt_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} events SEC(".maps");

SEC("tp/i2c/i2c_read")
int handle_tp(struct trace_event_raw_i2c_read *ctx)
{
	u32 index = 0;
	pid_t pid = bpf_get_current_pid_tgid() >> 32;

	stringkey pid_key = "pid";
	stringkey dev_key = "dev";
	stringkey adapter_key = "adpt";

	int *my_adapter = NULL;
	pid_t *my_pid = NULL;
	int *dev = NULL;
	
	
	struct i2c_event *event;

  int nr;
  ushort addr;
  ushort flags;
  ushort len;
  char comm[32];

	my_pid = bpf_map_lookup_elem(&i2c_opt_map, &pid_key);
	
	my_adapter = bpf_map_lookup_elem(&i2c_opt_map, &adapter_key);

	dev = bpf_map_lookup_elem(&i2c_opt_map, &dev_key);

	if (my_pid && *my_pid != pid)
		return 1;

  bpf_core_read(&nr, sizeof(nr), &ctx->adapter_nr);
  bpf_core_read(&addr, sizeof(addr), &ctx->addr);
  //bpf_core_read(&flags, sizeof(flags), &ctx->flags);
  bpf_core_read(&len, sizeof(len), &ctx->len);

  	if (my_adapter && *my_adapter != nr)
		return 1;

  	if (dev && *dev != addr)
		return 1;

	event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
	if (!event)
		return 1;

	event->pid = pid;
	if (bpf_get_current_comm(event->comm, sizeof(event->comm)))
		event->comm[0] = 0;
	event->idx = nr;
	event->addr = addr;
	event->len = len;
	event->ts = bpf_ktime_get_boot_ns();

	//bpf_printk("i2c read i2c-%d a=%x len=%u\n", nr, addr, len);

	bpf_ringbuf_submit(event, 0);

	return 0;
}
