// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2021 Sartura */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

SEC("kprobe/bq27xxx_battery_i2c_read")
int BPF_KPROBE(bq27xxx_i2c_read, void *di, u8 reg, bool single)
{
	bpf_printk("bq27xxx_i2c_read reg = 0x%02x, len = %u\n", reg, single ? 1 : 2);
	return 0;
}

SEC("kretprobe/bq27xxx_battery_i2c_read")
int BPF_KRETPROBE(bq27xxx_i2c_read_exit, long ret)
{
	bpf_printk("bq27xxx_i2c_read_exit ret = 0x%04X\n", ret);
	return 0;
}

#if 0
#Need kernel 6.0 to support on arm64
SEC("fexit/bq27xxx_battery_i2c_read")
int BPF_PROG(bq27xxx_i2c_read_exit, void *di, u8 reg, bool single, long ret)
{
	pid_t pid;
	const char *filename;

	pid = bpf_get_current_pid_tgid() >> 32;
	bpf_printk("bq27xxx_i2c_read reg = 0x%x, len = %u value = %x\n", reg, single ? 1 : 2, ret);
	return 0;
}
#endif

SEC("kprobe/bq27xxx_battery_i2c_write")
int BPF_KPROBE(bq27xxx_i2c_write, void *di, u8 reg, int value, bool single)
{
	bpf_printk("bq27xxx_i2c_write reg = 0x%02x (%x), len = %u\n", reg, value, single ? 2 : 3);
	return 0;
}
