// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2020 Facebook */
#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include "memleak.skel.h"

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	return vfprintf(stderr, format, args);
}

int main(int argc, char **argv)
{
	struct memleak_bpf *skel;
	int err;
	LIBBPF_OPTS(bpf_uprobe_opts, uprobe_opts);
	char binary_path[128] = { 0 };

	strcpy(binary_path, "/usr/lib/libc.so.6");

	/* Set up libbpf errors and debug info callback */
	libbpf_set_print(libbpf_print_fn);

	/* Load and verify BPF application */
	skel = memleak_bpf__open_and_load();
	if (!skel) {
		fprintf(stderr, "Failed to open and load BPF skeleton\n");
		return 1;
	}

	/* Attach tracepoint handler */
	uprobe_opts.func_name = "malloc";
	uprobe_opts.retprobe = false;
	/* uprobe/uretprobe expects relative offset of the function to attach
	 * to. libbpf will automatically find the offset for us if we provide the
	 * function name. If the function name is not specified, libbpf will try
	 * to use the function offset instead.
	 */
	skel->links.malloc_enter = bpf_program__attach_uprobe_opts(skel->progs.malloc_enter,
								 -1 /* self pid */, binary_path,
								 0 /* offset for function */,
								 &uprobe_opts /* opts */);
	if (!skel->links.malloc_enter) {
		err = -errno;
		fprintf(stderr, "Failed to attach uprobe: %d\n", err);
		goto cleanup;
	}

	/* we can also attach uprobe/uretprobe to any existing or future
	 * processes that use the same binary executable; to do that we need
	 * to specify -1 as PID, as we do here
	 */
	uprobe_opts.func_name = "malloc";
	uprobe_opts.retprobe = true;
	skel->links.malloc_exit = bpf_program__attach_uprobe_opts(
		skel->progs.malloc_exit, -1 /* self pid */, binary_path,
		0 /* offset for function */, &uprobe_opts /* opts */);
	if (!skel->links.malloc_exit) {
		err = -errno;
		fprintf(stderr, "Failed to attach uprobe: %d\n", err);
		goto cleanup;
	}

	/* Let libbpf perform auto-attach for uprobe_sub/uretprobe_sub
	 * NOTICE: we provide path and symbol info in SEC for BPF programs
	 */
	err = memleak_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to auto-attach BPF skeleton: %d\n", err);
		goto cleanup;
	}

	printf("Successfully started! Please run `sudo cat /sys/kernel/debug/tracing/trace_pipe` "
	       "to see output of the BPF programs.\n");

	for (;;) {
		sleep(1);
	}

cleanup:
	memleak_bpf__destroy(skel);
	return -err;
}
