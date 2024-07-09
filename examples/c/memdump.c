// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2020 Facebook */
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <time.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include "memdump.skel.h"

#include "memdump.h"
#include "blazesym.h"

static int attach_pid = -1;
static int duration = 3600;
static char binary_path[128] = {0};

static __u64 * g_stacks = NULL;
static size_t g_stacks_size = 0;

static struct blaze_symbolizer *symbolizer;

#define __ATTACH_UPROBE(skel, sym_name, prog_name, is_retprobe) \
    do { \
        LIBBPF_OPTS(bpf_uprobe_opts, uprobe_opts, \
                .func_name = #sym_name, \
                .retprobe = is_retprobe); \
        skel->links.prog_name = bpf_program__attach_uprobe_opts( \
                skel->progs.prog_name, \
                attach_pid, \
                binary_path, \
                0, \
                &uprobe_opts); \
    } while (0)

#define __CHECK_PROGRAM(skel, prog_name) \
    do { \
        if (!skel->links.prog_name) { \
            perror("no program attached for " #prog_name); \
            return -errno; \
        } \
    } while (0)

#define __ATTACH_UPROBE_CHECKED(skel, sym_name, prog_name, is_retprobe) \
    do { \
        __ATTACH_UPROBE(skel, sym_name, prog_name, is_retprobe); \
        __CHECK_PROGRAM(skel, prog_name); \
    } while (0)

/* ATTACH_UPROBE_CHECKED 和 ATTACH_UPROBE 宏的区别是:
 * ATTACH_UPROBE_CHECKED 会检查elf文件中(比如 libc.so)中是否存在 uprobe attach 的符号(比如malloc)
 * 如果不存在，返回错误；
 * ATTACH_UPROBE 发现符号不存在时不会返回错误，直接跳过这个符号的uprobe attach,继续往下执行；
 */
#define ATTACH_UPROBE(skel, sym_name, prog_name) __ATTACH_UPROBE(skel, sym_name, prog_name, false)
#define ATTACH_URETPROBE(skel, sym_name, prog_name) __ATTACH_UPROBE(skel, sym_name, prog_name, true)

#define ATTACH_UPROBE_CHECKED(skel, sym_name, prog_name) __ATTACH_UPROBE_CHECKED(skel, sym_name, prog_name, false)
#define ATTACH_URETPROBE_CHECKED(skel, sym_name, prog_name) __ATTACH_UPROBE_CHECKED(skel, sym_name, prog_name, true)

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	return vfprintf(stderr, format, args);
}

static int attach_uprobe(struct memdump_bpf *skel)
{
	ATTACH_UPROBE_CHECKED(skel, malloc, malloc_enter);
	ATTACH_URETPROBE_CHECKED(skel, malloc, malloc_exit);

	ATTACH_UPROBE_CHECKED(skel, free, free_enter);

	return 0;
}

static void print_frame(const char *name, uintptr_t input_addr, uintptr_t addr, uint64_t offset, const blaze_symbolize_code_info* code_info)
{
    // If we have an input address  we have a new symbol.
    if (input_addr != 0) {
      printf("%016lx: %s @ 0x%lx+0x%lx", input_addr, name, addr, offset);
			if (code_info != NULL && code_info->dir != NULL && code_info->file != NULL) {
				printf(" %s/%s:%u\n", code_info->dir, code_info->file, code_info->line);
      } else if (code_info != NULL && code_info->file != NULL) {
				printf(" %s:%u\n", code_info->file, code_info->line);
      } else {
				printf("\n");
      }
    } else {
      printf("%16s  %s", "", name);
			if (code_info != NULL && code_info->dir != NULL && code_info->file != NULL) {
				printf("@ %s/%s:%u [inlined]\n", code_info->dir, code_info->file, code_info->line);
      } else if (code_info != NULL && code_info->file != NULL) {
				printf("@ %s:%u [inlined]\n", code_info->file, code_info->line);
      } else {
				printf("[inlined]\n");
      }
    }
}

static void show_stack_trace(__u64 *stack, int stack_sz, pid_t pid)
{
	const struct blaze_symbolize_inlined_fn* inlined;
	const struct blaze_result *result;
	const struct blaze_sym *sym;
	int i, j;

	assert(sizeof(uintptr_t) == sizeof(uint64_t));

	if (pid) {
		struct blaze_symbolize_src_process src = {
			.pid = pid,
		};
		result = blaze_symbolize_process_virt_addrs(symbolizer, &src, (const uintptr_t *)stack, stack_sz);
	} else {
		struct blaze_symbolize_src_kernel src = {};
		result = blaze_symbolize_kernel_virt_addrs(symbolizer, &src, (const uintptr_t *)stack, stack_sz);
	}


	for (i = 0; i < stack_sz; i++) {
		if (!result || result->cnt <= i || result->syms[i].name == NULL) {
			printf("%016llx: <no-symbol>\n", stack[i]);
			continue;
		}

		sym = &result->syms[i];
		print_frame(sym->name, stack[i], sym->addr, sym->offset, &sym->code_info);

		for (j = 0; j < sym->inlined_cnt; j++) {
			inlined = &sym->inlined[j];
			print_frame(sym->name, 0, 0, 0, &inlined->code_info);
		}
	}

	blaze_result_free(result);
}

static void walk_hash_elements(struct bpf_map *map, struct bpf_map *m2)
{
	//const size_t stack_traces_key_size = bpf_map__key_size(m2);
  __u64 *cur_key = NULL;
  __u64 next_key;
  struct malloc_info info;
  int err;

  for (;;) {
  	err = bpf_map__get_next_key(map, cur_key, &next_key, sizeof(next_key));
    if (err)
    	break;

    err = bpf_map__lookup_elem(map, &next_key, sizeof(next_key), &info, sizeof(info), 0);

    // Use key and value here
		fprintf(stderr, "Malloc profile id: %d with count %d\n", info.stack_id, info.count);

		if (bpf_map__lookup_elem(m2,
                        &info.stack_id, 4, g_stacks, g_stacks_size, 0)) {
                        perror("failed to lookup stack traces!");
                        return;
                }

		int stack_size = 0;
		for (int i = 0; i < 127; i++) {
    	if (0 == g_stacks[i]) {
      	break;
      }

			stack_size++;
                        //printf("[%3d] 0x%llx\n", i, g_stacks[i]);
    }
		show_stack_trace(g_stacks, stack_size, attach_pid);

    cur_key = &next_key;
  }
}

static void parse_input(int argc, char **argv)
{
	int c;

	while ((c = getopt(argc, argv, "p:d:")) != -1) {
		switch (c)
		{
		case 'p':
			attach_pid = atoi(optarg);
			break;
		case 'd':
			duration = atoi(optarg);
			break;
		}
	}

	fprintf(stderr, "Start memprofile check on: %d with duration: %d\n", attach_pid, duration);
}

#if 0
/* Receive events from the ring buffer. */
static int event_handler(void *ctx, void *data, size_t size)
{
	struct malloc_event *event = data;

  printf("%d, size: %d\n", event->pid, event->ustack_sz);

	if (event->ustack_sz <= 0)
		return 1;

	printf("COMM: %s (pid=%d)\n", event->comm, event->pid);

	if (event->ustack_sz > 0) {
		printf("Userspace:\n");
		show_stack_trace(event->ustack, event->ustack_sz / sizeof(__u64), event->pid);
	} else {
		printf("No Userspace Stack\n");
	}

	return 0;
}
#endif

int main(int argc, char **argv)
{
	struct memdump_bpf *skel;
	int err;

	parse_input(argc, argv);

	/* Set up libbpf errors and debug info callback */
	libbpf_set_print(libbpf_print_fn);

	/* Load and verify BPF application */
	skel = memdump_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open BPF skeleton\n");
		return 1;
	}

	bpf_map__set_value_size(skel->maps.stack_traces, 127 * sizeof(__u64));

	err = memdump_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load BPF skeleton\n");
		goto cleanup;
	}

	symbolizer = blaze_symbolizer_new();
	if (!symbolizer) {
		fprintf(stderr, "Fail to create a symbolizer\n");
		err = -1;
		goto cleanup;
	}

	strcpy(binary_path, "/usr/lib/libc.so.6");

	/* Attach tracepoint handler */
	err = attach_uprobe(skel);
	if (err < 0) {
		fprintf(stderr, "Failed to attach uprobe: %d\n", err);
		goto cleanup;
	}

	/* Let libbpf perform auto-attach for uprobe_sub/uretprobe_sub
	 * NOTICE: we provide path and symbol info in SEC for BPF programs
	 */
	err = memdump_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to auto-attach BPF skeleton: %d\n", err);
		goto cleanup;
	}

#if 0
	/* Prepare ring buffer to receive events from the BPF program. */
	ring_buf = ring_buffer__new(bpf_map__fd(skel->maps.events), event_handler, NULL, NULL);
	if (!ring_buf) {
		err = -1;
		goto cleanup;
	}

	endtime = time(NULL) + duration;
#endif

	printf("Successfully started! Please run `sudo cat /sys/kernel/debug/tracing/trace_pipe` "
	       "to see output of the BPF programs.\n");

	g_stacks_size = 127 * sizeof(*g_stacks);
	g_stacks = (__u64 *)malloc(g_stacks_size);
	memset(g_stacks, 0, g_stacks_size);

	sleep(duration);
	walk_hash_elements(skel->maps.allocs, skel->maps.stack_traces);

cleanup:
	blaze_symbolizer_free(symbolizer);
	memdump_bpf__destroy(skel);
	return -err;
}
