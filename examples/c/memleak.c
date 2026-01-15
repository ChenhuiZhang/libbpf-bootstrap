// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2020 Facebook */
#include <assert.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <stdio.h>
#include <sys/resource.h>
#include <unistd.h>
#include "memleak.skel.h"

#include "blazesym.h"
#include "memleak.h"

// Structure to track stack trace statistics
struct stack_count {
  __s32 stack_id;
  int count;
  size_t total_bytes;
};

#define MAX_UNIQUE_STACKS 1024
static struct stack_count stack_stats[MAX_UNIQUE_STACKS];
static int unique_stack_count = 0;

static char *
find_libc_path(pid_t pid)
{
  char maps_path[64];
  char line[512];
  static char libc_path[256];
  FILE *fp;

  snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", pid);
  fp = fopen(maps_path, "r");
  if (!fp) {
    fprintf(stderr, "Warning: Failed to open %s (pid %d): %s, trying common paths\n", 
            maps_path, pid, strerror(errno));
    goto try_common_paths;
  }

  while (fgets(line, sizeof(line), fp)) {
    if (strstr(line, "/libc.so.") || strstr(line, "/libc-")) {
      // Extract path from line format: addr-addr perms offset dev:inode pathname
      char *path = strchr(line, '/');
      if (path) {
        char *newline = strchr(path, '\n');
        if (newline)
          *newline = '\0';
        // Verify it's actually libc, not just any library with "libc" in the name
        if (strstr(path, "/libc.so.") || strstr(path, "/libc-")) {
          snprintf(libc_path, sizeof(libc_path), "%s", path);
          fclose(fp);
          fprintf(stderr, "Found libc at: %s\n", libc_path);
          return libc_path;
        }
      }
    }
  }
  fclose(fp);

try_common_paths:
  // Fallback to common paths
  const char *common_paths[] = {
    "/lib/x86_64-linux-gnu/libc.so.6",
    "/usr/lib/libc.so.6",
    "/lib64/libc.so.6",
    "/usr/lib/x86_64-linux-gnu/libc.so.6",
    NULL
  };

  for (int i = 0; common_paths[i]; i++) {
    if (access(common_paths[i], F_OK) == 0) {
      snprintf(libc_path, sizeof(libc_path), "%s", common_paths[i]);
      fprintf(stderr, "Using common path: %s\n", libc_path);
      return libc_path;
    }
  }

  fprintf(stderr, "Error: Failed to find libc.so.6 in /proc/%d/maps or common paths\n", pid);
  return NULL;
}

static int attach_pid = -1;
static int interval = 10;
static char binary_path[128] = { 0 };

static __u64 *g_stacks = NULL;
static size_t g_stacks_size = 0;

static struct blaze_symbolizer *symbolizer;

#define __ATTACH_UPROBE(skel, sym_name, prog_name, is_retprobe) \
  do {                                                          \
    LIBBPF_OPTS(bpf_uprobe_opts,                                \
                uprobe_opts,                                    \
                .func_name = #sym_name,                         \
                .retprobe = is_retprobe);                       \
    skel->links.prog_name =                                     \
      bpf_program__attach_uprobe_opts(skel->progs.prog_name,    \
                                      attach_pid,               \
                                      binary_path,              \
                                      0,                        \
                                      &uprobe_opts);            \
  } while (0)

#define __CHECK_PROGRAM(skel, prog_name)             \
  do {                                               \
    if (!skel->links.prog_name) {                    \
      perror("no program attached for " #prog_name); \
      return -errno;                                 \
    }                                                \
  } while (0)

#define __ATTACH_UPROBE_CHECKED(skel, sym_name, prog_name, is_retprobe) \
  do {                                                                  \
    __ATTACH_UPROBE(skel, sym_name, prog_name, is_retprobe);            \
    __CHECK_PROGRAM(skel, prog_name);                                   \
  } while (0)

/* ATTACH_UPROBE_CHECKED 和 ATTACH_UPROBE 宏的区别是:
 * ATTACH_UPROBE_CHECKED 会检查elf文件中(比如 libc.so)中是否存在 uprobe attach
 * 的符号(比如malloc) 如果不存在，返回错误； ATTACH_UPROBE
 * 发现符号不存在时不会返回错误，直接跳过这个符号的uprobe attach,继续往下执行；
 */
#define ATTACH_UPROBE(skel, sym_name, prog_name) \
  __ATTACH_UPROBE(skel, sym_name, prog_name, false)
#define ATTACH_URETPROBE(skel, sym_name, prog_name) \
  __ATTACH_UPROBE(skel, sym_name, prog_name, true)

#define ATTACH_UPROBE_CHECKED(skel, sym_name, prog_name) \
  __ATTACH_UPROBE_CHECKED(skel, sym_name, prog_name, false)
#define ATTACH_URETPROBE_CHECKED(skel, sym_name, prog_name) \
  __ATTACH_UPROBE_CHECKED(skel, sym_name, prog_name, true)

static int
libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
  return vfprintf(stderr, format, args);
}

static int
attach_uprobe(struct memleak_bpf *skel)
{
  ATTACH_UPROBE_CHECKED(skel, malloc, malloc_enter);
  ATTACH_URETPROBE_CHECKED(skel, malloc, malloc_exit);

  ATTACH_UPROBE_CHECKED(skel, free, free_enter);

  return 0;
}

static void
print_frame(const char *name,
            uintptr_t input_addr,
            uintptr_t addr,
            uint64_t offset,
            const blaze_symbolize_code_info *code_info)
{
  // If we have an input address  we have a new symbol.
  if (input_addr != 0) {
    printf("%016lx: %s @ 0x%lx+0x%lx", input_addr, name, addr, offset);
    if (code_info != NULL && code_info->dir != NULL &&
        code_info->file != NULL) {
      printf(" %s/%s:%u\n", code_info->dir, code_info->file, code_info->line);
    } else if (code_info != NULL && code_info->file != NULL) {
      printf(" %s:%u\n", code_info->file, code_info->line);
    } else {
      printf("\n");
    }
  } else {
    printf("%16s  %s", "", name);
    if (code_info != NULL && code_info->dir != NULL &&
        code_info->file != NULL) {
      printf("@ %s/%s:%u [inlined]\n",
             code_info->dir,
             code_info->file,
             code_info->line);
    } else if (code_info != NULL && code_info->file != NULL) {
      printf("@ %s:%u [inlined]\n", code_info->file, code_info->line);
    } else {
      printf("[inlined]\n");
    }
  }
}

static void
show_stack_trace(__u64 *stack, int stack_sz, pid_t pid)
{
  const struct blaze_symbolize_inlined_fn *inlined;
  const struct blaze_syms *syms;
  const struct blaze_sym *sym;
  int i, j;

  assert(sizeof(uintptr_t) == sizeof(uint64_t));

  if (pid) {
    struct blaze_symbolize_src_process src = {
      .type_size = sizeof(src),
      .pid = pid,
    };
    syms = blaze_symbolize_process_abs_addrs(symbolizer,
                                                &src,
                                                (const uintptr_t *) stack,
                                                stack_sz);
  } else {
    struct blaze_symbolize_src_kernel src = {
      .type_size = sizeof(src),
    };
    syms = blaze_symbolize_kernel_abs_addrs(symbolizer,
                                               &src,
                                               (const uintptr_t *) stack,
                                               stack_sz);
  }

  for (i = 0; i < stack_sz; i++) {
    if (!syms || syms->cnt <= i || syms->syms[i].name == NULL) {
      printf("%016llx: <no-symbol>\n", stack[i]);
      continue;
    }

    sym = &syms->syms[i];
    print_frame(sym->name, stack[i], sym->addr, sym->offset, &sym->code_info);

    for (j = 0; j < sym->inlined_cnt; j++) {
      inlined = &sym->inlined[j];
      print_frame(inlined->name, 0, 0, 0, &inlined->code_info);
    }
  }

  blaze_syms_free(syms);
}

static void
update_stack_stats(__s32 stack_id, size_t size)
{
  // Find existing entry or create new one
  for (int i = 0; i < unique_stack_count; i++) {
    if (stack_stats[i].stack_id == stack_id) {
      stack_stats[i].count++;
      stack_stats[i].total_bytes += size;
      return;
    }
  }

  // Add new entry
  if (unique_stack_count < MAX_UNIQUE_STACKS) {
    stack_stats[unique_stack_count].stack_id = stack_id;
    stack_stats[unique_stack_count].count = 1;
    stack_stats[unique_stack_count].total_bytes = size;
    unique_stack_count++;
  }
}

static int
compare_stack_counts(const void *a, const void *b)
{
  const struct stack_count *sa = (const struct stack_count *)a;
  const struct stack_count *sb = (const struct stack_count *)b;
  // Sort by total bytes (descending)
  if (sb->total_bytes > sa->total_bytes) return 1;
  if (sb->total_bytes < sa->total_bytes) return -1;
  return 0;
}

static void
print_stack_summary(struct bpf_map *m2)
{
  if (unique_stack_count == 0) {
    fprintf(stderr, "\n=== No leaks detected ===\n");
    return;
  }

  // Sort by total bytes
  qsort(stack_stats, unique_stack_count, sizeof(struct stack_count), compare_stack_counts);

  fprintf(stderr, "\n=== Leak Summary (by stack trace) ===\n");
  fprintf(stderr, "Total unique stack traces: %d\n", unique_stack_count);

  // Count and filter stacks with count <= 1
  int suppressed_count = 0;
  int displayed_count = 0;
  for (int i = 0; i < unique_stack_count; i++) {
    if (stack_stats[i].count <= 1) {
      suppressed_count++;
    } else {
      displayed_count++;
    }
  }

  if (suppressed_count > 0) {
    fprintf(stderr, "Suppressed %d stack trace(s) with single allocation (count <= 1)\n", suppressed_count);
  }
  fprintf(stderr, "\n");

  for (int i = 0; i < unique_stack_count; i++) {
    // Skip stacks with count <= 1
    if (stack_stats[i].count <= 1) {
      continue;
    }

    fprintf(stderr, "[%d] Stack ID: %d, Count: %d allocations, Total: %zu bytes\n",
            i + 1, stack_stats[i].stack_id, stack_stats[i].count, stack_stats[i].total_bytes);

    // Print the stack trace for this ID
    if (stack_stats[i].stack_id >= 0) {
      memset(g_stacks, 0, g_stacks_size);
      if (bpf_map__lookup_elem(m2,
                               &stack_stats[i].stack_id,
                               sizeof(stack_stats[i].stack_id),
                               g_stacks,
                               g_stacks_size,
                               0) == 0) {
        int stack_size = 0;
        for (int j = 0; j < MAX_STACK_DEPTH; j++) {
          if (0 == g_stacks[j]) break;
          stack_size++;
        }
        show_stack_trace(g_stacks, stack_size, attach_pid);
      }
    }
    fprintf(stderr, "\n");
  }

  if (displayed_count == 0) {
    fprintf(stderr, "No stack traces with multiple allocations to display.\n");
  }
  fprintf(stderr, "=== End of Summary ===\n\n");
}

static void
walk_hash_elements(struct bpf_map *map, struct bpf_map *m2)
{
  // const size_t stack_traces_key_size = bpf_map__key_size(m2);
  __u64 *cur_key = NULL;
  __u64 next_key;
  struct alloc_info info;
  int err;

  // Reset statistics for this iteration
  unique_stack_count = 0;
  memset(stack_stats, 0, sizeof(stack_stats));

  for (;;) {
    err = bpf_map__get_next_key(map, cur_key, &next_key, sizeof(next_key));
    if (err)
      break;

    err = bpf_map__lookup_elem(map,
                               &next_key,
                               sizeof(next_key),
                               &info,
                               sizeof(info),
                               0);

    // Use key and value here
    fprintf(stderr,
            "Leak address: %p, size: %lu; id: %d\n",
            (void *) info.address,
            info.size,
            info.stack_id);

    if (info.stack_id < 0) {
      cur_key = &next_key;
      continue;
    }

    // Update statistics
    update_stack_stats(info.stack_id, info.size);

    // Clear stack buffer before lookup to avoid stale data
    memset(g_stacks, 0, g_stacks_size);

    // stack_id is s32 but map key is u32; same size, cast for clarity
    if (bpf_map__lookup_elem(m2,
                             &info.stack_id,
                             sizeof(info.stack_id),
                             g_stacks,
                             g_stacks_size,
                             0)) {
      fprintf(stderr, "Error: Failed to lookup stack trace for id %d (address: %p, size: %lu): %s\n",
              info.stack_id, (void *)info.address, info.size, strerror(errno));
      cur_key = &next_key;
      continue;
    }

    int stack_size = 0;
    for (int i = 0; i < MAX_STACK_DEPTH; i++) {
      if (0 == g_stacks[i]) {
        break;
      }

      stack_size++;
      // printf("[%3d] 0x%llx\n", i, g_stacks[i]);
    }
    show_stack_trace(g_stacks, stack_size, attach_pid);

    cur_key = &next_key;
  }

  // Print summary of stack traces
  print_stack_summary(m2);
}

static void
parse_input(int argc, char **argv)
{
  int c;

  while ((c = getopt(argc, argv, "p:i:")) != -1) {
    switch (c) {
    case 'p':
      attach_pid = atoi(optarg);
      break;
    case 'i':
      interval = atoi(optarg);
      break;
    }
  }

  fprintf(stderr,
          "Start memleak check on: %d with interval: %d\n",
          attach_pid,
          interval);
}

int
main(int argc, char **argv)
{
  struct memleak_bpf *skel;
  int err;

  parse_input(argc, argv);

  /* Set up libbpf errors and debug info callback */
  libbpf_set_print(libbpf_print_fn);

  /* Load and verify BPF application */
  skel = memleak_bpf__open();
  if (!skel) {
    fprintf(stderr, "Failed to open BPF skeleton\n");
    return 1;
  }

  bpf_map__set_value_size(skel->maps.stack_traces, MAX_STACK_DEPTH * sizeof(__u64));

  err = memleak_bpf__load(skel);
  if (err) {
    fprintf(stderr, "Error: Failed to load and verify BPF skeleton: %d\n", err);
    goto cleanup;
  }

  symbolizer = blaze_symbolizer_new();
  if (!symbolizer) {
    fprintf(stderr, "Error: Failed to create blazesym symbolizer\n");
    err = -1;
    goto cleanup;
  }

  // Use pid 1 (init) for finding libc if monitoring all processes
  pid_t search_pid = (attach_pid == -1) ? 1 : attach_pid;
  char *libc_path = find_libc_path(search_pid);
  if (!libc_path) {
    fprintf(stderr, "Error: Failed to find libc path for pid %d\n", search_pid);
    err = -1;
    goto cleanup;
  }
  snprintf(binary_path, sizeof(binary_path), "%s", libc_path);

  /* Attach tracepoint handler */
  err = attach_uprobe(skel);
  if (err < 0) {
    fprintf(stderr, "Error: Failed to attach uprobe to %s (pid: %d): %d\n", 
            binary_path, attach_pid, err);
    goto cleanup;
  }

  /* Let libbpf perform auto-attach for uprobe_sub/uretprobe_sub
   * NOTICE: we provide path and symbol info in SEC for BPF programs
   */
  err = memleak_bpf__attach(skel);
  if (err) {
    fprintf(stderr, "Error: Failed to auto-attach BPF skeleton: %d\n", err);
    goto cleanup;
  }

  printf("Successfully started! Please run `sudo cat "
         "/sys/kernel/debug/tracing/trace_pipe` "
         "to see output of the BPF programs.\n");

  g_stacks_size = MAX_STACK_DEPTH * sizeof(*g_stacks);
  g_stacks = (__u64 *) malloc(g_stacks_size);
  if (!g_stacks) {
    fprintf(stderr, "Error: Failed to allocate %zu bytes for stack traces buffer\n", g_stacks_size);
    err = -ENOMEM;
    goto cleanup;
  }

  for (;;) {
    sleep(interval);
    walk_hash_elements(skel->maps.allocs, skel->maps.stack_traces);
    fprintf(stderr, "------------------------------- Done -------------------------------------\n");
  }

cleanup:
  if (g_stacks) {
    free(g_stacks);
  }
  blaze_symbolizer_free(symbolizer);
  memleak_bpf__destroy(skel);
  return -err;
}
