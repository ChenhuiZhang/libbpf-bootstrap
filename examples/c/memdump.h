/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef __MEMDUMP_H_
#define __MEMDUMP_H_

#ifndef TASK_COMM_LEN
#define TASK_COMM_LEN 16
#endif

#ifndef MAX_STACK_DEPTH
#define MAX_STACK_DEPTH 128
#endif

typedef __u64 stack_trace_t[MAX_STACK_DEPTH];

struct malloc_event {
	__u32 pid;
	char comm[TASK_COMM_LEN];
	__s32 ustack_sz;
	stack_trace_t ustack;
};

struct malloc_info {
	__u32 pid;
	char comm[TASK_COMM_LEN];
	int stack_id;
	//__s32 ustack_sz;
	//stack_trace_t ustack;
  int count;
};

#endif /* __MEMDUMP_H_ */
