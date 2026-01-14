#ifndef __MEMLEAK_H_
#define __MEMLEAK_H_

#define MAX_STACK_DEPTH 127
#define MAX_MALLOC_ENTRIES 1024
#define MAX_ALLOC_ENTRIES 10240
#define MAX_STACK_TRACE_ENTRIES 10240

struct alloc_info {
	__u64 address;
	size_t size;
	__s32 stack_id;
};

#endif
