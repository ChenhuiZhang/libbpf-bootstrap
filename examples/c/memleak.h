#ifndef __MEMLEAK_H_
#define __MEMLEAK_H_

struct alloc_info {
	__u64 address;
	size_t size;
	int stack_id;
};

#endif
