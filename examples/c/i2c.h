/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2022 Meta Platforms, Inc. */
#ifndef __I2C_H_
#define __I2C_H_

#ifndef TASK_COMM_LEN
#define TASK_COMM_LEN 16
#endif

struct i2c_event {
	__u32 pid;
	char comm[TASK_COMM_LEN];
	__u16 idx;
	__u16 addr;
	__u16 len;
	__u64 ts;
};

#endif /* __I2C_H_ */
