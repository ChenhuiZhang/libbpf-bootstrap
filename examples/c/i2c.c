/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#include <stdio.h>
#include <unistd.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include <getopt.h>
#include <time.h>
#include "i2c.skel.h"

#include "i2c.h"

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	return vfprintf(stderr, format, args);
}

static int foo(int argc, char **argv, struct bpf_map *map)
{
	pid_t pid = -1;
	int adpt = -1;
	int dev = -1;
	int c;
	char pid_key[16] = "pid";
	char adapter_key[16] = "adpt";
	char dev_key[16] = "dev";
	int err = 0;

	while ((c = getopt(argc, argv, "p:a:d:")) != -1) {
		switch (c)
		{
		case 'p':
			pid = atoi(optarg);
			err = bpf_map__update_elem(map,
						&pid_key, sizeof(pid_key),
						&pid, sizeof(pid_t), BPF_ANY);
			break;
		case 'a':
			adpt = atoi(optarg);
			err = bpf_map__update_elem(map,
						&adapter_key, sizeof(adapter_key),
						&adpt, sizeof(adpt), BPF_ANY);
			break;
		case 'd':
			dev = atoi(optarg);
			err = bpf_map__update_elem(map,
						&dev_key, sizeof(dev_key),
						&dev, sizeof(dev), BPF_ANY);
			break;
		}

		if (err < 0) {
			goto out;
		}
	}

	fprintf(stderr, "Start mointor on i2c-%d dev %02x for process: %d\n", adpt, dev, pid);

out:
	return err;
}

/* Receive events from the ring buffer. */
static int event_handler(void *_ctx, void *data, size_t size)
{
	struct i2c_event *event = data;

	printf("%llu %s(%d) %d-%04x len=%u\n", event->ts / 1000 / 1000 / 1000, event->comm, event->pid, event->idx, event->addr, event->len);

	return 0;
}

int main(int argc, char **argv)
{
	struct ring_buffer *ring_buf = NULL;
	struct i2c_bpf *skel;
	time_t endtime;
	int err;

	/* Set up libbpf errors and debug info callback */
	libbpf_set_print(libbpf_print_fn);

	/* Load and verify BPF application */
	skel = i2c_bpf__open_and_load();
	if (!skel) {
		fprintf(stderr, "Failed to open and load BPF skeleton\n");
		return 1;
	}

	/* Apply the filter from command line */
	err = foo(argc, argv, skel->maps.i2c_opt_map);
	if (err) {
		fprintf(stderr, "Error updating map: %s\n", strerror(err));
		goto cleanup;
	}

	/* Attach tracepoint handler */
	err = i2c_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto cleanup;
	}

	/* Prepare ring buffer to receive events from the BPF program. */
	ring_buf = ring_buffer__new(bpf_map__fd(skel->maps.events), event_handler, NULL, NULL);
	if (!ring_buf) {
		err = -1;
		goto cleanup;
	}

	endtime = time(NULL) + 3600;

	printf("Hermes Successfully started! Please run `sudo cat /sys/kernel/debug/tracing/trace_pipe` "
	       "to see output of the BPF programs.\n");

	while (1) {
		err = ring_buffer__poll(ring_buf, 100);
		if (err == -EINTR) {
			break;
		}
		if (err < 0) {
			fprintf(stderr, "Error polling ring buffer: %d\n", err);
			break;
		}
		if (time(NULL) > endtime) {
			break;
		}
	}

cleanup:
	ring_buffer__free(ring_buf);
	i2c_bpf__destroy(skel);
	return -err;
}
