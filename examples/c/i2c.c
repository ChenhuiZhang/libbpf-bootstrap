/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#include <stdio.h>
#include <unistd.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include <getopt.h>
#include <time.h>
#include <errno.h>
#include <stdlib.h>
#include "i2c.skel.h"

#include "i2c.h"

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	return vfprintf(stderr, format, args);
}

/* Helper function to parse integer with validation */
static int parse_int(const char *str, int *value, const char *name)
{
	char *endptr;
	long val;

	errno = 0;
	val = strtol(str, &endptr, 10);

	if (errno != 0 || *endptr != '\0') {
		fprintf(stderr, "Invalid %s: %s\n", name, str);
		return -EINVAL;
	}

	*value = (int)val;
	return 0;
}

static int apply_filter_options(int argc, char **argv, struct bpf_map *map, int *timeout)
{
	pid_t pid = -1;
	int adpt = -1;
	int dev = -1;
	int c;
	char pid_key[16] = "pid";
	char adapter_key[16] = "adpt";
	char dev_key[16] = "dev";
	int err = 0;

	while ((c = getopt(argc, argv, "p:a:d:i:")) != -1) {
		switch (c) {
		case 'p':
			if (parse_int(optarg, &pid, "PID") != 0 || pid <= 0)
				pid = -1; /* Parse failed or non-positive, monitor all */
			err = bpf_map__update_elem(map, &pid_key, sizeof(pid_key), &pid,
						   sizeof(pid_t), BPF_ANY);
			break;
		case 'a':
			if (parse_int(optarg, &adpt, "adapter number") != 0 || adpt <= 0)
				adpt = -1; /* Parse failed or non-positive, monitor all */
			err = bpf_map__update_elem(map, &adapter_key, sizeof(adapter_key), &adpt,
						   sizeof(adpt), BPF_ANY);
			break;
		case 'd':
			if (parse_int(optarg, &dev, "device address") != 0 || dev <= 0)
				dev = -1; /* Parse failed or non-positive, monitor all */
			err = bpf_map__update_elem(map, &dev_key, sizeof(dev_key), &dev,
						   sizeof(dev), BPF_ANY);
			break;
		case 'i':
			if (parse_int(optarg, timeout, "timeout") != 0 || *timeout <= 0) {
				fprintf(stderr, "Invalid timeout, using default: 3600s\n");
				*timeout = 3600;
			}
			break;
		}

		if (err < 0) {
			goto out;
		}
	}

	fprintf(stderr, "Start monitor on i2c-%d dev %02x for process: %d\n", adpt, dev, pid);

out:
	return err;
}

/* Receive events from the ring buffer. */
static int event_handler(void *_ctx, void *data, size_t size)
{
	struct i2c_event *event = data;

	printf("%llu %s(%d) %d-%04x len=%u\n", event->ts / 1000 / 1000 / 1000, event->comm,
	       event->pid, event->idx, event->addr, event->len);

	return 0;
}

int main(int argc, char **argv)
{
	struct ring_buffer *ring_buf = NULL;
	struct i2c_bpf *skel;
	time_t endtime;
	int timeout = 3600; /* Default timeout: 1 hour */
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
	err = apply_filter_options(argc, argv, skel->maps.i2c_opt_map, &timeout);
	if (err) {
		fprintf(stderr, "Error updating map: %s\n", strerror(-err));
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

	endtime = time(NULL) + timeout;

	printf("I2C monitor successfully started! Monitoring I2C events for %d seconds...\n",
	       timeout);

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
	return err < 0 ? -err : err;
}
