#define __TARGET_ARCH_arm64
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

struct event {
	pid_t pid;
	char filename[256];
	umode_t mode;
};

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(max_entries, 1024);
	__type(key, int);
	__type(value, int);
} mkdir SEC(".maps");

// need to create a dummy instane, otherwise the cargo-libbpf won't generate rust 
// definition for the struct event
struct event dummy = {0};

char LICENSE[] SEC("license") = "GPL";

SEC("kprobe/do_mkdirat")
int BPF_KPROBE(do_mkdirat, int dfd, struct filename *name, umode_t mode) {
	// above format: function name, follow by its argument
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	struct event ev = {};
	ev.pid = pid;
	ev.mode = mode;
	const char *filename = BPF_CORE_READ(name,name);
	bpf_probe_read_str(ev.filename, sizeof(ev.filename), filename);
	// ctx was defined in kernel header
	bpf_perf_event_output(ctx, &mkdir, BPF_F_CURRENT_CPU, &ev, sizeof(ev));
	return 0;
}
