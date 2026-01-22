#define __TARGET_ARCH_arm64
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

struct event {
	pid_t pid;
	char command[32];
};

struct event dummy = {0};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 4096);
} events SEC(".maps");

char LICENSE[] SEC("license") = "GPL";

SEC("uprobe//bin/bash:shell_execve")
int BPF_UPROBE(uprobe_bash_shell_execve, const char *filename)
{
	struct event *evt;
	evt = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
	if (!evt) return 0;

	evt->pid = bpf_get_current_pid_tgid() >> 32;
	bpf_probe_read_user_str(evt->command, sizeof(evt->command),filename);
	bpf_ringbuf_submit(evt, 0);

	return 0;
}
