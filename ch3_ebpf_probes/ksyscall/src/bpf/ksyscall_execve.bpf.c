#define __TARGET_ARCH_arm64
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define MAX_ARGS 7
#define ARG_SIZE 128

struct event {
    __u32 pid;
    char path[ARG_SIZE];
    char argv[MAX_ARGS][ARG_SIZE];
};

struct event dummy = {0};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 16);
}rb SEC(".maps");

char LICENSE[] SEC("license") = "GPL";

SEC("ksyscall/execve")
int BPF_KSYSCALL(kprobe_sys_execve,
                 const char *filename,
                 const char *const *argv) {
    struct event *ev  = bpf_ringbuf_reserve(&rb, sizeof(*ev), 0);
    if (!ev)
        return 0;

    ev->pid = bpf_get_current_pid_tgid() >> 32;
    bpf_probe_read_user_str(ev->path, sizeof(ev->path), filename);

    #pragma unroll
    for (int i = 0; i < MAX_ARGS; i++) {
        const char *argp = NULL;
        bpf_probe_read_user(&argp, sizeof(argp), &argv[i]);
        if (!argp){
            break;
        }
        bpf_probe_read_user_str(ev->argv[i], sizeof(ev->argv[i]), argp);
    }
    bpf_ringbuf_submit(ev, 0);
    return 0;
}
