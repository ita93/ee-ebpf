#define __TARGET_ARCH_arm64
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

/*
SEC("kprobe/do_mkdirat")
int kprobe_mkdir(struct pt_regs *ctx)
{
    pid_t pid;
    const char *filename;
    umode_t mode;

    pid = bpf_get_current_pid_tgid() >> 32;
    struct filename *name = (struct filename *)PT_REGS_PARM2(ctx);
    filename = BPF_CORE_READ(name, name);
	mode = PT_REGS_PARM3(ctx);
   
    bpf_printk("KPROBE ENTRY pid = %d, filename = %s, mode = %u\n", pid, filename,mode);

    return 0;
}*/

// Using BPF_KPROBE helper macro
SEC("kprobe/do_mkdirat")
int BPF_KPROBE(capture_mkdir, int dfd, struct filename *name, umode_t mode)
{
        pid_t pid;
        const char *filename;
        pid = bpf_get_current_pid_tgid() >> 32;
        filename = BPF_CORE_READ(name, name);
        bpf_printk("KPROBE ENTRY pid = %d, filename = %s, mode = %u\n", pid, filename, mode);
        return 0;
}
