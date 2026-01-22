#define __TARGET_ARCH_arm64
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

SEC("kretprobe/do_mkdirat")
int BPF_KRETPROBE(do_mkdirat,int ret) 
{
	pid_t pid;
	pid = bpf_get_current_pid_tgid() >> 32;
	bpf_printk("KPROBE ENTRY pid = %d, return = %d \n",
	    	pid, ret);
	return 0;
}
