// SPDX-License-Identifier: GPL-2.0
// Kernel Security Monitor BPF-LSM — process exec denial via bprm_check_security hook
// Control plane writes target PIDs to deny_map; LSM returns -EPERM for those PIDs.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define EPERM 1

// Map of PIDs to deny — control plane writes here
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, __u32);
    __type(value, __u8);  // 1 = deny
} deny_exec_map SEC(".maps");

// Kill notification ring buffer — tell userspace when we blocked something
struct kill_event {
    __u32 pid;
    __u32 ppid;
    __u32 uid;
    __u64 timestamp_ns;
    char  comm[16];
    char  filename[256];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 64 * 1024);
} kill_events SEC(".maps");

SEC("lsm/bprm_check_security")
int BPF_PROG(ksm_bprm_check, struct linux_binprm *bprm, int ret)
{
    // If a previous LSM already denied, respect that
    if (ret != 0)
        return ret;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = (__u32)(pid_tgid >> 32);

    __u8 *deny = bpf_map_lookup_elem(&deny_exec_map, &pid);
    if (!deny)
        return 0;  // Not in deny list — allow

    // Log the kill event
    struct kill_event *e = bpf_ringbuf_reserve(&kill_events, sizeof(*e), 0);
    if (e) {
        __u64 uid_gid = bpf_get_current_uid_gid();
        e->pid = pid;
        e->uid = (__u32)uid_gid;
        e->timestamp_ns = bpf_ktime_get_ns();
        bpf_get_current_comm(e->comm, sizeof(e->comm));

        // Read parent PID
        struct task_struct *task = (void *)bpf_get_current_task();
        if (task) {
            struct task_struct *parent = NULL;
            BPF_CORE_READ_INTO(&parent, task, real_parent);
            if (parent) {
                BPF_CORE_READ_INTO(&e->ppid, parent, tgid);
            }
        }

        // Read the filename being exec'd
        if (bprm) {
            const char *fname = NULL;
            BPF_CORE_READ_INTO(&fname, bprm, filename);
            if (fname) {
                bpf_probe_read_kernel_str(e->filename, sizeof(e->filename), fname);
            }
        }

        bpf_ringbuf_submit(e, 0);
    }

    // Remove from deny map after blocking (one-shot)
    bpf_map_delete_elem(&deny_exec_map, &pid);

    return -EPERM;
}

char LICENSE[] SEC("license") = "GPL";
