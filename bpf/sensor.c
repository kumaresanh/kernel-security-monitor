// SPDX-License-Identifier: GPL-2.0
// Kernel Security Monitor eBPF Sensor — CO-RE tracepoints for execve, openat, connect
// Ring buffer delivery to userspace

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define MAX_PAYLOAD 256
#define MAX_ARGS    20
#define TASK_COMM_LEN 16

// Event types — must match Go side
enum event_type {
    EVENT_EXECVE  = 1,
    EVENT_OPENAT  = 2,
    EVENT_CONNECT = 3,
};

// Shared event structure sent through ring buffer
struct event {
    __u32 event_type;
    __u32 pid;
    __u32 ppid;
    __u32 uid;
    __u64 timestamp_ns;
    char  comm[TASK_COMM_LEN];
    // For execve: filename; for openat: pathname; for connect: addr string
    char  payload[MAX_PAYLOAD];
    __s32 ret_val;       // return value / flags
    __u32 payload_len;
    // Connect-specific fields
    __u16 dst_port;
    __u32 dst_ip4;
    __u16 sa_family;
    // Openat-specific
    __s32 flags;
};

// Ring buffer map — 256KB, sized for demo workloads
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

// PID filter map — only trace PIDs in this set (0 = trace all)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);
    __type(value, __u8);
} pid_filter SEC(".maps");

// Config: if filter_enabled is > 0, only trace PIDs in pid_filter
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} ksm_config SEC(".maps");

static __always_inline int should_trace(__u32 pid)
{
    __u32 key = 0;
    __u32 *filter_enabled = bpf_map_lookup_elem(&ksm_config, &key);
    if (filter_enabled && *filter_enabled > 0) {
        __u8 *val = bpf_map_lookup_elem(&pid_filter, &pid);
        return val != NULL;
    }
    // Filter disabled — trace everything (but skip kernel threads)
    return pid > 0;
}

static __always_inline void fill_common(struct event *e, enum event_type type)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u64 uid_gid  = bpf_get_current_uid_gid();

    e->event_type   = type;
    e->pid          = (__u32)(pid_tgid >> 32);
    e->ppid         = 0; // filled below via task_struct
    e->uid          = (__u32)uid_gid;
    e->timestamp_ns = bpf_ktime_get_ns();
    e->ret_val      = 0;
    e->payload_len  = 0;
    e->dst_port     = 0;
    e->dst_ip4      = 0;
    e->sa_family    = 0;
    e->flags        = 0;
    bpf_get_current_comm(e->comm, sizeof(e->comm));

    // Read parent PID via task_struct
    struct task_struct *task = (void *)bpf_get_current_task();
    if (task) {
        struct task_struct *parent = NULL;
        BPF_CORE_READ_INTO(&parent, task, real_parent);
        if (parent) {
            BPF_CORE_READ_INTO(&e->ppid, parent, tgid);
        }
    }
}

// ---- tracepoint/syscalls/sys_enter_execve ----
// args: const char *filename, const char *const *argv, const char *const *envp
struct execve_args {
    unsigned short common_type;
    unsigned char  common_flags;
    unsigned char  common_preempt_count;
    int            common_pid;
    int            __syscall_nr;
    const char    *filename;
    const char *const *argv;
    const char *const *envp;
};

SEC("tracepoint/syscalls/sys_enter_execve")
int tracepoint_execve(struct execve_args *ctx)
{
    __u32 pid = (__u32)(bpf_get_current_pid_tgid() >> 32);
    if (!should_trace(pid))
        return 0;

    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    fill_common(e, EVENT_EXECVE);

    // Read filename
    const char *filename = NULL;
    bpf_probe_read_user(&filename, sizeof(filename), &ctx->filename);
    if (filename) {
        bpf_probe_read_user_str(e->payload, sizeof(e->payload), filename);
        e->payload_len = sizeof(e->payload); // conservative
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// ---- tracepoint/syscalls/sys_enter_openat ----
struct openat_args {
    unsigned short common_type;
    unsigned char  common_flags;
    unsigned char  common_preempt_count;
    int            common_pid;
    int            __syscall_nr;
    int            dfd;
    const char    *filename;
    int            flags;
    unsigned short mode;
};

SEC("tracepoint/syscalls/sys_enter_openat")
int tracepoint_openat(struct openat_args *ctx)
{
    __u32 pid = (__u32)(bpf_get_current_pid_tgid() >> 32);
    if (!should_trace(pid))
        return 0;

    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    fill_common(e, EVENT_OPENAT);

    const char *filename = NULL;
    bpf_probe_read_user(&filename, sizeof(filename), &ctx->filename);
    if (filename) {
        bpf_probe_read_user_str(e->payload, sizeof(e->payload), filename);
        e->payload_len = sizeof(e->payload);
    }

    bpf_probe_read_user(&e->flags, sizeof(e->flags), &ctx->flags);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// ---- tracepoint/syscalls/sys_enter_connect ----
struct connect_args {
    unsigned short common_type;
    unsigned char  common_flags;
    unsigned char  common_preempt_count;
    int            common_pid;
    int            __syscall_nr;
    int            fd;
    struct sockaddr *uservaddr;
    int            addrlen;
};

SEC("tracepoint/syscalls/sys_enter_connect")
int tracepoint_connect(struct connect_args *ctx)
{
    __u32 pid = (__u32)(bpf_get_current_pid_tgid() >> 32);
    if (!should_trace(pid))
        return 0;

    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    fill_common(e, EVENT_CONNECT);

    // Read sockaddr to extract family, IP, port
    struct sockaddr_in sa = {};
    struct sockaddr *addr = NULL;
    bpf_probe_read_user(&addr, sizeof(addr), &ctx->uservaddr);
    if (addr) {
        bpf_probe_read_user(&sa, sizeof(sa), addr);
        e->sa_family = sa.sin_family;
        if (sa.sin_family == 2) { // AF_INET
            e->dst_port = __builtin_bswap16(sa.sin_port);
            e->dst_ip4  = sa.sin_addr.s_addr;
        }
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
