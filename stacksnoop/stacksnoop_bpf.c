/* SPDX-License-Identifier: GPL-2.0 */
#include <linux/bpf.h>
#include "share.h"

extern __u64 stackmap;
extern __u64 events;

static unsigned long long (*bpf_get_current_pid_tgid)(void) =
    (void *) BPF_FUNC_get_current_pid_tgid;

static int (*bpf_get_current_comm)(void *buf, int buf_size) =
    (void *) BPF_FUNC_get_current_comm;

static int (*bpf_get_stackid)(void *ctx, void *map, __u64 flags) =
    (void *) BPF_FUNC_get_stackid;

static int (*bpf_perf_event_output)(void *ctx, void *map, __u64 index,
            void *data, __u32 size) =
    (void *) BPF_FUNC_perf_event_output;

void trace_stack(void *ctx)
{
    struct data data = {};

    /*
     * The bpf function calls must use &var to avoid an extra instruction.
     * Try change &stackmap to stackmap and see the difference.
     */
    data.stack_id = bpf_get_stackid(ctx, &stackmap, BPF_F_REUSE_STACKID);
    data.pid = bpf_get_current_pid_tgid();
    bpf_get_current_comm(&data.comm, sizeof(data.comm));

    /*
     * If the flag == n, only allows events from n-th CPU.
     * The special flag BPF_F_CURRENT_CPU allows events from all CPUs.
     */
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &data, sizeof(data));
}
