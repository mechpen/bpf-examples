/* SPDX-License-Identifier: GPL-2.0 */
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <linux/bpf.h>
#include <linux/unistd.h>
#include "bpf_helpers.h"
#include "utils.h"
#include "log.h"

static inline int sys_bpf(enum bpf_cmd cmd, union bpf_attr *attr,
                          unsigned int size)
{
    return syscall(__NR_bpf, cmd, attr, size);
}

void bpf_map_update_elem(int fd, void *key, void *value)
{
    int ret;
    union bpf_attr attr;

    bzero(&attr, sizeof(attr));
    attr.map_fd = fd;
    attr.key = (__u64)key;
    attr.value = (__u64)value;
    attr.flags = BPF_ANY;

    ret = sys_bpf(BPF_MAP_UPDATE_ELEM, &attr, sizeof(attr));
    if (ret < 0)
        ERROR_EXIT("bpf: %s", strerror(errno));
}

void bpf_map_lookup_elem(int fd, const void *key, void *value)
{
    int ret;
    union bpf_attr attr = {
        .map_fd = fd,
        .key    = (__u64)key,
        .value  = (__u64)value,
    };

    ret = sys_bpf(BPF_MAP_LOOKUP_ELEM, &attr, sizeof(attr));
    if (ret < 0)
        ERROR_EXIT("bpf: %s", strerror(errno));
}

int bpf_load_stack_map(void)
{
    int ret;
    union bpf_attr attr;

    memset(&attr, '\0', sizeof(attr));
    attr.map_type = BPF_MAP_TYPE_STACK_TRACE;
    attr.key_size = sizeof(__u32);
    attr.value_size = BPF_MAX_STACK_DEPTH * sizeof(__u64);
    attr.max_entries = 1024;

    ret = sys_bpf(BPF_MAP_CREATE, &attr, sizeof(attr));
    if (ret < 0)
        ERROR_EXIT("bpf: %s", strerror(errno));
    return ret;
}

void bpf_lookup_stack(int fd, __u64 stack_id, __u64 *stack)
{
    bpf_map_lookup_elem(fd, &stack_id, stack);
}

int bpf_load_event_array(void)
{
    int ret;
    union bpf_attr attr;

    memset(&attr, '\0', sizeof(attr));
    attr.map_type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
    attr.key_size = sizeof(int);
    attr.value_size = sizeof(__u32);
    attr.max_entries = get_num_cpus();;

    ret = sys_bpf(BPF_MAP_CREATE, &attr, sizeof(attr));
    if (ret < 0)
        ERROR_EXIT("bpf: %s", strerror(errno));
    return ret;
}

int bpf_load_prog(void* insns, int insns_size)
{
    int ret;
    union bpf_attr attr;
    char *license = "GPL";
    static char log_buf[1024];

    DBG_DUMP(insns, insns_size);

    bzero(&attr, sizeof(attr));
    attr.prog_type = BPF_PROG_TYPE_KPROBE;
    attr.insn_cnt = insns_size/sizeof(struct bpf_insn);
    attr.insns = (__u64)insns;
    attr.license = (__u64)license;
    attr.kern_version = get_kern_version();

    attr.log_buf = (__u64)log_buf;
    attr.log_size = sizeof(log_buf);
    attr.log_level = 1;
    log_buf[0] = 0;

    ret = sys_bpf(BPF_PROG_LOAD, &attr, sizeof(attr));
    if (ret < 0)
        ERROR_EXIT("bpf: %s\n%s", strerror(errno), log_buf);
    return ret;
}
