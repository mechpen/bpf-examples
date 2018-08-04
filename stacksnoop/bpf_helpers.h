#ifndef _BPF_HELPERS_H
#define _BPF_HELPERS_H

#include <linux/types.h>

#define BPF_MAX_STACK_DEPTH 127

int bpf_load_stack_map(void);

void bpf_lookup_stack(int fd, __u64 stack_id, __u64 *stack);

int bpf_load_event_array(void);

int bpf_load_prog(void* insns, int insns_size);

void bpf_map_update_elem(int fd, void *key, void *value);

#endif
