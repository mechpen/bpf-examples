#ifndef _STACKSNOOP_H
#define _STACKSNOOP_H

#include <linux/types.h>

#define TASK_COMM_LEN 16

struct data {
    __u64 stack_id;
    __u32 pid;
    char comm[TASK_COMM_LEN];
};

#endif
