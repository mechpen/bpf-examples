/* SPDX-License-Identifier: GPL-2.0 */
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <assert.h>
#include <poll.h>
#include "utils.h"
#include "bpf_helpers.h"
#include "elf_helpers.h"
#include "event_helpers.h"
#include "ksyms.h"
#include "share.h"
#include "log.h"

#define BPF_OBJ  "stacksnoop_bpf.o"

int log_verbose = 0;
int stackmap_fd;

void process_data(void *data, int size)
{
    int i;
    struct data *d = data;
    __u64 stack[BPF_MAX_STACK_DEPTH];

    assert(size >= sizeof(*d));
    printf(">>> pid: %d comm: %s\n", d->pid, d->comm);
    bpf_lookup_stack(stackmap_fd, d->stack_id, stack);

    for (i = 0; i < BPF_MAX_STACK_DEPTH && stack[i] != 0; i++) {
        const char *name;
        __s64 offset;

        ksyms_lookup_addr(stack[i], &name, &offset);
        printf("    %p @ %s %s0x%llx\n", (void *)stack[i], name,
               offset>=0 ? "+"    : "-", offset>=0 ? offset : -offset);
    }
}

int main(int argc, char *argv[])
{
    char *function;
    int eventmap_fd, bpf_fd;
    int insns_size, i, num_cpus;
    void *insns, **fd_mems;
    struct pollfd *poll_fds;

    if (argc != 2) {
        printf("Usage: %s <function>\n", argv[0]);
        exit(1);
    }
    function = argv[1];

    ksyms_load();
    stackmap_fd = bpf_load_stack_map();
    eventmap_fd = bpf_load_event_array();
    elf_load_bpf_insns(BPF_OBJ, stackmap_fd, eventmap_fd, &insns, &insns_size);
    bpf_fd = bpf_load_prog(insns, insns_size);
    event_attach_kprobe(bpf_fd, function);

    num_cpus = get_num_cpus();
    fd_mems = malloc(num_cpus*sizeof(*fd_mems));
    poll_fds = calloc(num_cpus, sizeof(*poll_fds));

    for (i = 0; i < num_cpus; i++) {
        poll_fds[i].events = POLLIN;
        event_open_reader(i, &(poll_fds[i].fd), &fd_mems[i]);
        bpf_map_update_elem(eventmap_fd, &i, &(poll_fds[i].fd));
    }

    printf(">>> waiting for %s()\n", function);
    for (;;) {
        if (poll(poll_fds, num_cpus, -1) < 0) {
            if (errno == EINVAL)
                ERROR_EXIT("poll: Invalid");
        }
        for (i = 0; i < num_cpus; i++) {
            if (poll_fds[i].revents & POLLIN) {
                DBG("read cpu %d", i);
                process_events(fd_mems[i], process_data);
            }
        }
    }
    return 0;
}
