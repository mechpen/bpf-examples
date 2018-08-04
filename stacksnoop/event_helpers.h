#ifndef _EVENT_HELPERS_H
#define _EVENT_HELPERS_H

typedef void (*event_handler_t)(void *event, int size);

void event_attach_kprobe(int bpf_fd, char *function);

void event_open_reader(int cpu, int *fd, void **mem);

void process_events(void *mem, event_handler_t handler);

#endif
