/* SPDX-License-Identifier: GPL-2.0 */
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <assert.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <stropts.h>
#include <linux/perf_event.h>
#include <linux/unistd.h>
#include "utils.h"
#include "event_helpers.h"
#include "log.h"

static int page_size;
static int page_cnt = 8;
static int mmap_size;

static void *perf_event_mmap(int fd)
{
    void *mem;

    page_size = getpagesize();
    mmap_size = page_size * (page_cnt + 1);

    mem = mmap(NULL, mmap_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (mem == MAP_FAILED)
            ERROR_EXIT("mmap: %s", strerror(errno));

    return mem;
}

static inline int sys_perf_event_open(struct perf_event_attr *attr,
                                      pid_t pid, int cpu, int group_fd,
                                      unsigned long flags)
{
    return syscall(__NR_perf_event_open, attr, pid, cpu, group_fd, flags);
}

int event_attach_kprobe_dympmu(int bpf_fd, char *function)
{
    int fd, type;
    struct perf_event_attr attr;

    type = find_kprobe_pmu_type("kprobe");
    if (type < 0)
        return -1;

    bzero(&attr, sizeof(attr));
    attr.sample_period = 1;
    attr.wakeup_events = 1;
    attr.size = sizeof(attr);
    attr.type = type;

    attr.config1 = (__u64)function;
    attr.config2 = (__u64)0;

    fd = sys_perf_event_open(&attr, -1, 0, -1, PERF_FLAG_FD_CLOEXEC);
    if (fd < 0)
        ERROR_EXIT("perf_event_open: %s", strerror(errno));
    return fd;
}

int event_attach_kprobe_debugfs(int bpf_fd, char *function)
{
    int fd, bytes;
    char buf[256];
    static char *event_alias = "stacksnoop";
    static char *event_type = "kprobe";
    struct perf_event_attr attr;

    snprintf(buf, sizeof(buf), "/sys/kernel/debug/tracing/%s_events",
             event_type);
    fd = open(buf, O_WRONLY | O_APPEND, 0);
    if (fd < 0)
        ERROR_EXIT("open: %s", strerror(errno));

    snprintf(buf, sizeof(buf), "p:%ss/%s %s",
             event_type, event_alias, function);

    if (write(fd, buf, strlen(buf)) < 0)
        ERROR_EXIT("cannot attach kprobe: %s", strerror(errno));
    close(fd);

    snprintf(buf, sizeof(buf), "/sys/kernel/debug/tracing/events/%ss/%s/id",
             event_type, event_alias);
    fd = open(buf, O_RDONLY, 0);
    if (fd < 0)
        ERROR_EXIT("open(%s): %s", buf, strerror(errno));

    bytes = read(fd, buf, sizeof(buf));
    if (bytes <= 0 || bytes >= sizeof(buf))
        ERROR_EXIT("read %s error: %s", buf, strerror(errno));
    close(fd);
    buf[bytes] = '\0';

    bzero(&attr, sizeof(attr));
    attr.config = strtol(buf, NULL, 0);
    attr.type = PERF_TYPE_TRACEPOINT;
    attr.sample_period = 1;
    attr.wakeup_events = 1;

    fd = sys_perf_event_open(&attr, -1, 0, -1, PERF_FLAG_FD_CLOEXEC);
    if (fd < 0)
        ERROR_EXIT("perf_event_open: %s", strerror(errno));
    return fd;
}

void event_attach_kprobe(int bpf_fd, char *function)
{
    int fd;

    fd = event_attach_kprobe_dympmu(bpf_fd, function);
    if (fd < 0)
        fd = event_attach_kprobe_debugfs(bpf_fd, function);

    if (ioctl(fd, PERF_EVENT_IOC_SET_BPF, bpf_fd) < 0)
        ERROR_EXIT("ioctl(SET_BPF): %s", strerror(errno));
    if (ioctl(fd, PERF_EVENT_IOC_ENABLE, 0) < 0)
        ERROR_EXIT("ioctl(ENABLE, kprobe): %s", strerror(errno));
}

void event_open_reader(int cpu, int *fd, void **mem)
{
    struct perf_event_attr attr;

    bzero(&attr, sizeof(attr));
    attr.type = PERF_TYPE_SOFTWARE;
    attr.config = PERF_COUNT_SW_BPF_OUTPUT;
    attr.sample_type = PERF_SAMPLE_RAW;
    attr.sample_period = 1;
    attr.wakeup_events = 1;
    attr.size = sizeof(attr);

    *fd = sys_perf_event_open(&attr, -1, cpu, -1, PERF_FLAG_FD_CLOEXEC);
    if (*fd < 0)
        ERROR_EXIT("perf_event_open: %s", strerror(errno));

    *mem = perf_event_mmap(*fd);
    if (ioctl(*fd, PERF_EVENT_IOC_ENABLE, 0) < 0)
        ERROR_EXIT("ioctl(ENABLE, sample): %s", strerror(errno));
}

static void process_lost_event(void *event)
{
    struct {
        struct perf_event_header header;
        __u64 id;
        __u64 lost;
    } *e = event;

    INFO("lost %lld samples", e->lost);
}

static void process_sample_event(void *event, event_handler_t handler)
{
    struct {
        struct perf_event_header header;
        __u32 size;
        char data[0];
    } *e = event;

    assert(e->header.size >= sizeof(*e));
    assert(e->header.size == sizeof(*e) + e->size);

    handler(e->data, e->size);
}

static void process_event(void *event, event_handler_t handler)
{
    struct perf_event_header *eh = event;

    DBG("event type %d ", eh->type);
    if (eh->type == PERF_RECORD_LOST)
        process_lost_event(event);
    else if (eh->type == PERF_RECORD_SAMPLE)
        process_sample_event(event, handler);
    else
        ERROR("invalid event type %d", eh->type);
}

void process_events(void *mem, event_handler_t handler)
{
    static void *buf = NULL;
    static size_t buf_len = 0;
    struct perf_event_mmap_page *header = mem;
    __u64 data_tail = header->data_tail;
    __u64 data_head = header->data_head;
    void *base, *begin, *end;

    asm volatile("" ::: "memory"); /* in real code it should be smp_rmb() */
    if (data_head == data_tail)
        return;

    base = ((char *)header) + page_size;
    begin = base + data_tail % mmap_size;
    end = base + data_head % mmap_size;

    while (begin != end) {
        struct perf_event_header *ehdr;

        ehdr = begin;
        if (begin + ehdr->size > base + mmap_size) {
            long len = base + mmap_size - begin;

            if (buf_len < ehdr->size) {
                free(buf);
                buf = malloc(ehdr->size);
                if (!buf)
                    ERROR_EXIT("malloc: %s", strerror(errno));
                buf_len = ehdr->size;
            }

            memcpy(buf, begin, len);
            memcpy(buf + len, base, ehdr->size - len);
            ehdr = buf;
            begin = base + ehdr->size - len;
        } else if (begin + ehdr->size == base + mmap_size) {
            begin = base;
        } else {
            begin += ehdr->size;
        }

        process_event(ehdr, handler);
        data_tail += ehdr->size;
    }

    __sync_synchronize(); /* smp_mb() */
    header->data_tail = data_tail;
}
