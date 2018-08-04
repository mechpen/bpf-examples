#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <limits.h>
#include <linux/types.h>
#include "log.h"

#define KSYMS_FILE       
#define MIN_KERN_ADDR    0x00ffffffffffffff
#define MAX_KERN_ADDR    0xffffffffffffffff

static int ksyms_count;
static __u64 *ksyms_addrs;
static char **ksyms_names;

void ksyms_lookup_addr(__u64 addr, const char **name, __u64 *offset)
{
    int l = 0, r = ksyms_count-1, m;

    if (addr < ksyms_addrs[l]) {
        ERROR("addr %p too small", (void *)addr);
        *name = "__min__";
        *offset = ksyms_addrs[l] - addr;
        return;
    }
    if (addr >= ksyms_addrs[r]) {
        *name = ksyms_names[r];
        *offset = addr - ksyms_addrs[r];
        return;
    }

    while (l + 1 < r) {
        m = (l + r) / 2;
        if (addr < ksyms_addrs[m])
            r = m;
        else
            l = m;
    }
    *name = ksyms_names[l];
    *offset = addr - ksyms_addrs[l];
}

static int get_ksyms_count()
{
    char *cmd = "wc -l /proc/kallsyms";
    char buf[100];
    FILE *fp;
    int count;

    fp = popen(cmd, "r");
    if (fp == NULL)
        ERROR_EXIT("popen error: %s", strerror(errno));

    if (fgets(buf, sizeof(buf), fp) == NULL)
        ERROR_EXIT("cannot read command output");

    errno = 0;
    count = (int)strtol(buf, NULL, 10);
    if (errno != 0)
        ERROR_EXIT("invalid output: %s", strerror(errno));

    fclose(fp);
    return count;
}

static void add_ksym(char *name, __u64 addr)
{
    ksyms_names[ksyms_count] = strdup(name);
    ksyms_addrs[ksyms_count] = addr;
    ksyms_count++;
}

void ksyms_load(void)
{
    char *cmd = "sort /proc/kallsyms";
    FILE *fp;
    char line[2048], *name, *p;
    __u64 addr;
    int count;

    count = get_ksyms_count();
    ksyms_addrs = malloc(count*sizeof(*ksyms_addrs));
    ksyms_names = malloc(count*sizeof(*ksyms_names));

    fp = popen(cmd, "r");
    if (fp == NULL)
        ERROR_EXIT("popen error: %s", strerror(errno));

    while (fgets(line, sizeof(line), fp) != NULL) {
        addr = strtoul(line, &p, 16);
        if (addr == 0 || addr == ULLONG_MAX)
            continue;
        if (addr < MIN_KERN_ADDR)
            continue;

        p++;
        if (*p == 'b' || *p == 'B' || *p == 'd' ||
            *p == 'D' || *p == 'r' || *p == 'R')
            continue;

        p += 2;
        name = p;
        while (*p && !isspace(*p))
            p++;
        *p = '\0';

        add_ksym(name, addr);
    }

    if (ksyms_count == 0)
        ERROR_EXIT("no symbol found");
    DBG("loaded %d symbols", ksyms_count);

    fclose(fp);
}
