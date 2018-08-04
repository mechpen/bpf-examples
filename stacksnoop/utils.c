/* SPDX-License-Identifier: GPL-2.0 */
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <linux/limits.h>
#include "log.h"

unsigned int get_kern_version(void)
{
    char *cmd = "sh -c \"uname -r | cut -d- -f1 | awk -F . '{print \\$1*65536+\\$2*256+\\$3}'\"";
    char buf[100];
    FILE *fp;
    int version;

    fp = popen(cmd, "r");
    if (fp == NULL)
        ERROR_EXIT("popen error: %s", strerror(errno));

    if (fgets(buf, sizeof(buf), fp) == NULL)
        ERROR_EXIT("cannot read command output");

    errno = 0;
    version = (int)strtol(buf, NULL, 10);
    if (errno != 0)
        ERROR_EXIT("invalid version: %s", strerror(errno));

    fclose(fp);
    return version;
}

#define PMU_TYPE_FILE    "/sys/bus/event_source/devices/%s/type"

int find_kprobe_pmu_type(const char *event_type)
{
    int fd, ret;
    char buf[PATH_MAX];

    ret = snprintf(buf, sizeof(buf), PMU_TYPE_FILE, event_type);
    if (ret < 0 || ret >= sizeof(buf))
        ERROR_EXIT("snprintf error");

    fd = open(buf, O_RDONLY);
    if (fd < 0)
        return -1;

    ret = read(fd, buf, sizeof(buf));
    close(fd);
    if (ret < 0 || ret >= sizeof(buf))
        ERROR_EXIT("read: %s", strerror(errno));

    errno = 0;
    ret = (int)strtol(buf, NULL, 10);
    if (errno != 0)
        ERROR_EXIT("invalid type: %s", strerror(errno));

    return ret;
}

#define CPU_RANGE_FILE   "/sys/devices/system/cpu/online"
#define CPU_FILE_MAX      200

static int read_cpu_num(char *string)
{
    char *op;
    int ret;

    op = strrchr(string, ',');
    if (op != NULL)
        string = op + 1;

    op = strrchr(string, '-');
    if (op != NULL) 
        string = op + 1;

    errno = 0;
    ret = (int)strtol(string, NULL, 10);
    if (errno != 0)
        ERROR_EXIT("invalid type: %s", strerror(errno));

    return ret + 1;
}

int get_num_cpus()
{
    int fd, ret;
    char buf[CPU_FILE_MAX];

    fd = open(CPU_RANGE_FILE, O_RDONLY);
    if (fd < 0)
        ERROR_EXIT("open: %s", strerror(errno));

    ret = read(fd, buf, sizeof(buf));
    close(fd);
    if (ret < 0 || ret >= sizeof(buf))
        ERROR_EXIT("read: %s", strerror(errno));

    return read_cpu_num(buf);
}
