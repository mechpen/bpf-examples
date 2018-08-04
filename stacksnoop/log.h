#ifndef _LOG_H
#define _LOG_H

#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>

extern int log_verbose;

static inline void dump(void *_data, int len)
{
    int i;
    char *data = _data;

    printf("%02hhx", data[0]);
    for (i = 1; i < len; i++) {
        if ((i % 2) == 0)
            printf(" ");
        if ((i % 16) == 0)
            printf("\n");
        printf("%02hhx", data[i]);
    }
    printf("\n");
}

#define DBG_DUMP(data, len) ({                              \
    if (log_verbose)                                        \
        dump(data, len);                                    \
})

#define DBG(fmt, args...) ({                                \
    if (log_verbose) {                                      \
        struct timeval tv;                                  \
        gettimeofday(&tv, NULL);                            \
        fprintf(stderr, "%ld.%02ld [dbg] %s: " fmt "\n",    \
            tv.tv_sec, tv.tv_usec/10000,                    \
            __func__, ##args);                              \
    }                                                       \
})

#define INFO(fmt, args...) ({                               \
    struct timeval tv;                                      \
    gettimeofday(&tv, NULL);                                \
    fprintf(stderr, "%ld.%02ld [info] " fmt "\n",           \
        tv.tv_sec, tv.tv_usec/10000,                        \
        ##args);                                            \
})

#define ERROR(fmt, args...) ({                              \
    struct timeval tv;                                      \
    gettimeofday(&tv, NULL);                                \
    fprintf(stderr, "%ld.%02ld [error] %s: " fmt "\n",      \
        tv.tv_sec, tv.tv_usec/10000,                        \
        __func__, ##args);                                  \
})

#define ERROR_EXIT(fmt, args...) ({                         \
    ERROR(fmt, ##args);                                     \
    exit(-1);                                               \
})

#endif
