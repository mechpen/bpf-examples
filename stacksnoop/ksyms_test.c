#include <stdio.h>
#include <stdlib.h>
#include "ksyms.h"
#include "log.h"

int log_verbose = 1;

int main(int argc, char *argv[])
{
    char *name;
    __u64 addr, off;

    if (argc < 2) {
        printf("no addr\n");
        return 1;
    }

    ksyms_load();
    addr = strtoul(argv[1], NULL, 16);
    ksyms_lookup_addr(addr, &name, &off);
    printf("%p is at %s+0x%llx\n", (void *)addr, name, off);

    return 0;
}
