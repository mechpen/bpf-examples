#ifndef _KSYMS_H
#define _KSYMS_H

#include <linux/types.h>

void ksyms_load(void);

void ksyms_lookup_addr(__u64 addr, const char **name, __s64 *offset);

#endif
