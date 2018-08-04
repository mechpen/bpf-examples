#ifndef _UTILS_H
#define _UTILS_H

unsigned int get_kern_version(void);

int find_kprobe_pmu_type(const char *event_type);

int get_num_cpus();

#endif
