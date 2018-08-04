#ifndef _ELF_HELPERS_H
#define _ELF_HELPERS_H

void elf_load_bpf_insns(char *path, int stackmap_fd, int events_fd,
                        void **insns, int *insns_size);

#endif
