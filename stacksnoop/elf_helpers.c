/* SPDX-License-Identifier: GPL-2.0 */
#include <assert.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>
#include <gelf.h>
#include <linux/bpf.h>
#include "log.h"

void get_sec(Elf *elf, int i, GElf_Ehdr *ehdr, char **shname,
             GElf_Shdr *shdr, Elf_Data **data)
{
    Elf_Scn *scn;

    scn = elf_getscn(elf, i);
    if (!scn)
        ERROR("elf_getscn: %s", elf_errmsg(-1));

    if (gelf_getshdr(scn, shdr) != shdr)
        ERROR("gelf_getshdr: %s", elf_errmsg(-1));

    *shname = elf_strptr(elf, ehdr->e_shstrndx, shdr->sh_name);
    if (!*shname || !shdr->sh_size)
        ERROR("elf_strptr: %s", elf_errmsg(-1));

    *data = elf_getdata(scn, 0);
    if (!*data || elf_getdata(scn, *data) != NULL)
        ERROR("elf_getdata: %s", elf_errmsg(-1));
}

void elf_load_bpf_insns(char *path, int stackmap_fd, int events_fd,
                        struct bpf_insn **insns, int *insns_size)
{
    int i, fd;
    Elf *elf;
    GElf_Ehdr ehdr;
    GElf_Shdr shdr, sym_shdr, rel_shdr;
    Elf_Data *data, *sym_data = NULL, *rel_data = NULL;
    int text_idx = -1, sym_idx = -1;
    char *name;

    if (elf_version(EV_CURRENT) == EV_NONE)
        ERROR_EXIT("elf_version: %s", elf_errmsg(-1));

    fd = open(path, O_RDONLY, 0);
    if (fd < 0)
        ERROR_EXIT("open: %s", strerror(errno));

    elf = elf_begin(fd, ELF_C_READ, NULL);
    if (!elf)
        ERROR_EXIT("elf_begin: %s", elf_errmsg(-1));

    if (gelf_getehdr(elf, &ehdr) != &ehdr)
        ERROR_EXIT("bpf file error");

    for (i = 1; i < ehdr.e_shnum; i++) {
        get_sec(elf, i, &ehdr, &name, &shdr, &data);
        DBG("section %d:%s data %p size %zd link %d flags %d",
               i, name, data->d_buf, data->d_size,
               shdr.sh_link, (int) shdr.sh_flags);

        if (strcmp(name, ".text") == 0) {
            assert(shdr.sh_type == SHT_PROGBITS);
            assert(shdr.sh_flags & SHF_EXECINSTR);
            text_idx = i;
            *insns = (struct bpf_insn *) data->d_buf;
            *insns_size = data->d_size;
        } else if (strcmp(name, ".symtab") == 0) {
            assert(shdr.sh_type == SHT_SYMTAB);
            sym_idx = i;
            sym_data = data;
            sym_shdr = shdr;
        } else if (strcmp(name, ".rel.text") == 0) {
            assert(shdr.sh_type == SHT_REL);
            rel_shdr = shdr;
            rel_data = data;
        }
    }

    assert(text_idx != -1 && sym_idx != -1 && rel_data != NULL);
    assert(rel_shdr.sh_link == sym_idx && rel_shdr.sh_info == text_idx);

    for (i = 0; i < rel_shdr.sh_size/rel_shdr.sh_entsize; i++) {
        GElf_Sym sym;
        GElf_Rel rel;
        int idx;
        struct bpf_insn *insn;

        gelf_getrel(rel_data, i, &rel);
        idx = rel.r_offset / sizeof(struct bpf_insn);
        insn = &(*insns)[idx];

        if (insn->code != (BPF_LD | BPF_IMM | BPF_DW))
            ERROR_EXIT("invalid rel %d", i);
        insn->src_reg = BPF_PSEUDO_MAP_FD;

        gelf_getsym(sym_data, GELF_R_SYM(rel.r_info), &sym);
        name = elf_strptr(elf, sym_shdr.sh_link, sym.st_name);
        if (strcmp(name, "stackmap") == 0) {
            insn->imm = stackmap_fd;
        } else if (strcmp(name, "events") == 0) {
            insn->imm = events_fd;
        } else {
            ERROR_EXIT("invalid rel %d sym %s", i, name);
        }
    }
}
