/* SPDX-License-Identifier: GPL-2.0 */
#include <stdio.h>
#include <stddef.h>
#include <assert.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <linux/bpf.h>
#include <linux/filter.h>
#include <linux/unistd.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <netinet/ip.h>

#define BPF_MOV64_IMM(DST, IMM)                                 \
        ((struct bpf_insn) {                                    \
                .code  = BPF_ALU64 | BPF_MOV | BPF_K,           \
                .dst_reg = DST,                                 \
                .src_reg = 0,                                   \
                .off   = 0,                                     \
                .imm   = IMM })

#define BPF_MOV64_REG(DST, SRC)                                 \
        ((struct bpf_insn) {                                    \
                .code  = BPF_ALU64 | BPF_MOV | BPF_X,           \
                .dst_reg = DST,                                 \
                .src_reg = SRC,                                 \
                .off   = 0,                                     \
                .imm   = 0 })

#define BPF_LD_ABS(SIZE, IMM)                                   \
        ((struct bpf_insn) {                                    \
                .code  = BPF_LD | BPF_SIZE(SIZE) | BPF_ABS,     \
                .dst_reg = 0,                                   \
                .src_reg = 0,                                   \
                .off   = 0,                                     \
                .imm   = IMM })

#define BPF_STX_MEM(SIZE, DST, SRC, OFF)                        \
        ((struct bpf_insn) {                                    \
                .code  = BPF_STX | BPF_SIZE(SIZE) | BPF_MEM,    \
                .dst_reg = DST,                                 \
                .src_reg = SRC,                                 \
                .off   = OFF,                                   \
                .imm   = 0 })

#define BPF_ALU64_IMM(OP, DST, IMM)                             \
        ((struct bpf_insn) {                                    \
                .code  = BPF_ALU64 | BPF_OP(OP) | BPF_K,        \
                .dst_reg = DST,                                 \
                .src_reg = 0,                                   \
                .off   = 0,                                     \
                .imm   = IMM })

#define BPF_EMIT_CALL(FUNC)                                     \
        ((struct bpf_insn) {                                    \
                .code  = BPF_JMP | BPF_CALL,                    \
                .dst_reg = 0,                                   \
                .src_reg = 0,                                   \
                .off   = 0,                                     \
                .imm   = (FUNC)})

#define BPF_JMP_IMM(OP, DST, IMM, OFF)                          \
        ((struct bpf_insn) {                                    \
                .code  = BPF_JMP | BPF_OP(OP) | BPF_K,          \
                .dst_reg = DST,                                 \
                .src_reg = 0,                                   \
                .off   = OFF,                                   \
                .imm   = IMM })

#define BPF_STX_XADD(SIZE, DST, SRC, OFF)                       \
        ((struct bpf_insn) {                                    \
                .code  = BPF_STX | BPF_SIZE(SIZE) | BPF_XADD,   \
                .dst_reg = DST,                                 \
                .src_reg = SRC,                                 \
                .off   = OFF,                                   \
                .imm   = 0 })

#define BPF_LD_MAP_FD(DST, MAP_FD)                              \
        BPF_LD_IMM64_RAW(DST, BPF_PSEUDO_MAP_FD, MAP_FD)

#define BPF_LD_IMM64_RAW(DST, SRC, IMM)                         \
        ((struct bpf_insn) {                                    \
                .code  = BPF_LD | BPF_DW | BPF_IMM,             \
                .dst_reg = DST,                                 \
                .src_reg = SRC,                                 \
                .off   = 0,                                     \
                .imm   = (__u32) (IMM) }),                      \
        ((struct bpf_insn) {                                    \
                .code  = 0, /* zero is reserved opcode */       \
                .dst_reg = 0,                                   \
                .src_reg = 0,                                   \
                .off   = 0,                                     \
                .imm   = ((__u64) (IMM)) >> 32 })

#define BPF_EXIT_INSN()                                         \
        ((struct bpf_insn) {                                    \
                .code  = BPF_JMP | BPF_EXIT,                    \
                .dst_reg = 0,                                   \
                .src_reg = 0,                                   \
                .off   = 0,                                     \
        .imm   = 0 })

static inline int open_raw_sock(const char *name)
{
    struct sockaddr_ll sll;
    int sock;

    sock = socket(PF_PACKET, SOCK_RAW | SOCK_NONBLOCK | SOCK_CLOEXEC,
                  htons(ETH_P_ALL));
    if (sock < 0) {
        printf("cannot create raw socket\n");
        return -1;
    }

    bzero(&sll, sizeof(sll));
    sll.sll_family = AF_PACKET;
    sll.sll_ifindex = if_nametoindex(name);
    sll.sll_protocol = htons(ETH_P_ALL);
    if (bind(sock, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
        printf("bind to %s: %s\n", name, strerror(errno));
        close(sock);
        return -1;
    }

    return sock;
}

static inline int sys_bpf(enum bpf_cmd cmd, union bpf_attr *attr,
                          unsigned int size)
{
    return syscall(__NR_bpf, cmd, attr, size);
}

int bpf_create_map(enum bpf_map_type map_type, int key_size,
                   int value_size, int max_entries)
{
    union bpf_attr attr;

    bzero(&attr, sizeof(attr));
    attr.map_type = map_type;
    attr.key_size = key_size;
    attr.value_size = value_size;
    attr.max_entries = max_entries;

    return sys_bpf(BPF_MAP_CREATE, &attr, sizeof(attr));
}

int bpf_prog_load(enum bpf_prog_type prog_type, struct bpf_insn* insns,
                  int insns_size, const char *license)
{
    union bpf_attr attr;

    bzero(&attr, sizeof(attr));
    attr.prog_type = prog_type;
    attr.insn_cnt = insns_size/sizeof(struct bpf_insn);
    attr.insns = (__u64)insns;
    attr.license = (__u64)license;

    return sys_bpf(BPF_PROG_LOAD, &attr, sizeof(attr));
}

int bpf_map_lookup_elem(int fd, const void *key, void *value)
{
    union bpf_attr attr;

    bzero(&attr, sizeof(attr));
    attr.map_fd = fd;
    attr.key = (__u64)key;
    attr.value = (__u64)value;

    return sys_bpf(BPF_MAP_LOOKUP_ELEM, &attr, sizeof(attr));
}

/* bpf+sockets example:
 * 1. create array map of 256 elements
 * 2. load program that counts number of packets received
 *    r0 = skb->data[ETH_HLEN + offsetof(struct iphdr, protocol)]
 *    map[r0]++
 * 3. attach prog_fd to raw socket via setsockopt()
 * 4. print number of received TCP/UDP packets every second
 */
int main(int argc, char **argv)
{
    char *interface = "lo";
    int sock, map_fd, prog_fd, key;
    long long value = 0, tcp_cnt, udp_cnt;

    if (argc > 1)
        interface = argv[1];

    map_fd = bpf_create_map(BPF_MAP_TYPE_ARRAY, sizeof(key),
                            sizeof(value), 256);
    if (map_fd < 0) {
        printf("failed to create map '%s'\n", strerror(errno));
        return 1;
    }

    struct bpf_insn prog[] = {
        BPF_MOV64_REG(BPF_REG_6, BPF_REG_1),      /* r6 = r1 */
        BPF_LD_ABS(BPF_B, ETH_HLEN + offsetof(struct iphdr, protocol)),
                                                  /* r0 = ip->proto */
        BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_0, -4),
                                                  /* *(u32 *)(fp - 4) = r0 */
        BPF_MOV64_REG(BPF_REG_2, BPF_REG_10),     /* r2 = fp */
        BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -4),    /* r2 = r2 - 4 */
        BPF_LD_MAP_FD(BPF_REG_1, map_fd),         /* r1 = map_fd */
        BPF_EMIT_CALL(BPF_FUNC_map_lookup_elem),  /* r0 = map_lookup(r1, r2) */
        BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 0, 2),    /* if (r0 == 0) goto pc+2 */
        BPF_MOV64_IMM(BPF_REG_1, 1),              /* r1 = 1 */
        BPF_STX_XADD(BPF_DW, BPF_REG_0, BPF_REG_1, 0),
                                                  /* lock *(u64 *) r0 += r1 */
        BPF_MOV64_IMM(BPF_REG_0, 0),              /* r0 = 0 */
        BPF_EXIT_INSN(),                          /* return r0 */
    };

    prog_fd = bpf_prog_load(BPF_PROG_TYPE_SOCKET_FILTER, prog,
                            sizeof(prog), "GPL");
    if (prog_fd < 0) {
        printf("failed to load bpf '%s'\n", strerror(errno));
        return 1;
    }

    sock = open_raw_sock(interface);
    assert(setsockopt(sock, SOL_SOCKET, SO_ATTACH_BPF, &prog_fd,
                      sizeof(prog_fd)) == 0);

    for (;;) {
        key = IPPROTO_TCP;
        assert(bpf_map_lookup_elem(map_fd, &key, &tcp_cnt) == 0);
        key = IPPROTO_UDP;
        assert(bpf_map_lookup_elem(map_fd, &key, &udp_cnt) == 0);
        printf("TCP %lld UDP %lld packets\n", tcp_cnt, udp_cnt);
        sleep(1);
    }

    return 0;
}
