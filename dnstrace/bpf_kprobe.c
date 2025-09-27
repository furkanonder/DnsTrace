#include <net/sock.h>

struct packet_info {
    u8 protocol;
    u32 src_addr;
    u32 dst_addr;
};
struct process_info {
    u32 ifindex;
    u32 pid;
    char comm[64];
};

BPF_TABLE_PUBLIC("hash", struct packet_info, struct process_info, packets, sizeof(long));

int trace_sendmsg(struct pt_regs *ctx, struct sock *sk) {
    u8 protocol = sk->sk_protocol;
    u16 src_port = sk->sk_num, dst_port = sk->sk_dport;

    if (src_port == ntohs(53) || dst_port == ntohs(53)) {
        u32 src_addr = sk->sk_rcv_saddr, dst_addr = sk->sk_daddr;
        struct packet_info packet = {};
        packet.protocol = protocol;
        packet.src_addr = htonl(src_addr);
        packet.dst_addr = htonl(dst_addr);
        struct process_info val = {};
        val.pid = bpf_get_current_pid_tgid() >> 32;
        bpf_get_current_comm(val.comm, 64);
        packets.update(&packet, &val);
    }
    return 0;
}
