import argparse

from dnstrace.dnstrace import DnsTrace

BPF_KPROBE = b"""
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
"""

BPF_SOCK = b"""
#include <net/sock.h>
#include <bcc/proto.h>

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

BPF_TABLE("extern", struct packet_info, struct process_info, packets, sizeof(long));
BPF_PERF_OUTPUT(dns_event_outputs);

int dns_filter(struct __sk_buff *skb) {
    u8 *cursor = 0;
    struct ethernet_t *ethernet = cursor_advance(cursor, sizeof(*ethernet));
    if (ethernet->type != ETH_P_IP) {
        return 0;
    }

    struct ip_t *ip = cursor_advance(cursor, sizeof(*ip));
    u8 protocol = ip->nextp;
    u16 src_port = 0, dst_port = 0;
    if (protocol == IPPROTO_UDP) {
        struct udp_t *udp = cursor_advance(cursor, sizeof(*udp));
        src_port = udp->sport;
        dst_port = udp->dport;
    }
    else if (protocol == IPPROTO_TCP) {
        struct tcp_t *tcp = cursor_advance(cursor, sizeof(*tcp));
        if (!tcp->flag_psh) {
            return 0;
        }
        src_port = tcp->src_port;
        dst_port = tcp->dst_port;
    }
    else {
        return 0;
    }
    if (dst_port != 53 && src_port != 53) {
        return 0;
    }

    struct packet_info packet = {};
    packet.protocol = protocol;
    packet.src_addr = skb->ingress_ifindex == 0 ? ip->src : ip->dst;
    packet.dst_addr = skb->ingress_ifindex == 0 ? ip->dst : ip->src;

    struct process_info *ps_info = packets.lookup(&packet);
    if (ps_info) {
        ps_info->ifindex = skb->ifindex;
        dns_event_outputs.perf_submit_skb(skb, skb->len, ps_info, sizeof(struct process_info));
    }
    return 0;
}
"""


def main():
    parser = argparse.ArgumentParser(description="Monitor DNS queries by host processes using eBPF!")
    parser.add_argument("-t", "--tail", action="store_true", help="Stream live DNS queries")
    args = parser.parse_args()

    dns_trace = DnsTrace(BPF_KPROBE, BPF_SOCK, tail_mode=args.tail)
    dns_trace.start()


if __name__ == "__main__":
    main()
