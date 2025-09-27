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
