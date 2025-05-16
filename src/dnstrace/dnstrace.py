import ctypes as ct
import os
import site
import socket
import struct
import sys
from collections import Counter
from datetime import datetime

from dnslib import QTYPE, DNSRecord

from dnstrace.color import BLUE, CYAN, GREEN, MAGENTA, RED, YELLOW, set_color

DNS_PROTOCOLS = {17: "UDP", 6: "TCP"}
IP_VERSIONS = {4: "IPv4"}
ETH_LENGTH = 14

try:
    version = sys.version_info
    site.addsitedir(f"/usr/lib/python{version.major}.{version.minor}/site-packages")
    site.addsitedir("/usr/lib/python3/dist-packages")
    site.addsitedir(os.path.expandvars("$PYTHON_USER_SITE"))
    from bcc import BPF
except ImportError:
    print(set_color(RED, "Error: The 'bcc' module is not available."))
    print(
        set_color(
            BLUE, "For installation instructions, please visit: https://github.com/iovisor/bcc/blob/master/INSTALL.md"
        )
    )
    sys.exit(1)


class DnsTrace:
    def __init__(self, bpf_kprobe: bytes, bpf_sock: bytes, tail_mode: bool = False) -> None:
        self.bpf_kprobe = BPF(text=bpf_kprobe)
        self.bpf_sock = BPF(text=bpf_sock)
        self.packets: Counter = Counter()
        self.query_types: Counter = Counter()
        self.start_time = datetime.now()
        self.tail_mode = tail_mode

    @staticmethod
    def create_skb_event(size: int) -> type[ct.Structure]:
        class SkbEvent(ct.Structure):
            _fields_ = [
                ("ifindex", ct.c_uint32),
                ("pid", ct.c_uint32),
                ("comm", ct.c_char * 64),
                ("raw", ct.c_ubyte * (size - ct.sizeof(ct.c_uint32 * 2) - ct.sizeof(ct.c_char * 64))),
            ]

        return SkbEvent

    @staticmethod
    def parse_packet(raw: bytes) -> tuple:
        # Skip Ethernet header
        ip_packet = raw[ETH_LENGTH:]

        ip_header = struct.unpack("!BBHHHBBH4s4s", ip_packet[:20])
        ip_protocol = ip_header[6]
        ip_version = ip_header[0] >> 4
        ip_src = socket.inet_ntoa(ip_header[8])
        ip_dst = socket.inet_ntoa(ip_header[9])
        header_len = ip_header[0] & 0x0F
        # Calculate header length in bytes
        header_len = header_len * 4

        # UDP
        if ip_protocol == 17:
            udp_packet = ip_packet[header_len:]
            dns_packet = udp_packet[8:]
        # TCP
        elif ip_protocol == 6:
            tcp_packet = ip_packet[header_len:]
            tcp_header_len = tcp_packet[12] >> 4
            tcp_header_len = tcp_header_len * 4 + 2
            dns_packet = tcp_packet[tcp_header_len:]

        dns_data = DNSRecord.parse(dns_packet)
        is_query = True if dns_data.header.qr == 0 else False
        query_type = QTYPE.get(dns_data.q.qtype, f"{dns_data.q.qtype}")
        return IP_VERSIONS[ip_version], DNS_PROTOCOLS[ip_protocol], ip_src, ip_dst, query_type, is_query

    def print_stats(self) -> None:
        os.system("clear")
        print(
            f"DNSTrace v0.1.0\t\t {set_color(BLUE, 'START TIME:')} {self.start_time}\t\t"
            f"{set_color(BLUE, 'LAST REFRESH:')} {datetime.now()}\n"
            f"{set_color(GREEN, 'TOTAL QUERIES:')} {set_color(RED, self.packets.total())}\n"
        )

        for q_type in self.query_types.keys():
            print(f"{set_color(MAGENTA, '~')} ", end="")
            print(f"{q_type} QUERIES: {set_color(BLUE, self.query_types[q_type])}", end="")
            print(f"{set_color(MAGENTA, ' ~  ')}", end="")
        else:
            print("\n")

        print(
            f"| {set_color(GREEN, 'Process'):^30} | {set_color(BLUE, 'Interface'):^21} | "
            f"{set_color(MAGENTA, 'IP Version'):^20} | {set_color(MAGENTA, 'Protocol'):^8} | "
            f"{set_color(YELLOW, 'Source IP'):^24} | {set_color(YELLOW, 'Destination IP'):^24} | "
            f"{set_color(CYAN, 'Query Type'):^10} | {set_color(MAGENTA, 'Count'):^5} |"
        )
        print("-" * 122)

        for (ps_name, if_name, ip_ver, ip_proto, ip_src, ip_dst, q_type), count in self.packets.most_common():
            print(
                f"| {ps_name:^21} | {if_name:^12} | {ip_ver:^11} | {ip_proto:^8} |"
                f" {ip_src:^15} | {ip_dst:^15} | {q_type:^10} | {count:^5} |"
            )

    def display_dns_event(self, cpu: int, data: int, size: int) -> None:
        skb_event = self.create_skb_event(size)
        sk = ct.cast(data, ct.POINTER(skb_event)).contents

        try:
            with open(f"/proc/{sk.pid}/comm") as proc_comm:
                proc_name = proc_comm.read().rstrip()
        except OSError:
            try:
                proc_name = sk.comm.decode()
            except AttributeError:
                proc_name = "?"

        if_name = socket.if_indextoname(sk.ifindex)
        ip_version, ip_proto, ip_src, ip_dst, query_type, is_query = self.parse_packet(bytes(sk.raw))
        if is_query:
            if self.tail_mode:
                timestamp = datetime.now().strftime("%H:%M:%S")
                print(f"{timestamp}: query[{query_type}] {proc_name} from {ip_src}")
            else:
                key = (proc_name, if_name, ip_version, ip_proto, ip_src, ip_dst, query_type)
                self.packets[key] += 1
                self.query_types[query_type] += 1
                self.print_stats()

    def start(self) -> None:
        self.bpf_kprobe.attach_kprobe(event=b"tcp_sendmsg", fn_name=b"trace_sendmsg")
        self.bpf_kprobe.attach_kprobe(event=b"udp_sendmsg", fn_name=b"trace_sendmsg")
        BPF.attach_raw_socket(self.bpf_sock.load_func(b"dns_filter", BPF.SOCKET_FILTER), b"")
        self.bpf_sock[b"dns_event_outputs"].open_perf_buffer(self.display_dns_event)

        if self.tail_mode:
            print("Press Ctrl+C to exit\n")
        else:
            self.print_stats()

        while True:
            try:
                self.bpf_sock.perf_buffer_poll()
            except KeyboardInterrupt:
                sys.exit()
