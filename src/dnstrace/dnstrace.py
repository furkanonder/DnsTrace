import ctypes as ct
import os
import site
import socket
import struct
import sys
from collections import Counter
from datetime import datetime

from dnslib import QTYPE, DNSRecord

from dnstrace.color import printer

DNS_PROTOCOLS = {17: "UDP", 6: "TCP"}
IP_VERSIONS = {4: "IPv4"}
ETH_LENGTH = 14

FIELD_MAP = {
    "Process": (0, "green", 18, "center"),
    "Interface": (1, "blue", 10, "center"),
    "IP Ver": (2, "magenta", 8, "center"),
    "Proto": (3, "magenta", 5, "center"),
    "Source IP": (4, "yellow", 14, "center"),
    "Dest IP": (5, "yellow", 14, "center"),
    "QType": (6, "cyan", 6, "center"),
    "Domain": (7, "white", 24, "center"),
    "Count": ("count", "magenta", 6, "center"),
}


try:
    version = sys.version_info
    site.addsitedir(f"/usr/lib/python{version.major}.{version.minor}/site-packages")
    site.addsitedir("/usr/lib/python3/dist-packages")
    site.addsitedir(os.path.expandvars("$PYTHON_USER_SITE"))
    from bcc import BPF
except ImportError:
    printer.error("Error: The 'bcc' module is not available.")
    printer.error("For installation instructions, please visit: https://github.com/iovisor/bcc/blob/master/INSTALL.md")
    sys.exit(1)


class DnsTrace:
    def __init__(self, bpf_kprobe: bytes, bpf_sock: bytes, tail_mode: bool = False, show_domain: bool = False) -> None:
        self.bpf_kprobe = BPF(text=bpf_kprobe)
        self.bpf_sock = BPF(text=bpf_sock)
        self.packets: Counter = Counter()
        self.query_types: Counter = Counter()
        self.start_time = datetime.now().strftime("%H:%M:%S")
        self.tail_mode = tail_mode
        self.show_domain = show_domain
        self.columns = self.initialize_columns()

    def initialize_columns(self):
        columns = ["Process", "Interface", "IP Ver", "Proto", "Source IP", "Dest IP", "QType", "Count"]
        if self.show_domain:
            columns.insert(5, "Domain")
        return columns

    @property
    def timestamp(self) -> str:
        return datetime.now().strftime("%H:%M:%S")

    @staticmethod
    def format_cell(value: str, color: str, width: int, align: str) -> str:
        truncated = (value[: width - 3] + "...") if len(value) > width else value
        if align == "left":
            content = truncated.ljust(width)
        elif align == "right":
            content = truncated.rjust(width)
        else:
            content = truncated.center(width)
        return printer.cformat(content, color)

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

    def parse_packet(self, raw: bytes) -> tuple:
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
        domain = str(dns_data.q.qname).rstrip(".") if self.show_domain and is_query else ""

        return IP_VERSIONS[ip_version], DNS_PROTOCOLS[ip_protocol], ip_src, ip_dst, query_type, is_query, domain

    def print_stats(self) -> None:
        os.system("clear")
        print("DNSTrace [v0.1.0]")
        printer.info("START TIME: ", raw_text=f"{self.start_time}", end="\t")
        printer.info("LAST REFRESH: ", raw_text=f"{self.timestamp}", end="\t")
        printer.info("TOTAL QUERIES: ", raw_text=f"{self.packets.total()}")

        for q_type in self.query_types.keys():
            printer.cprint("~ ", color="magenta", raw_text=f"{q_type} QUERIES: ", end="")
            printer.cprint(f"{self.query_types[q_type]}", color="blue", end="")
            printer.cprint(" ~  ", color="magenta", end="")
        else:
            print("\n")

        headers = [self.format_cell(col, *FIELD_MAP[col][1:]) for col in self.columns]
        print(f"│ {' │ '.join(headers)} │")

        for key, count in self.packets.most_common():
            row = []
            for col in self.columns:
                idx, color, width, align = FIELD_MAP[col]
                value = count if col == "Count" else key[idx]
                row.append(self.format_cell(f"{value}", color, width, align))
            print(f"│ {' │ '.join(row)} │")

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
        ip_version, ip_proto, ip_src, ip_dst, query_type, is_query, domain = self.parse_packet(bytes(sk.raw))

        if is_query:
            if self.tail_mode:
                print(f"{self.timestamp}: query[{query_type}/{ip_proto}] {proc_name} ({domain}) from {ip_src}")
            else:
                key = (proc_name, if_name, ip_version, ip_proto, ip_src, ip_dst, query_type, domain)
                self.packets[key] += 1
                self.query_types[query_type] += 1
                self.print_stats()

    def start(self) -> None:
        self.bpf_kprobe.attach_kprobe(event=b"tcp_sendmsg", fn_name=b"trace_sendmsg")
        self.bpf_kprobe.attach_kprobe(event=b"udp_sendmsg", fn_name=b"trace_sendmsg")
        BPF.attach_raw_socket(self.bpf_sock.load_func(b"dns_filter", BPF.SOCKET_FILTER), b"")
        self.bpf_sock[b"dns_event_outputs"].open_perf_buffer(self.display_dns_event)

        if self.tail_mode:
            print("Press Ctrl+C to exit")
        else:
            self.print_stats()

        while True:
            try:
                self.bpf_sock.perf_buffer_poll()
            except KeyboardInterrupt:
                sys.exit()
