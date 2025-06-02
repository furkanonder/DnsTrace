import ctypes as ct
import os
import re
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
QUERY_TYPE_DISTRIBUTION_MAX_WIDTH = 20


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
        self.col_configs = {col: FIELD_MAP[col][1:] for col in self.columns}
        self.column_bases = ["─" * (cfg[1] + 2) for cfg in self.col_configs.values()]
        self.table_width = sum(cfg[1] + 3 for cfg in self.col_configs.values()) - 1

    def initialize_columns(self):
        columns = ["Process", "Interface", "IP Ver", "Proto", "Source IP", "Dest IP", "QType", "Count"]
        if self.show_domain:
            columns.insert(6, "Domain")
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

    def center_print(self, content: str, color: str = None):
        visible = len(re.sub(r"\x1b\[[0-9;]*m", "", content))
        padding = (self.table_width - visible) // 2
        formatted_content = printer.cformat(content, color) if color else content
        print(f"{' ' * padding}{formatted_content}")

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
        # Skip Ethernet header (14 bytes) - ([0-5]: Destination MAC, [6-11]: Source MAC, [12-13]: EtherType)
        ip_packet = raw[ETH_LENGTH:]

        # Unpack IPv4 header using big-endian format
        # Format string "!BBHHHBBH4s4s" breakdown:
        #   !  : Network byte order (big-endian)
        #   B  : 1-byte unsigned char (8 bits)
        #   H  : 2-byte unsigned short (16 bits)
        #   4s : 4-byte byte string
        #
        # IPv4 Header Structure (20 bytes):
        #  0                   1                   2                   3
        #  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
        # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        # |Version|  IHL  |    DSCP/ECN   |         Total Length          | <- B B H
        # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        # |         Identification        |Flags|   Fragment Offset       | <- H H
        # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        # |  Time to Live |   Protocol    |       Header Checksum         | <- B B H
        # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        # |                       Source Address                          | <- 4s
        # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        # |                    Destination Address                        | <- 4s
        # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        #
        # Field mapping to unpacked tuple:
        #   [0]: Byte 0 (Version/IHL)  -> B
        #   [1]: Byte 1 (TOS)          -> B
        #   [2]: Bytes 2-3 (Total Len) -> H
        #   [3]: Bytes 4-5 (ID)        -> H
        #   [4]: Bytes 6-7 (Flags/Frag)-> H
        #   [5]: Byte 8 (TTL)          -> B
        #   [6]: Byte 9 (Protocol)     -> B
        #   [7]: Bytes 10-11 (Checksum)-> H
        #   [8]: Bytes 12-15 (Src IP)  -> 4s
        #   [9]: Bytes 16-19 (Dst IP)  -> 4s
        ip_header = struct.unpack("!BBHHHBBH4s4s", ip_packet[:20])

        # Extract protocol number
        ip_protocol = ip_header[6]
        # Extract IP version (upper 4 bits of first byte)
        ip_version = ip_header[0] >> 4

        # Convert binary IP addresses to string format
        ip_src = socket.inet_ntoa(ip_header[8])  # Bytes 12-15: Source IP
        ip_dst = socket.inet_ntoa(ip_header[9])  # Bytes 16-19: Destination IP

        # Calculate IP header length (IHL field in 32-bit words)
        header_len = ip_header[0] & 0x0F  # Get IHL (lower 4 bits of first byte)
        header_len = header_len * 4  # Convert to bytes

        # Process UDP packets (DNS over UDP)
        if ip_protocol == 17:
            # UDP Header Structure (8 bytes) - RFC 768:
            #  0                   1                   2                   3
            # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            # |          Source Port          |       Destination Port        |
            # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            # |            Length             |           Checksum            |
            udp_packet = ip_packet[header_len:]  # Skip IP header
            # Skip UDP header - [Src Port (2)] [Dst Port (2)] [Length (2)] [Checksum (2)]
            dns_packet = udp_packet[8:]
        # Process TCP packets (DNS over TCP)
        elif ip_protocol == 6:
            # Skip IP header to get TCP packet
            tcp_packet = ip_packet[header_len:]

            # TCP Header Structure (20 bytes minimum):
            #  0                   1                   2                   3
            # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            # |          Source Port          |       Destination Port        |
            # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            # |                        Sequence Number                       |
            # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            # |                     Acknowledgment Number                     |
            # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            # |  Data |           |U|A|P|R|S|F|
            # | Offset| Reserved  |R|C|S|S|Y|I|            Window
            # |       |           |G|K|H|T|N|N|
            # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

            # Data Offset (TCP header length) is in upper 4 bits of byte 12
            tcp_header_len = (tcp_packet[12] >> 4) * 4  # Convert 32-bit words to bytes
            dns_packet = tcp_packet[tcp_header_len:]  # Skip TCP header

            # DNS-over-TCP has 2-byte length prefix before the actual DNS message - RFC 1035 Section 4.2.2: "TCP usage"
            if len(dns_packet) >= 2:
                dns_packet = dns_packet[2:]  # Skip the 2-byte length prefix

        # Parse DNS payload
        dns_data = DNSRecord.parse(dns_packet)
        is_query = dns_data.header.qr == 0  # QR bit: 0=Query, 1=Response
        query_type = QTYPE.get(dns_data.q.qtype, f"{dns_data.q.qtype}")
        domain = str(dns_data.q.qname).rstrip(".") if self.show_domain and is_query else ""

        return IP_VERSIONS[ip_version], DNS_PROTOCOLS[ip_protocol], ip_src, ip_dst, query_type, is_query, domain

    def print_stats(self) -> None:
        os.system("cls" if os.name == "nt" else "clear")
        # Header
        self.center_print("DNSTrace [v0.1.0]", "cyan")
        self.center_print(
            f"{printer.cformat(f'Started: {self.start_time}', 'blue')}  "
            f"{printer.cformat(f'Updated: {self.timestamp}', 'yellow')}  "
            f"{printer.cformat(f'Total: {self.packets.total()}', 'green')}"
        )

        # Query Type Distribution
        type_chart = []
        total = max(1, sum(self.query_types.values()))
        for query_type, count in self.query_types.most_common():
            bar = f"{'█' * int((count / total) * QUERY_TYPE_DISTRIBUTION_MAX_WIDTH)}"
            type_chart.append(
                f"{self.format_cell(query_type, 'cyan', 8, 'left')} "
                f"{self.format_cell(bar, 'magenta', QUERY_TYPE_DISTRIBUTION_MAX_WIDTH, 'left')} "
                f"{self.format_cell(str(count), 'blue', 6, 'right')}"
            )
        print(f"\n{'\n'.join(type_chart)}\n")

        # Table Headers
        print(f"┌{'┬'.join(self.column_bases)}┐")
        headers = [self.format_cell(col, *self.col_configs[col]) for col in self.columns]
        print(f"│ {' │ '.join(headers)} │")

        # Section Separator
        print(f"├{'┼'.join(self.column_bases)}┤")

        # Table Body
        for key, count in self.packets.most_common():
            row = []
            for col in self.columns:
                idx, color, width, align = FIELD_MAP[col]
                value = count if col == "Count" else key[idx]
                row.append(self.format_cell(f"{value}", color, width, align))
            print(f"│ {' │ '.join(row)} │")

        # Footer
        print(f"└{'┴'.join(self.column_bases)}┘")

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
