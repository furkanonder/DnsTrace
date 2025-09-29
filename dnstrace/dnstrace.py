from collections import Counter
import ctypes as ct
from datetime import datetime, timezone
import os
from pathlib import Path
import re
import signal
import site
import socket
import struct
import sys
from typing import Any, ClassVar

from dnslib import QTYPE, DNSRecord

from dnstrace.color import printer

UDP_PROTOCOL = 17
TCP_PROTOCOL = 6
DNS_PROTOCOLS = {UDP_PROTOCOL: "UDP", TCP_PROTOCOL: "TCP"}
IP_VERSIONS = {4: "IPv4"}
ETH_LENGTH = 14

FIELD_MAP_FULL = {
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

FIELD_MAP_COMPACT = {
    "Process": (0, "green", 10, "center"),
    "Proto": (3, "magenta", 5, "center"),
    "Source IP": (4, "yellow", 15, "center"),
    "Dest IP": (5, "yellow", 15, "center"),
    "QType": (6, "cyan", 5, "center"),
    "Count": ("count", "magenta", 5, "center"),
}

MIN_TERMINAL_WIDTH = 80
MIN_TERMINAL_HEIGHT = 24
SMALL_SCREEN_WIDTH = 110
QUERY_TYPE_DISTRIBUTION_MAX_WIDTH = 20
# DNS-over-TCP has 2-byte length prefix before the actual DNS message - RFC 1035 Section 4.2.2: "TCP usage"
DNS_TCP_LENGTH_PREFIX = 2

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
        self.packets: Counter[tuple[str, str, str, str, str, str, str, str]] = Counter()
        self.query_types: Counter[str] = Counter()
        self.start_time = datetime.now(timezone.utc).strftime("%H:%M:%S")
        self.tail_mode = tail_mode
        self.show_domain = show_domain
        if not self.tail_mode:
            self.terminal_size_valid = self.check_terminal_size()
            self._setup_signal_handlers()
            self._update_column_configuration()

    @property
    def timestamp(self) -> str:
        return datetime.now().astimezone().strftime("%H:%M:%S")

    @staticmethod
    def hide_cursor() -> None:
        print("\x1b[?25l", end="", flush=True)

    @staticmethod
    def show_cursor() -> None:
        print("\x1b[?25h", end="", flush=True)

    @staticmethod
    def get_terminal_size() -> tuple[int, int]:
        try:
            size = os.get_terminal_size()
            return size.columns, size.lines
        except OSError:
            return 80, 24

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

    def clear_screen(self) -> None:
        self.hide_cursor()
        os.system("cls" if os.name == "nt" else "clear")

    def initialize_columns(self, field_map: dict[str, Any] | None = None) -> list[str]:
        if field_map is None:
            field_map = FIELD_MAP_FULL
        columns = list(field_map.keys())
        if not self.show_domain and "Domain" in columns:
            columns.remove("Domain")
        return columns

    def _update_column_configuration(self) -> None:
        width, _ = self.get_terminal_size()
        if width < SMALL_SCREEN_WIDTH:
            self.field_map = FIELD_MAP_COMPACT
        else:
            self.field_map = FIELD_MAP_FULL
        self.columns = self.initialize_columns(self.field_map)
        self.col_configs = {col: self.field_map[col][1:] for col in self.columns}
        self.column_bases = ["─" * (cfg[1] + 2) for cfg in self.col_configs.values()]
        self.table_width = sum(cfg[1] + 3 for cfg in self.col_configs.values()) - 1

    def _signal_handler(self, signum: int, _frame: Any) -> None:
        if signum == signal.SIGWINCH:
            if self.check_terminal_size():
                self._update_column_configuration()
                self.print_stats()
            else:
                self.display_terminal_size_error()

    def _setup_signal_handlers(self) -> None:
        signal.signal(signal.SIGWINCH, self._signal_handler)

    def check_terminal_size(self) -> bool:
        width, height = self.get_terminal_size()
        return width >= MIN_TERMINAL_WIDTH and height >= MIN_TERMINAL_HEIGHT

    def display_terminal_size_error(self) -> None:
        self.clear_screen()
        printer.error("Terminal size too small:")
        width, height = self.get_terminal_size()
        print(f"Current: Width = {width} Height = {height}")
        print(f"\nNeeded for current config:\nWidth = {MIN_TERMINAL_WIDTH} Height = {MIN_TERMINAL_HEIGHT}")
        printer.warning("Please resize your terminal window and try again.")

    def center_print(self, content: str, color: str | None = None) -> None:
        visible = len(re.sub(r"\x1b\[[0-9;]*m", "", content))
        terminal_width, _ = self.get_terminal_size()
        padding = (terminal_width - visible) // 2
        formatted_content = printer.cformat(content, color) if color else content
        print(f"{' ' * padding}{formatted_content}")

    def center_table(self, content: str) -> str:
        terminal_width, _ = self.get_terminal_size()
        # Remove ANSI color codes to get actual visible length
        visible_length = len(re.sub(r"\x1b\[[0-9;]*m", "", content))
        padding = max(0, (terminal_width - visible_length) // 2)
        return f"{' ' * padding}{content}"

    @staticmethod
    def create_skb_event(size: int) -> type[ct.Structure]:
        class SkbEvent(ct.Structure):
            _fields_: ClassVar = [
                ("ifindex", ct.c_uint32),
                ("pid", ct.c_uint32),
                ("comm", ct.c_char * 64),
                ("raw", ct.c_ubyte * (size - ct.sizeof(ct.c_uint32 * 2) - ct.sizeof(ct.c_char * 64))),
            ]

        return SkbEvent

    def parse_packet(self, raw: bytes) -> tuple[str, str, str, str, str, bool, str]:
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
        if ip_protocol == UDP_PROTOCOL:
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
        elif ip_protocol == TCP_PROTOCOL:
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
            if len(dns_packet) >= DNS_TCP_LENGTH_PREFIX:
                dns_packet = dns_packet[DNS_TCP_LENGTH_PREFIX:]  # Skip the 2-byte length prefix

        # Parse DNS payload
        dns_data = DNSRecord.parse(dns_packet)
        is_query = dns_data.header.qr == 0  # QR bit: 0=Query, 1=Response
        query_type = QTYPE.get(dns_data.q.qtype, f"{dns_data.q.qtype}")
        domain = str(dns_data.q.qname).rstrip(".") if self.show_domain and is_query else ""

        return IP_VERSIONS[ip_version], DNS_PROTOCOLS[ip_protocol], ip_src, ip_dst, query_type, is_query, domain

    def print_stats(self) -> None:
        if not self.check_terminal_size():
            self.display_terminal_size_error()
            return
        self.clear_screen()
        # Header
        self.center_print("DNSTrace [v0.1.0]", "cyan")
        self.center_print(
            f"{printer.cformat(f'Started: {self.start_time}', 'blue')}  "
            f"{printer.cformat(f'Updated: {self.timestamp}', 'yellow')}  "
            f"{printer.cformat(f'Total: {self.packets.total()}', 'green')}",
        )

        # Query Type Distribution
        if self.query_types:
            type_chart = []
            total = max(1, sum(self.query_types.values()))
            for query_type, count in self.query_types.most_common():
                bar = f"{'█' * int((count / total) * QUERY_TYPE_DISTRIBUTION_MAX_WIDTH)}"
                chart_line = (
                    f"{self.format_cell(query_type, 'cyan', 8, 'left')} "
                    f"{self.format_cell(bar, 'magenta', QUERY_TYPE_DISTRIBUTION_MAX_WIDTH, 'left')} "
                    f"{self.format_cell(str(count), 'blue', 6, 'right')}"
                )
                type_chart.append(self.center_table(chart_line))
            print("\n" + "\n".join(type_chart) + "\n")

        table_lines = []
        # Table Headers
        table_top = f"┌{'┬'.join(self.column_bases)}┐"
        table_lines.append(table_top)
        headers = [self.format_cell(col, *self.col_configs[col]) for col in self.columns]
        table_header = f"│ {' │ '.join(headers)} │"
        table_lines.append(table_header)
        # Section Separator
        table_separator = f"├{'┼'.join(self.column_bases)}┤"
        table_lines.append(table_separator)
        # Table Body
        for key, count in self.packets.most_common():
            row = []
            for col in self.columns:
                idx, color, width, align = self.field_map[col]
                value = count if col == "Count" else key[idx]  # type: ignore[call-overload]
                row.append(self.format_cell(f"{value}", color, width, align))
            table_row = f"│ {' │ '.join(row)} │"
            table_lines.append(table_row)
        # Footer
        table_bottom = f"└{'┴'.join(self.column_bases)}┘"
        table_lines.append(table_bottom)

        for line in table_lines:
            print(self.center_table(line))

    def display_dns_event(self, _cpu: int, data: int, size: int) -> None:
        skb_event = self.create_skb_event(size)
        sk = ct.cast(data, ct.POINTER(skb_event)).contents

        try:
            with Path(f"/proc/{sk.pid}/comm").open() as proc_comm:
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
                domain = f" ({domain})" if self.show_domain else ""
                print(
                    f"{printer.cformat(f'{self.timestamp}', 'blue')} "
                    f"{printer.cformat(f'query[{query_type}/{ip_proto}]', 'cyan')} "
                    f"{printer.cformat(f'{proc_name}{domain}', 'green')} "
                    f"{printer.cformat(f'from {if_name} ({ip_src})', 'yellow')}",
                )
            else:
                key = (proc_name, if_name, ip_version, ip_proto, ip_src, ip_dst, query_type, domain)
                self.packets[key] += 1
                self.query_types[query_type] += 1
                self.print_stats()

    def start(self) -> None:
        if not self.tail_mode and not self.check_terminal_size():
            self.display_terminal_size_error()
            return
        self.bpf_kprobe.attach_kprobe(event=b"tcp_sendmsg", fn_name=b"trace_sendmsg")
        self.bpf_kprobe.attach_kprobe(event=b"udp_sendmsg", fn_name=b"trace_sendmsg")
        BPF.attach_raw_socket(self.bpf_sock.load_func(b"dns_filter", BPF.SOCKET_FILTER), b"")
        self.bpf_sock[b"dns_event_outputs"].open_perf_buffer(self.display_dns_event)

        if self.tail_mode:
            self.clear_screen()
            print("Press Ctrl+C to exit")
        else:
            self.print_stats()

        try:
            while True:
                self.bpf_sock.perf_buffer_poll()
        except KeyboardInterrupt:
            self.show_cursor()
            sys.exit()
