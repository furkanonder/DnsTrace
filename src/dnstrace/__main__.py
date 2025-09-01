import argparse
import os
import sys

from dnstrace.dnstrace import DnsTrace

CUR_DIR = os.path.dirname(os.path.abspath(__file__))


def main():
    parser = argparse.ArgumentParser(description="Monitor DNS queries by host processes using eBPF!")
    parser.add_argument("-t", "--tail", action="store_true", help="Stream live DNS queries")
    parser.add_argument("-d", "--domain", action="store_true", help="Show DNS query domains")
    args = parser.parse_args()

    with open(os.path.join(CUR_DIR, "bpf_kprobe.c"), "rb") as f:
        bpf_kprobe = f.read()
    with open(os.path.join(CUR_DIR, "bpf_sock.c"), "rb") as f:
        bpf_sock = f.read()

    if os.geteuid() != 0:
        print("Error: This tool requires root privileges. Please run with sudo.", file=sys.stderr)
        sys.exit(1)

    print("dnstrace is initializing...")
    try:
        with open(os.path.join(CUR_DIR, "bpf_kprobe.c"), "rb") as f:
            bpf_kprobe = f.read()
        with open(os.path.join(CUR_DIR, "bpf_sock.c"), "rb") as f:
            bpf_sock = f.read()
        dns_trace = DnsTrace(bpf_kprobe, bpf_sock, tail_mode=args.tail, show_domain=args.domain)
        dns_trace.start()
    except KeyboardInterrupt:
        print("\ndnstrace stopped by user")
        sys.exit(0)
    except Exception as e:
        print(f"Unexpected error: {e}", file=sys.stderr)
        sys.exit(2)


if __name__ == "__main__":
    main()
