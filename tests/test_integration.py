import os
import select
import shutil
import subprocess
import time

import pytest


@pytest.mark.skipif(os.geteuid() != 0, reason="Test requires root privileges")
@pytest.mark.skipif(not shutil.which("ip"), reason="Test requires ip tool")
@pytest.mark.skipif(not shutil.which("dig"), reason="Test requires dig tool")
class TestDnsTraceIntegration:
    TIMEOUT = 2
    TEST_CASES = [
        ("localhost", "A", "udp"),
        ("example.com", "A", "tcp"),
        ("google.com", "AAAA", "udp"),
        ("1.1.1.1", "AAAA", "tcp"),
    ]

    @pytest.fixture(scope="class")
    def dns_server(self):
        with open("/etc/resolv.conf") as f:
            servers = [line.split()[1] for line in f if line.startswith("nameserver")]
            if not servers:
                pytest.skip("No DNS servers configured")
            return servers[0]

    def _generate_dns_query(self, dns_server: str, domain: str, record_type: str = "A", protocol: str = "udp") -> None:
        cmd = ["dig", f"@{dns_server}", domain, record_type, "+short"]
        if protocol.lower() == "tcp":
            cmd.append("+tcp")

        try:
            subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=self.TIMEOUT)
        except subprocess.CalledProcessError as e:
            pytest.fail(f"DNS query failed: {e}")

    @pytest.fixture(autouse=True)
    def dnstrace_process(self):
        proc = None
        try:
            proc = subprocess.Popen(
                ["python", "-u", "-m", "dnstrace", "-t", "-d"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,
            )
            time.sleep(self.TIMEOUT * 3)
            yield proc
        finally:
            if proc:
                proc.terminate()
                proc.wait(timeout=self.TIMEOUT)
                proc.stdout.close()
                proc.stderr.close()

    @pytest.mark.parametrize("test_domain, record_type, protocol", TEST_CASES)
    def test_dns_query_capture(self, dnstrace_process, dns_server, test_domain, record_type, protocol):
        self._generate_dns_query(dns_server, test_domain, record_type, protocol)

        # Expected pattern: "query[TYPE/PROTOCOL]"
        expected_marker = f"query[{record_type}/{protocol.upper()}]"
        domain_marker = f"({test_domain})"

        buffer = ""
        start_time = time.time()

        while time.time() - start_time < self.TIMEOUT:
            # Check for readable output every 200ms
            rlist, _, _ = select.select([dnstrace_process.stdout], [], [], 0.2)
            if rlist:
                try:
                    chunk = os.read(dnstrace_process.stdout.fileno(), 4096).decode(errors="replace")
                    buffer += chunk
                    while "\n" in buffer:
                        line, buffer = buffer.split("\n", 1)
                        if expected_marker in line and domain_marker in line:
                            return
                except (OSError, ValueError):
                    break
            if dnstrace_process.poll() is not None:
                stderr = dnstrace_process.stderr.read()
                pytest.fail(f"DNSTrace crashed:\n{stderr}")

        pytest.fail(
            f"DNS {protocol.upper()} query not detected\n"
            f"Expected: {expected_marker} and {domain_marker}\n"
            f"Output buffer:\n{buffer}\n"
            f"Errors:\n{dnstrace_process.stderr.read()}"
        )
