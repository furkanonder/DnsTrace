<div align="center">
  <h2>DnsTrace</h2>
  <h3> Monitor DNS queries by host processes using eBPF!</h3>
  <a href="https://github.com/furkanonder/dnstrace/issues"><img alt="GitHub issues" src="https://img.shields.io/github/issues/furkanonder/dnstrace"></a>
  <a href="https://github.com/furkanonder/dnstrace/stargazers"><img alt="GitHub stars" src="https://img.shields.io/github/stars/furkanonder/dnstrace"></a>
  <a href="https://github.com/furkanonder/dnstrace/blob/main/LICENSE"><img alt="GitHub license" src="https://img.shields.io/github/license/furkanonder/dnstrace"></a>
  <a href="https://pepy.tech/project/dnstrace"><img alt="Downloads" src="https://pepy.tech/badge/dnstrace"></a>
</div>

![Demo](assets/demo.gif)

## Quick Start

### Prerequisites

DnsTrace requires BCC (BPF Compiler Collection) to be installed on your system. Follow the [BCC installation guide](https://github.com/iovisor/bcc/blob/master/INSTALL.md) for your Linux distribution.

### Installation

Install DnsTrace using pipx:

```bash
pipx install dnstrace
```

### Usage

Run DnsTrace with root privileges:

```bash
sudo dnstrace
```

#### Command Line Options

```bash
sudo dnstrace [OPTIONS]

Options:
  -t, --tail     Stream live DNS queries (tail mode)
  -d, --domain   Show DNS query domains
  -h, --help     Show help message
```

#### Examples

**Basic monitoring:**
```bash
sudo dnstrace
```

**Stream live queries:**
```bash
sudo dnstrace --tail
```

**Show domains with live-streaming:**
```bash
sudo dnstrace --tail --domain
```

## 📊 Display Modes

### Table Mode (Default)
- Real-time statistics dashboard
- Query type distribution charts
- Process attribution and interface details
- Responsive column layout

### Tail Mode (`--tail`)
- Live-streaming of DNS queries
- Optional domain display with `--domain` flag
