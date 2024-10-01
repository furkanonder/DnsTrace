# DnsTrace
DnsTrace is a tool that identifies DNS queries made by processes on the host.
![Demo](assets/demo.gif)

## Installation
Before installing DnsTrace, you need to install BCC (BPF Compiler Collection) as it is a
dependency for the project. You can find installation instructions [here](https://github.com/iovisor/bcc/blob/master/INSTALL.md).

After installing BCC, you can install DnsTrace using the following command:
```sh
pipx install dnstrace
```

## Running
```sh
sudo dnstrace
```
