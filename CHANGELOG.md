# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and
this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - 2025-09-28

### Added

- Tail mode (`--tail` flag) for streaming live DNS queries
- Domain display option (`--domain` flag) to show DNS query domains
- Modern terminal interface with professional table-based layout
- Dynamic column management that adapts to terminal size
- Visual bar charts for DNS query type distribution
- SIGWINCH signal handler for dynamic terminal resizing
- Responsive design with automatic layout adjustment

### Changed

- Refactored `clear_screen()` to hide cursor before clearing for cleaner display
- Modernized build system with pyproject.toml
- Updated project structure and file organization
- Enhanced error handling with graceful degradation

## [0.1.0] - 2024-10-02

### Added

- Initial release of DnsTrace
- Basic DNS query monitoring using eBPF
- Support for both UDP and TCP DNS queries
- Process name resolution
- Simple terminal output with colored text
- Support for IPv4 DNS queries

[0.2.0]: https://github.com/furkanonder/dnstrace/releases/tag/0.2.0
[0.1.0]: https://github.com/furkanonder/dnstrace/releases/tag/0.1.0
