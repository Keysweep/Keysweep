# Keysweep

A fast, modular security testing toolkit written in Rust.

Keysweep combines three core capabilities into a single CLI:

- Bruteforcing – Test credentials against authentication endpoints.
- Fuzzing – Discover hidden files, directories, parameters, and endpoints.
- Hash Cracking – Verify or recover passwords using wordlists and multiple hash formats.

Designed with performance, concurrency, and extensibility in mind.

## Features

- High-performance multithreaded engine
- Modular architecture
- Multiple protocol login bruteforcing
- Fuzzing with multiple FUZZ keywords
- Wordlist-based hash cracking
- Cross-platform (Windows, Linux, macOS)

More modules and protocols are planned.

## Installation

### Prerequisites

- Rust 1.70 or later ([Install Rust](https://www.rust-lang.org/tools/install))
- Cargo (comes with Rust)

### Build from Source

```bash
git clone https://github.com/Keysweep/Keysweep.git
cd Keysweep
cargo build --release
```

The compiled binary will be located at `target/release/keysweep`.

## Usage

Keysweep provides built-in documentation for every command.

- keysweep --help
- keysweep login --help
- keysweep fuzz --help
- keysweep hash --help

## Dependencies

- **clap** - Command-line argument parsing
- **reqwest** - HTTP client
- **crossbeam-channel** - Multi-threaded communication
- **bcrypt** - Bcrypt hashing
- **sha1, sha2** - SHA algorithms
- **md-5, md4** - MD algorithms
- **hmac** - HMAC authentication
- **hex** - Hex encoding/decoding
- **indicatif** - Progress bars
- **sha-crypt** - SHA crypt password hashing
- **rand** - Random number generation
- **encoding_rs** - Character encoding

Contributions are welcome! Please feel free to submit pull requests or open issues for bugs and feature requests.

## Disclaimer

Keysweep is intended for authorized security testing, research, and educational purposes only. You are responsible for ensuring you have permission to test any target system.

## License

This code is licensed under the MIT license
