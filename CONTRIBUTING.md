# Contributing to Keysweep

Thank you for your interest in contributing to Keysweep!

Contributions of all kinds are welcome, including bug reports, feature requests, documentation improvements, and code contributions.

## Reporting Bugs

Before opening an issue, please:

- Ensure you're using the latest version.
- Search existing issues to avoid duplicates.
- Include clear steps to reproduce the problem.
- Include your operating system, Rust version, and any relevant logs or error messages.

## Suggesting Features

Feature requests are welcome. Please describe:

- The problem you're trying to solve.
- Your proposed solution.
- Any alternatives you've considered.

## Development Setup

Clone the repository:

```bash
git clone https://github.com/Keysweep/Keysweep.git
cd Keysweep
```

Build the project:

```bash
cargo build
```

Run the test suite:

```bash
cargo test
```

Ensure the code is formatted:

```bash
cargo fmt
```

Run Clippy:

```bash
cargo clippy --all-targets --all-features -- -D warnings
```

## Coding Guidelines

- Follow standard Rust style conventions.
- Keep functions small and focused.
- Prefer clear and descriptive names.
- Avoid unnecessary dependencies.
- Add tests for new functionality whenever practical.
- Document public APIs.

## Pull Requests

Before submitting a pull request, please ensure:

- The project builds successfully.
- All tests pass.
- `cargo fmt` reports no formatting issues.
- `cargo clippy` passes without warnings.
- Your changes are clearly described.

Small, focused pull requests are preferred over large changes.

## Questions

If you have questions or would like to discuss a feature before implementing it, feel free to open an issue.
