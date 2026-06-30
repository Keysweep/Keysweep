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

### 1. Fork the repository

Click Fork on GitHub to create your own copy of the repository.

### 2. Clone your fork

```bash
git clone https://github.com/<your-username>/Keysweep.git
cd Keysweep
```

### 3. Add the upstream remote

This lets you keep your fork up to date.

```bash
git remote add upstream https://github.com/Keysweep/Keysweep.git
```

Verify:

```bash
git remote -v
```

You should see both origin and upstream.

### 4. Create a Branch

Never work directly on main.

Create a branch for your changes:

```bash
git checkout -b feature/my-awesome-feature
```

Examples:

- feature/add-jwt-login
- feature/improve-wordlist-parser
- fix/windows-output
- docs/update-readme
- refactor/hash-engine

### 5. Make Your Changes

Keep your changes focused on a single issue or feature.

If possible:

- Write clean, idiomatic Rust.
- Add comments only when they improve understanding.
- Keep functions small and easy to read.
- Update documentation when behavior changes.

### 6. Verify Everything Works

Before committing, run:

```bash
cargo fmt
cargo clippy --all-targets --all-features -- -D warnings
cargo test
```

If your change affects the CLI, it's also a good idea to test it manually.

### 7. Commit Your Changes

Write clear commit messages.

Good examples:

- feat: add NTLM authentication support
- fix: handle empty hash input
- docs: improve installation instructions
- refactor: simplify scheduler

Avoid vague messages like:

- fix
- update
- changes
- stuff

### 8. Keep Your Branch Up to Date

Before opening a Pull Request:

```bash
git fetch upstream
git rebase upstream/main
```

Resolve any conflicts if necessary.

### 9. Push Your Branch

```bash
git push origin feature/my-awesome-feature
```

### 10. Open a Pull Request

Open a Pull Request against the main branch.

Please include:

- A clear description of what changed.
- Why the change was made.
- Any related issue (for example: Closes #42).
- Screenshots or terminal output if relevant.

### 11. Pull Request Checklist

Before submitting, make sure:

- The project builds successfully.
- `cargo fmt` passes.
- `cargo clippy --all-targets --all-features -- -D warnings` passes.
- `cargo test` passes.
- Documentation has been updated if necessary.
- Your changes are focused on a single issue or feature.

## Coding Guidelines

- Follow standard Rust style conventions.
- Keep functions small and focused.
- Prefer clear and descriptive names.
- Avoid unnecessary dependencies.
- Add tests for new functionality whenever practical.
- Document public APIs.

## Questions

If you have questions or would like to discuss a feature before implementing it, feel free to open an issue.

Thank you for contributing to Keysweep!
