# kl

[![License: Apache-2.0 OR MIT OR CC0-1.0](https://img.shields.io/badge/license-Apache--2.0%20OR%20MIT%20OR%20CC0--1.0-blue.svg)](LICENSE-APACHE)

> **Kernel Layer Primitives — Landlock LSM, seccomp-BPF Syscall Filtering, and Namespace Containment**  
> Pure-Rust Linux container containment interfaces without C runtime or external daemon dependencies.  
> Tri-licensed under `Apache-2.0 OR MIT OR CC0-1.0`.

## Philosophical Foundations & Machine Sympathy
- **Champion Inspiration:** Bryan Cantrill (uncompromising systems observability, machine sympathy, and deterministic kernel boundaries).
- **Substantive Systems Implementation:** Fully functional Landlock LSM ruleset compilation, seccomp-BPF system call filtering, and Linux namespace isolation.
- **Zero-I/O Domain Isolation:** `kl-domain` contains zero system calls, zero filesystem interactions, and zero async runtimes. All ruleset representations, syscall policies, and invariant checks operate on pure memory structures.

## Crate Layout
| Crate | Responsibility |
|---|---|
| `crates/kl-domain` | Pure zero-I/O models: `LandlockAbi`, `PathAccess`, `SeccompProfile`, `SyscallRule`, and `IsolationPlan`. |
| `crates/kl` | Systems runtime and CLI (`kl`): Kernel ABI probing on isolated scratch threads, seccomp-BPF compilation, and namespace containment. |

## CLI Usage

### Probe Host Kernel Capabilities
```bash
# Probe Linux kernel Landlock ABI version and seccomp capabilities
kl probe
```

### Verify Isolation Plan
```bash
# Validate internal consistency and invariants of an isolation plan
kl verify plan.json
```

## Building & Verification
All builds must specify `-j 2` to prevent memory exhaustion on shared hosts:
```bash
cargo check -j 2
cargo test -j 2
```

## License
Licensed under any of:
- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT License ([LICENSE-MIT](LICENSE-MIT))
- CC0 1.0 Universal ([LICENSE-CC0](LICENSE-CC0))

This repository follows the unsigned constitution: [Privacy, Freedom, Dignity](https://github.com/unsigned-gg/.github/blob/main/PRIVACY_FREEDOM_DIGNITY.md) · [Guiding Principles](https://github.com/unsigned-gg/.github/blob/main/GUIDING_PRINCIPLES.md) · [Community Standards](https://github.com/unsigned-gg/.github/blob/main/COMMUNITY_STANDARDS.md) · [Brand Voice](https://github.com/unsigned-gg/.github/blob/main/BRAND_VOICE.md).

## Principles

See the [unsigned-gg principles](https://github.com/unsigned-gg/.github) for the architectural doctrine and community standards.
