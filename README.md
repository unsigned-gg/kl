# kl

> kl (Kernel Layer Primitives)  
> Direct, pure-Rust bindings for Linux Landlock LSM, seccomp BPF syscall filtering, and cgroup v2 resource limits without C runtime dependencies.  
> Dual-licensed under `Apache-2.0 OR MIT`.

## Philosophical Foundations
- **Champion Inspiration:** Bryan Cantrill
- **Zero Days Open Source Initiative (ZOSI):** Machine sympathy, low-level efficiency, and verified contracts.
- **Architecture:** Zero-I/O domain model in `kl-domain` separated from systems runtime in `kl`.

## Crates
- `crates/kl`: Systems implementation and runtime interfaces.
- `crates/kl-domain`: Pure zero-I/O domain models, validation, and algebraic state machines.

## Building
All builds must specify `-j 2` to prevent memory exhaustion on shared multi-agent hosts:
```bash
cargo build -j 2
cargo test -j 2
```
