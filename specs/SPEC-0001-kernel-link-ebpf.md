---
status: draft
created: 2026-10-11
tags: [ebpf, landlock, lsm, seccomp, verification, priority, kernel]
priority: high
author: Christian M. Todie <chris@todie.io>
champion: Bryan Cantrill
---

# SPEC-0001: Kernel Link eBPF Architecture, Landlock LSM Confinement, and Verification Bounds

## 1. Overview & Machine Sympathy

The `kl` (Kernel Layer Primitives) subsystem provides direct, pure-Rust abstractions for Linux kernel observability and sandboxing:
1. **eBPF Probes & Instrumentation**: In-kernel tracing, network filtering, and zero-copy telemetry.
2. **Landlock LSM Confinement**: Unprivileged, fine-grained filesystem access sandboxing.
3. **Seccomp-BPF Filtering**: Deterministic system call attack surface reduction.
4. **Priority Clamping**: Linux scheduler priority bounds and priority inversion prevention.

Inspired by Bryan Cantrill's systems ethos of machine sympathy, zero-cost abstractions, and radical observability, `kl` enforces a strict architectural boundary:
- **`crates/kl-domain`**: Zero-I/O pure domain models, algebraic state machines, and mathematical verification assertions. It does not touch the filesystem, network, or kernel syscalls (`std::fs`, `std::net`, `tokio`, and `std::process` are forbidden).
- **`crates/kl`**: Systems runtime interface, eBPF attachment helpers, Landlock LSM rule compilation, and scheduler priority clamping.

```
+-------------------------------------------------------------------+
|                        User Applications                          |
+-------------------------------------------------------------------+
                                  |
                                  v
+-------------------------------------------------------------------+
|                            crates/kl                              |
|   (Systems Runtime, eBPF Attachment, Priority Clamper, Enforcers) |
+-------------------------------------------------------------------+
                                  |
                                  v
+-------------------------------------------------------------------+
|                        crates/kl-domain                           |
|       (Zero-I/O Domain Models, Verifier Limits, Invariant FSM)     |
+-------------------------------------------------------------------+
                                  |
                                  v
+-------------------------------------------------------------------+
|                          Linux Kernel                             |
|   [eBPF JIT Engine]   [Landlock LSM]   [Seccomp BPF]   [CFS/RT]   |
+-------------------------------------------------------------------+
```

---

## 2. eBPF Probe Subsystem Specification

### 2.1 Supported Probe Hook Types

`kl` supports the primary Linux kernel eBPF program types:

| Probe Type | Hook Mechanism | Zero-Copy Support | Typical Latency Target |
|---|---|---|---|
| `Kprobe` | Dynamic kernel symbol entry | Yes (via RingBuf) | < 45 ns |
| `Kretprobe` | Dynamic kernel symbol return | Yes (via RingBuf) | < 50 ns |
| `Tracepoint` | Static kernel tracepoint event | Yes (via RingBuf) | < 25 ns |
| `RawTracepoint` | Zero-copy kernel tracepoint hook | Yes (via RingBuf) | < 15 ns |
| `Uprobe` | User-space binary instruction entry | Yes (via RingBuf) | < 70 ns |
| `Uretprobe` | User-space binary return point | Yes (via RingBuf) | < 75 ns |
| `Xdp` | NIC driver packet processing | Native Packet DMA | < 10 ns |
| `SocketFilter` | Network socket packet filtering | Socket buffer view | < 20 ns |
| `CgroupSkb` | Cgroup v2 ingress/egress filtering | Socket buffer view | < 25 ns |
| `Lsm` | Linux Security Module hook | Zero-copy hook context | < 30 ns |

### 2.2 Probe Lifecycle State Machine

Probe execution follows a deterministic finite state machine (`ProbeAttachmentState`):

```
+-----------+       validate()       +-----------+       bpf(PROG_LOAD)      +--------+
| Declared  | ---------------------> | Validated | ------------------------> | Loaded |
+-----------+                        +-----------+                           +--------+
      |                                    |                                      |
      |                                    |                                      v
      |                                    |       bpf_link_create()         +----------+
      |                                    |    +--------------------------> | Attached | <---+
      |                                    |    |                            +----------+     |
      |                                    |    |                                 |           |
      |                                    |    |             detach()            |           | attach()
      |                                    |    |                                 v           |
      |                                    |    |                            +----------+     |
      |                                    |    +--------------------------- | Detached | ----+
      |                                    |                                 +----------+
      |                                    v                                      |
      +----------------------------> +----------+ <-------------------------------+
              close / teardown       | Unloaded |
                                     +----------+
```

### 2.3 Zero-Copy Ring-Buffer Architecture (`BPF_MAP_TYPE_RINGBUF`)

As championed by Sindri, `kl` deprecates legacy per-CPU perf ring buffers (`BPF_MAP_TYPE_PERF_EVENT_ARRAY`) in favor of direct zero-copy memory-mapped ring-buffers (`BPF_MAP_TYPE_RINGBUF`):
1. **Single Memory Mapping**: User space mmaps the producer page, consumer page, and data pages in a single contiguous dual-mapped virtual address region.
2. **Lockless Concurrency**: In-kernel probes allocate space with `bpf_ringbuf_reserve()`, write directly to memory, and commit with `bpf_ringbuf_submit()`.
3. **Zero Bouncing**: No intermediate memory copies occur between kernel probe capture and user-space ring-buffer consumption.
4. **Capacity Constraint**: Ring-buffer capacity must be an exact power of two and a multiple of 4096 bytes (page size) to allow branchless index wrapping via bitwise AND: `pos & (capacity - 1)`.

---

## 3. Landlock LSM Confinement Specification

### 3.1 ABI Evolution Matrix

`kl` targets Linux Landlock LSM ABI versions V1 through V5:

| ABI Version | Linux Kernel | Distinct Capabilities Handled |
|---|---|---|
| **V1** | 5.13+ | Basic FS rights: ReadFile, ReadDir, WriteFile, Execute, MakeDir, MakeReg, RemoveFile, RemoveDir |
| **V2** | 5.19+ | Added `LANDLOCK_ACCESS_FS_REFER` (cross-directory file renaming/hardlinking) |
| **V3** | 6.2+ | Added `LANDLOCK_ACCESS_FS_TRUNCATE` (explicit truncation rights enforcement) |
| **V4** | 6.7+ | Added network port controls (`BIND_TCP`, `CONNECT_TCP`) |
| **V5** | 6.10+ | Added `LANDLOCK_ACCESS_FS_IOCTL_DEV` (character and block device ioctls) |

### 3.2 Inviolable Path Confinement Rules (Idunn's Invariant)

To guarantee that sandboxed processes cannot inspect host memory, leak credentials, or escape sandboxes, `kl` enforces strict security constraints on all path rules:
1. **Absolute Ban on `/proc` Traversal**:
   - Access to `/proc` or any subpath (e.g. `/proc/$pid/mem`, `/proc/kcore`, `/proc/kallsyms`, `/proc/sys`) is strictly forbidden.
   - Any path rule targeting `/proc` fails domain validation immediately (`DomainError::ProhibitedPathRule`).
2. **System Mount Write Prohibition**:
   - Write access, node creation, or file deletion under `/sys` is forbidden.
3. **Raw Device Creation Ban**:
   - Sandboxed tasks cannot create character (`MakeChar`) or block (`MakeBlock`) devices.
4. **Mandatory `PR_SET_NO_NEW_PRIVS`**:
   - Before applying any ruleset, `prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)` is strictly enforced to prevent privilege escalation via setuid binaries.

---

## 4. Seccomp-BPF System Call Filtering

`kl` integrates classic seccomp-BPF filtering to enforce least privilege:
- **Default Action**: Strict fail-closed policy (`SECCOMP_RET_KILL_PROCESS` or `SECCOMP_RET_ERRNO(EPERM)`).
- **Architecture Validation**: Mandatory audit architecture check (`AUDIT_ARCH_X86_64`, `AUDIT_ARCH_AARCH64`, or `AUDIT_ARCH_RISCV64`) at the entry of the BPF filter program to defeat cross-architecture ABI attacks.
- **Argument Inspection**: Multi-argument evaluation with relational operators (`Eq`, `Ne`, `Gt`, `Ge`, `Lt`, `Le`, and `MaskedEq`).
- **Program Complexity Bound**: Filter programs must not exceed 4096 classic BPF instructions (`BPF_MAXINSNS`).

---

## 5. Verification Bounds & Execution Limits

To ensure machine sympathy and avoid crashing or stalling host kernels, `kl-domain` verifies all structures against hard kernel limits:

| Parameter | Kernel Ceiling | `kl` Invariant Enforcement | Rationale |
|---|---|---|---|
| **Max Instructions** | 1,000,000 | `VerifierBounds::max_instructions` | BPF verifier complexity limit (Linux 5.2+) |
| **Max Stack Size** | 512 bytes | `VerifierBounds::max_stack_bytes` | Hardware verifier fixed execution frame limit |
| **Tail Call Depth** | 33 | `VerifierBounds::max_tail_call_depth` | Kernel call stack overflow prevention |
| **Probe Latency Budget** | 50 ns | `PriorityClamp::latency_budget_ns` | Thjalfi's overhead budget (< 50ns CPU cycle budget) |
| **RingBuf Capacity** | 2^30 bytes | Power-of-two, >= 4096 bytes | Page-aligned bitwise index mask arithmetic |
| **Seccomp Instructions** | 4096 insns | `SeccompFilterDescriptor::validate()` | Classic BPF filter size ceiling |

---

## 6. Priority Clamping & Inversion Guardrails

### 6.1 Scheduler Bounds

Thread priorities are clamped to valid Linux scheduler domains:
- **CFS Nice Level**: Clamped within `[-20, 19]`.
- **Realtime FIFO/RR**: Clamped within `[1, 99]`.
- **Latency Budget**: Measured probe execution cycles must not exceed 50ns.

### 6.2 Priority Inversion Prevention (Loki's Hazard)

When probes write into a shared ring-buffer, priority inversions present severe hazards:
- **Hazard**: An in-kernel probe executing in realtime context (`SCHED_FIFO` priority 90) writes events into a ring-buffer whose user-space consumer thread runs under default CFS (`SCHED_OTHER`, nice 0).
- **Outcome**: The consumer is starved of CPU cycles by other workloads, causing ring-buffer exhaustion and dropped kernel events.
- **Guardrail**: `PriorityInversionGuard::check_producer_consumer` detects this condition during domain validation and returns `DomainError::PriorityInversionHazard`. Ring-buffer consumer thread priority must equal or exceed producer realtime priority.

---

## 7. Adversarial Analysis & Threat Model

| Attack Vector | Threat Scenario | Mitigation in `kl` |
|---|---|---|
| **Map Injection Attack** | Attacker writes corrupted state into shared BPF maps to alter control flow. | Gullveig's finite state machine enforces atomic lifecycle transitions (`Declared -> Allocated -> Verified -> Active -> Drained -> Closed`). |
| **Memory Snooping via `/proc`** | Sandboxed process accesses `/proc/$pid/mem` or `/proc/kcore` to read secrets. | Idunn's Landlock rule forbids `/proc` traversal at the LSM inode layer. |
| **Spectre v1 Speculative Read** | Speculative execution bounds bypass in eBPF array lookups. | Enforces array index sanitization and BPF JIT constant blinding. |
| **CPU Starvation Inversion** | Low-priority worker thread causes probe event drops. | `PriorityInversionGuard` requires consumer RT priority to match or exceed probe priority. |
| **TOCTOU Path Race** | Attacker moves a directory tree while path resolution occurs. | Landlock operates on directory file descriptors (`O_PATH`), immune to rename races. |

---

## 8. Acceptance Criteria & Verification Gates

1. **Zero-I/O Invariant**: `crates/kl-domain` contains zero imports or references to `std::net`, `std::fs`, `tokio`, or `std::process`. Verified by `make smoke`.
2. **Host Throttling**: All builds, tests, and CI invocations pass `-j 2`.
3. **Full Pipeline Pass**:
   - `make fmt-check` exits 0.
   - `make clippy` exits 0 with warnings treated as errors (`-D warnings`).
   - `make test` runs all unit and integration tests cleanly.
   - `make smoke` compiles `kl` and proves the zero-I/O boundary.
