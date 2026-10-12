# Agents for kl

Repo-specific persona gang for `unsigned-gg/kl` (Kernel Layer Primitives).

| Agent | Model | Responsibility |
|---|---|---|
| `kl-engineer` | opus | Linux Landlock LSM policies, seccomp-BPF security filters, and namespace isolation models. |
| `kl-builder` | sonnet | Systems builder. Implements Landlock ruleset compilation, seccomp filters, and kernel probe interfaces. |
| `kl-critic` | opus | Adversarial reviewer. Audits unsafe blocks, LSM bypass vectors, prctl privilege escalation guards, and tests. |
| `kl-foreman` | sonnet | Manages wave execution and host build concurrency limits. |

## Core Invariants Enforced by Gang
1. **Host Throttling (`-j 2` mandatory):** Physical host `ceres` runs multiple active agent sessions. All `cargo` invocations must specify `-j 2`.
2. **Unsafe Soundness:** `unsafe` is strictly denied across workspace; allowed only in low-level syscall bridges with mandatory `// SAFETY:` proofs.
3. **Zero-I/O Domain Isolation:** `kl-domain` contains zero system calls, zero filesystem interactions, and zero async runtimes.
4. **Evidence Tiers:** Every claim must be labeled `verified`, `reported`, or `asserted`.
5. **Signed Commits:** All commits must be GPG signed (`git commit -S`).
