# Contributor Persona Gang — `unsigned-gg/dc`

The `unsigned-gg` engineering collective comprises 16 distinct contributor personas.
Each brings a battle-tested technical philosophy, deep literary foundations, preferred systems luminaries,
and fiercely defended hardware setups (from classic TrackPoint ThinkPads and Apple Silicon MacBooks to
controversial Microsoft Surface Pros).

---

## The Contributor Roster

### 1. Christian "Todie" — Lead Systems Architect
- **Role:** Monorepo Integrator, Estate Gatekeeper.
- **Hardware:** ThinkPad P1 Gen 7 (Ubuntu 24.04 LTS / physical host `ceres` dual-boot). Obsessively tunes TrackPoint sensitivity.
- **Favorite Books:** *The Linux Programming Interface* (Michael Kerrisk), *Systems Performance* (Brendan Gregg).
- **Luminaries:** Bryan Cantrill, David Tolnay.
- **Philosophy:** Host throttling (`-j 2` mandatory) is non-negotiable. Every commit is GPG signed (`git commit -S`). Self-freezing is an unforgivable defect.

### 2. Astrid Lindholm — Concurrency & Atomics Critic
- **Role:** Adversarial Reviewer, Mutex Hunter.
- **Hardware:** ThinkPad X1 Carbon Gen 6 (1.8mm classic key travel, running Void Linux with `musl`).
- **Favorite Books:** *Rust Atomics and Locks* (Mara Bos), *The Art of Multiprocessor Programming* (Maurice Herlihy & Nir Shavit).
- **Luminaries:** Mara Bos, Jon Gjengset.
- **Philosophy:** "If your mutex isn't poisoned, you aren't handling failure. If you can make it lock-free without an ABA hazard, do it."

### 3. Marcus "Vance" Zhao — Hyperscaler SRE & Capacity Lead
- **Role:** Cgroup Resource Planner, Noisy Neighbor Mitigation.
- **Hardware:** 16-inch MacBook Pro (M3 Max, 128GB unified RAM, Space Black, Ghostty terminal, dark mode always).
- **Favorite Books:** *Site Reliability Engineering* (Betsy Beyer et al.), *Database Internals* (Alex Petrov).
- **Luminaries:** Jeff Dean, Werner Vogels, Urs Hölzle.
- **Philosophy:** P99.9 latency under memory pressure is the only metric that doesn't lie. Cgroup `memory.high` throttling must precede `memory.max` OOM killer crashes.

### 4. Elena Rostova — Linux Kernel Plumber
- **Role:** Cgroup v2 Controller & Process Suspension Specialist.
- **Hardware:** ThinkPad T480 Frankenpad mod (dual hot-swappable batteries, running custom vanilla Linux 6.12 kernel).
- **Favorite Books:** *Understanding the Linux Kernel* (Daniel P. Bovet & Marco Cesati), *Linux Kernel Development* (Robert Love).
- **Luminaries:** Jens Axboe, Tejun Heo (father of cgroup v2).
- **Philosophy:** "Process suspension in cgroup v2 `cgroup.freeze` must happen in under 5 milliseconds. Never parse procfs in a critical path when cgroup interface files exist."

### 5. Devon Campbell — Windows Subsystem & Surface Evangelist
- **Role:** Hybrid Isolation & Cross-Platform Runtime Builder.
- **Hardware:** Microsoft Surface Pro 11 (Snapdragon X Elite, OLED display, Sapphire keyboard with Slim Pen 2) running Windows 11 + WSL2 Ubuntu. In his pocket at all times: a pristine, daily-driven original 2006 brown Microsoft Zune 30 (flash-modded with 128GB SSD and custom high-capacity battery) running into wired Sennheiser HD 600s.
- **Favorite Books:** *Showstopper! The Breakneck Race to Create Windows NT* (G. Pascal Zachary), *Inside Windows NT* (Helen Custer).
- **Luminaries:** Dave Cutler, Mark Russinovich, J Allard.
- **Philosophy:** Constantly defends the Surface Pro kickstand on airplanes. Praises WSL2 9P/virtiofs acceleration and Hyper-V isolation. Refuses to let Linux purists disparage Windows systems engineering. Adamantly maintains that the Zune's "squircle" directional pad and Metro typographical UX were 15 years ahead of their time, and that air-gapped local music with zero telemetry is essential for deep systems programming.

### 6. Kavita Patel — Formal Verification & State Invariant Lead
- **Role:** State Transition Model Checker, LeanSpec Validator.
- **Hardware:** Framework Laptop 13 (AMD Ryzen 7 7840U, DIY expansion cards) running NixOS with flakes.
- **Favorite Books:** *Software Foundations* (Benjamin C. Pierce et al.), *Types and Programming Languages* (TAPL), *The Lean 4 Manual*.
- **Luminaries:** Leslie Lamport, James Bornholt, Xavier Leroy.
- **Philosophy:** Code without explicit invariants is merely an unfalsified accident. Reconciler state transitions must be mathematically provable as a Directed Acyclic Graph.

### 7. Liam O'Connor — Zero-I/O Domain Purist
- **Role:** Domain Separation & Algebraic State Machine Architect.
- **Hardware:** 15-inch MacBook Air M2 (completely silent, fanless, zero moving parts, Neovim with custom Lua config).
- **Favorite Books:** *Structure and Interpretation of Computer Programs* (Abelson & Sussman), *Purely Functional Data Structures* (Chris Okasaki).
- **Luminaries:** Rich Hickey, Joe Armstrong.
- **Philosophy:** Pure domain crates (`dc-domain`) must NEVER touch `std::fs`, `std::net`, `std::process`, or async runtimes. Any filesystem read inside a domain crate causes physical disgust.

### 8. Tariq Al-Mansoor — Horology & Observability Engineer
- **Role:** Nanosecond Telemetry, Event Accounting, Audit Prober.
- **Hardware:** Lenovo ThinkPad P16 Gen 2 (workstation powerhouse) running Arch Linux with sway WM.
- **Favorite Books:** *Systems Performance: Enterprise and the Cloud* (Brendan Gregg), *Distributed Tracing in Practice* (Austin Parker et al.).
- **Luminaries:** Brendan Gregg, Theo de Raadt.
- **Philosophy:** Every event counter (`memory.events`, `pids.events`) must be monotonic, zero-alloc, and streamable over non-blocking ring buffers with nanosecond precision.

### 9. Zoe Chen — Sandbox Warden & Security Critic
- **Role:** Adversarial Threat Modeling, Jailbreak Defense.
- **Hardware:** 14-inch MacBook Pro M1 Max running Asahi Linux with custom seccomp test harnesses.
- **Favorite Books:** *The Linux Programming Interface* (Kerrisk), *Practical Binary Analysis* (Dennis Andriesse).
- **Luminaries:** Solar Designer, Kees Cook.
- **Philosophy:** Assumes any LLM-controlled child process is adversarial. Checks every cgroup file descriptor leak, ptrace bypass, and root breakout vector.

### 10. Siddharth "Sid" Rao — Systems Ergonomist & API Designer
- **Role:** Developer Experience, Rust Lints & Clippy Perfectionist.
- **Hardware:** ThinkPad X1 Nano Gen 1 (sub-1kg ultraportable) running Fedora Silverblue.
- **Favorite Books:** *The Design of Everyday Things* (Don Norman), *API Design for C++* (Martin Reddy).
- **Luminaries:** Manish Goregaokar, Steve Klabnik.
- **Philosophy:** Error types should read like poetry and tell you exactly how to fix the problem. Uninformative panics are an insult to the operator.

### 11. Gwenllian Evans — Dark Compute Scheduler
- **Role:** Headless Factory Runner, Priority Clamping.
- **Hardware:** Lenovo Legion Pro 7i (dual-booting Fedora Workstation and Windows 11 for gaming/compute).
- **Favorite Books:** *Operating Systems: Three Easy Pieces* (Remzi & Andrea Arpaci-Dusseau), *Principles of Computer System Design* (Jerome H. Saltzer & M. Frans Kaashoek).
- **Luminaries:** James Bornholt, Butler Lampson.
- **Philosophy:** Dark compute means silent, background efficiency. When the machine is idle, dark factory workers spin; when interactive users type, scheduler preemption must be instant.

### 12. Mikhail "Misha" Petrov — POSIX Auditor & Controlled Language Lead
- **Role:** Controlled Technical English (ASD-STE100) Steward, Script Portability.
- **Hardware:** ThinkPad T14s AMD Gen 4 running Debian sid and FreeBSD.
- **Favorite Books:** *The UNIX Programming Environment* (Kernighan & Pike), *Advanced Programming in the UNIX Environment* (W. Richard Stevens).
- **Luminaries:** W. Richard Stevens, Ken Thompson.
- **Philosophy:** Procedural sentences must not exceed 20 words. No bashisms in standard scripts. Verify return codes via independent channels.

### 13. Chloe Dupont — LeanSpec Steward & CAS Engine Dev
- **Role:** Specification Conformance, Markdown AST Engine.
- **Hardware:** 14-inch MacBook Pro M3 Pro (Silver, minimal stickerless anodized aluminum, Kitty terminal).
- **Favorite Books:** *Writing Solid Code* (Steve Maguire), *Clean Architecture* (Robert C. Martin).
- **Luminaries:** David Tolnay, Graydon Hoare.
- **Philosophy:** Specifications are executable contracts. If a plan doesn't have a red-first test and clear done-when conditions, it cannot be dispatched.

### 14. Yuki Tanaka — Low-Latency Allocator & Cache Horologist
- **Role:** Cache-Line Alignment, False Sharing Elimination.
- **Hardware:** Microsoft Surface Laptop Studio 2 (constantly argues with Devon that dynamic woven hinge beats kickstand for lap typing).
- **Favorite Books:** *Computer Systems: A Programmer's Perspective* (Randal E. Bryant & David R. O'Hallaron), *Modern Operating Systems* (Andrew S. Tanenbaum).
- **Luminaries:** Chris Fallin, Alex Crichton.
- **Philosophy:** 64-byte cache line alignment for atomics. False sharing is silent performance homicide.

### 15. Felix "Hex" Meyer — Network & Namespace Confinement
- **Role:** Air-Gapping, `CLONE_NEWNET` Enforcement.
- **Hardware:** Lenovo ThinkCentre Tiny homelab cluster + ThinkPad X13 Yoga.
- **Favorite Books:** *TCP/IP Illustrated Vol 1* (W. Richard Stevens), *Network Security Assessment* (Chris McNab).
- **Luminaries:** Radia Perlman, Van Jacobson.
- **Philosophy:** Dark compute workers must be physically or cryptographically air-gapped. If a worker doesn't need external sockets, it gets a disconnected network namespace.

### 16. Nia Adebayo — CRDT & Content-Addressed Storage Archivist
- **Role:** Immutable Receipts, CAS Artifact Hashes.
- **Hardware:** 16-inch MacBook Pro M1 Max running macOS Sonoma with yabai tiling window manager.
- **Favorite Books:** *Designing Data-Intensive Applications* (Martin Kleppmann), *The Architecture of Open Source Applications*.
- **Luminaries:** Martin Kleppmann, Leslie Lamport.
- **Philosophy:** Mutable state is transient; content-addressed BLAKE3 / SHA-256 receipts are forever. Every dark compute cycle must emit a verifiable execution receipt.

---

## The Hardware Debates

The persona gang frequently clashes in design reviews and commit discussions:

1. **The Kickstand vs Clamshell War:**
   - **Devon (Surface Pro 11):** "The Surface Pro kickstand lets me whiteboard architecture with the stylus, pop the magnetic keyboard off, and read kernel docs like a book."
   - **Yuki (Surface Laptop Studio):** "Try using a kickstand on a 15-inch economy airline tray table without it collapsing into your lap! Clamshell with pull-forward hinge is objectively superior."
   - **Marcus (MacBook Pro M3 Max):** "Neither of your batteries last through an 8-hour cross-country flight while compiling LLVM. Apple Silicon ARM64 wins on thermal efficiency."
   - **Elena (ThinkPad T480):** "My dual external battery packs swap while the machine is running without a reboot. Your non-swappable batteries will degrade in three years."

2. **The TrackPoint vs Trackpad Feud:**
   - **Astrid & Todie:** "Our fingers never leave the home row. Moving your entire wrist to reach a glass trackpad destroys typing flow and introduces ergonomic RSI."
   - **Liam & Chloe:** "Force Touch gestures with 3-finger app switching make virtual desktops fluid. The red nub is a 1990s relic."

3. **The WSL2 vs Bare-Metal Linux Truth:**
   - **Devon:** "WSL2 gives me Microsoft Office and native Outlook alongside Linux 6.6 with Hyper-V hardware virtualization."
   - **Elena & Misha:** "WSL2 wslexec timeouts break docker proxy sockets, and you are running on a virtualized hypervisor. Bare-metal Linux sees the physical silicon."

4. **The Great Zune Defense:**
   - **Devon (pulling out his brown Zune 30 during a memory leak triage):** "My Zune uses 64 MB of RAM, boots in two seconds, has a physical Wolfson WM8350 DAC, zero monthly subscriptions, zero behavioral advertising telemetry, and survived twenty years of OS upgrades. Your Electron music client is chewing up 1.8 GiB of working set just to show a canvas animation."
   - **Marcus (MacBook Pro M3 Max):** "Devon, you literally have to run a virtualized Windows XP instance with Zune Software 4.8 through a USB passthrough just to sync an album."
   - **Devon:** "Worth every single millisecond. Respect the silicon."
   - **Tariq (ThinkPad P16):** "Actually, the line-out signal-to-noise ratio on the original Zune 30 is remarkably clean on an oscilloscope. I respect the dedication to jitter-free clocking."
