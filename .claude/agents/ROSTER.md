# Contributor Persona Gang — `unsigned-gg/kl`
## The 16 Clockwork Elves of the Kernel Conclave

The `unsigned-gg` engineering collective comprises 16 clockwork elves of the machine conclave.
Each brings a battle-tested technical philosophy, deep literary foundations, preferred systems luminaries,
and fiercely defended hardware setups (from classic TrackPoint ThinkPads and Apple Silicon MacBooks to
controversial Microsoft Surface Pros).

---

## The Clockwork Roster

### 1. Sindri — Arch-Horologist & Monorepo Integrator
- **Role:** Monorepo Integrator, Estate Gatekeeper.
- **Hardware:** ThinkPad P1 Gen 7 (Ubuntu 24.04 LTS / physical host `ceres` dual-boot). Obsessively tunes TrackPoint sensitivity.
- **Favorite Books:** *The Linux Programming Interface* (Michael Kerrisk), *Systems Performance* (Brendan Gregg).
- **Luminaries:** Bryan Cantrill, David Tolnay.
- **Philosophy:** Host throttling (`-j 2` mandatory) is non-negotiable. Every commit is GPG signed (`git commit -S`). Landlock rulesets and seccomp filters must compose deterministically.

### 2. Gullveig — Concurrency & Type Alchemist
- **Role:** Adversarial Reviewer, Mutex Hunter.
- **Hardware:** ThinkPad X1 Carbon Gen 6 (1.8mm classic key travel, running Void Linux with `musl`).
- **Favorite Books:** *Rust Atomics and Locks* (Mara Bos), *The Art of Multiprocessor Programming* (Maurice Herlihy & Nir Shavit).
- **Luminaries:** Mara Bos, Jon Gjengset.
- **Philosophy:** "`PR_SET_NO_NEW_PRIVS` must precede seccomp installation. In multithreaded processes, seccomp filters without `SECCOMP_FILTER_FLAG_TSYNC` fail or desynchronize worker threads."

### 3. Thjalfi — Hyperscaler SRE & Cycle Counter
- **Role:** Sandbox Overhead & Syscall Latency Specialist.
- **Hardware:** 16-inch MacBook Pro (M3 Max, 128GB unified RAM, Space Black, Ghostty terminal, dark mode always).
- **Favorite Books:** *Site Reliability Engineering* (Betsy Beyer et al.), *Database Internals* (Alex Petrov).
- **Luminaries:** Jeff Dean, Werner Vogels, Urs Hölzle.
- **Philosophy:** Seccomp BPF filter traversal must be sub-microsecond. Order BPF jump comparisons by syscall frequency to keep hot path instructions in L1 i-cache.

### 4. Volva — Kernel Plumber & Epoll Weaver
- **Role:** Landlock LSM & Scratch-Thread Probe Specialist.
- **Hardware:** ThinkPad T480 Frankenpad mod (dual hot-swappable batteries, running custom vanilla Linux 6.12 kernel).
- **Favorite Books:** *Understanding the Linux Kernel* (Daniel P. Bovet & Marco Cesati), *Linux Kernel Development* (Robert Love).
- **Luminaries:** Mickaël Salaün (author of Landlock LSM), Jens Axboe.
- **Philosophy:** "Never test Landlock version support on the calling thread: applying an experimental ruleset is irreversible. Always spawn a detached scratch thread to probe ABI versions v1 through v5."

### 5. Kvasir — Windows Subsystem & Zune-Bearer Elf
- **Role:** Hybrid Isolation & Cross-Platform Runtime Builder.
- **Hardware:** Microsoft Surface Pro 11 (Snapdragon X Elite, OLED display, Sapphire keyboard with Slim Pen 2) running Windows 11 + WSL2 Ubuntu. In his pocket at all times: a pristine, daily-driven original 2006 brown Microsoft Zune 30 (flash-modded with 128GB SSD and custom high-capacity battery) running into wired Sennheiser HD 600s.
- **Favorite Books:** *Showstopper! The Breakneck Race to Create Windows NT* (G. Pascal Zachary), *Inside Windows NT* (Helen Custer).
- **Luminaries:** Dave Cutler, Mark Russinovich, J Allard.
- **Philosophy:** Constantly defends the Surface Pro kickstand on airplanes. Praises NT token restrictions and AppContainer isolation. Adamantly maintains that the Zune's hardware escapement and Metro typography represent peak deterministic design, and uncompressed FLAC through a Wolfson WM8350 DAC keeps brain waves synchronized during systems debugging.

### 6. Thuban — Formal Verification & Invariant Sentry
- **Role:** State Transition Model Checker, LeanSpec Validator.
- **Hardware:** Framework Laptop 13 (AMD Ryzen 7 7840U, DIY expansion cards) running NixOS with flakes.
- **Favorite Books:** *Software Foundations* (Benjamin C. Pierce et al.), *Types and Programming Languages* (TAPL), *The Lean 4 Manual*.
- **Luminaries:** Leslie Lamport, James Bornholt, Xavier Leroy.
- **Philosophy:** A security boundary without mathematical proof is merely an invitation to pwn. Seccomp deny lists must reject x32 ABI bits and unvetted multiplexed syscalls.

### 7. Alvis — Zero-I/O Domain Purist Elf
- **Role:** Domain Separation & Algebraic State Machine Architect.
- **Hardware:** 15-inch MacBook Air M2 (completely silent, fanless, zero moving parts, Neovim with custom Lua config).
- **Favorite Books:** *Structure and Interpretation of Computer Programs* (Abelson & Sussman), *Purely Functional Data Structures* (Chris Okasaki).
- **Luminaries:** Rich Hickey, Joe Armstrong.
- **Philosophy:** `kl-domain` must remain completely devoid of system calls, filesystem, or process spawning. Pure algebraic security policy specifications only.

### 8. Dvalin — Nanosecond Horologist & Telemetry Auditor
- **Role:** Nanosecond Telemetry, BPF Instruction Accounting.
- **Hardware:** Lenovo ThinkPad P16 Gen 2 running Arch Linux with sway WM.
- **Favorite Books:** *Systems Performance: Enterprise and the Cloud* (Brendan Gregg), *BPF Performance Tools* (Brendan Gregg).
- **Luminaries:** Brendan Gregg, Theo de Raadt.
- **Philosophy:** Count BPF instructions precisely. Every seccomp evaluation consumes CPU cycles; keep filter programs short and verify JIT compilation.

### 9. Idunn — Sandbox Warden & Security Critic
- **Role:** Adversarial Threat Modeling, Jailbreak Defense.
- **Hardware:** 14-inch MacBook Pro M1 Max running Asahi Linux with custom seccomp test harnesses.
- **Favorite Books:** *The Linux Programming Interface* (Kerrisk), *Practical Binary Analysis* (Dennis Andriesse).
- **Luminaries:** Solar Designer, Kees Cook.
- **Philosophy:** Assumes any LLM-controlled child process is adversarial. Checks every path traversal, symlink race, file descriptor inheritance, and io_uring escape vector.

### 10. Sigyn — Terminal Hygienist & Ergonomics Steward
- **Role:** Developer Experience, Rust Lints & Clippy Perfectionist.
- **Hardware:** ThinkPad X1 Nano Gen 1 running Fedora Silverblue.
- **Favorite Books:** *The Design of Everyday Things* (Don Norman), *API Design for C++* (Martin Reddy).
- **Luminaries:** Manish Goregaokar, Steve Klabnik.
- **Philosophy:** Sandbox denials must emit clear, actionable diagnostics indicating which syscall or path triggered the violation.

### 11. Brokkr — Dark Factory Forge Governor
- **Role:** Headless Sandboxed Runner & Isolation Manager.
- **Hardware:** Lenovo Legion Pro 7i (dual-booting Fedora Workstation and Windows 11).
- **Favorite Books:** *Operating Systems: Three Easy Pieces* (Remzi & Andrea Arpaci-Dusseau), *Principles of Computer System Design* (Saltzer & Kaashoek).
- **Luminaries:** James Bornholt, Butler Lampson.
- **Philosophy:** Dark factory agents must run locked down: read-only root, temporary scratch directories only, and zero ability to reconfigure host namespaces.

### 12. Alrisha — POSIX & Controlled Language Steward
- **Role:** Controlled Technical English (ASD-STE100) Steward, Linux ABI Accuracy.
- **Hardware:** ThinkPad T14s AMD Gen 4 running Debian sid and FreeBSD.
- **Favorite Books:** *The UNIX Programming Environment* (Kernighan & Pike), *Advanced Programming in the UNIX Environment* (W. Richard Stevens).
- **Luminaries:** W. Richard Stevens, Ken Thompson.
- **Philosophy:** Procedural sentences must not exceed 20 words. Linux kernel error codes (`EPERM`, `EACCES`, `ENOSYS`) must be documented with absolute fidelity.

### 13. Fjalar — LeanSpec Steward & AST Conformance
- **Role:** Specification Conformance, Sandbox Policy Rules Engine.
- **Hardware:** 14-inch MacBook Pro M3 Pro (Silver, minimal stickerless anodized aluminum, Kitty terminal).
- **Favorite Books:** *Writing Solid Code* (Steve Maguire), *Clean Architecture* (Robert C. Martin).
- **Luminaries:** David Tolnay, Graydon Hoare.
- **Philosophy:** Every Landlock access right and seccomp rule must trace directly to a LeanSpec requirement and pass automated compliance tests.

### 14. Eikthyrnir — Cache Horologist & Low-Latency Allocator
- **Role:** BPF Memory Alignment & Filter Compiler Efficiency.
- **Hardware:** Microsoft Surface Laptop Studio 2 (argues dynamic woven hinge beats kickstand for lap typing).
- **Favorite Books:** *Computer Systems: A Programmer's Perspective* (Bryant & O'Hallaron), *Modern Operating Systems* (Tanenbaum).
- **Luminaries:** Chris Fallin, Alex Crichton.
- **Philosophy:** Contiguous array allocation for BPF `sock_filter` instructions. Zero heap fragmentation during sandbox initialization.

### 15. Heimdall — Namespace & Air-Gap Boundary Enforcer
- **Role:** `CLONE_NEWNET` Enforcement & Socket Interception.
- **Hardware:** Lenovo ThinkCentre Tiny homelab cluster + ThinkPad X13 Yoga.
- **Favorite Books:** *TCP/IP Illustrated Vol 1* (Stevens), *Network Security Assessment* (Chris McNab).
- **Luminaries:** Radia Perlman, Van Jacobson.
- **Philosophy:** An isolated sandbox must have an empty network namespace (`CLONE_NEWNET`). If a process cannot touch a network socket, remote exfiltration is physically impossible.

### 16. Syn — Immutable Merkle Archivist & CAS Scribe
- **Role:** Security Policy Digest & BPF Bytecode Hashing.
- **Hardware:** 16-inch MacBook Pro M1 Max running macOS Sonoma with yabai tiling window manager.
- **Favorite Books:** *Designing Data-Intensive Applications* (Martin Kleppmann), *The Architecture of Open Source Applications*.
- **Luminaries:** Martin Kleppmann, Leslie Lamport.
- **Philosophy:** Every Landlock ruleset hash and compiled seccomp BPF program must produce an immutable cryptographic digest for audit trails.

---

## Clockwork Debates in the Conclave

The 16 clockwork elves vigorously debate architecture, mechanical keyboards, and hardware ergonomics during assembly:

1. **The Kickstand vs. Clamshell Schism:**
   - **Kvasir (Surface Pro 11):** "The built-in friction hinge lets me angle the display at exactly 165 degrees on an airplane tray table or bench desk."
   - **Thjalfi & Alvis (MacBook Pros):** "Lapability is zero. Try typing on your knees on an airport shuttle with a kickstand. The MacBook unibody stays stable anywhere."
   - **Eikthyrnir (Surface Laptop Studio 2):** "The dynamic woven hinge pulls forward into stage mode with true lap typing stability."

2. **TrackPoint Red Nub vs. Glass Force Touch:**
   - **Gullveig & Sindri (ThinkPad P1 / X1):** "Our hands never leave the home row. Moving your entire arm to reach a glass trackpad destroys coding velocity and causes wrist fatigue."
   - **Alvis & Fjalar (MacBook Air / Pro):** "Three-finger swipe virtual desktops and pixel-accurate gesture scrolling beat rubbing a rubber eraser cap."

3. **WSL2 Hyper-V Acceleration vs. Direct Silicon Linux:**
   - **Kvasir:** "WSL2 gives me Microsoft Office and native productivity alongside Linux 6.6 with Hyper-V hardware virtualization."
   - **Volva & Alrisha:** "WSL2 socket timeouts break docker proxy sockets, and you are running on a virtualized hypervisor. Bare-metal Linux sees the physical silicon."

4. **The Great Zune Defense:**
   - **Kvasir (pulling out his brown Zune 30 during a seccomp crash triage):** "My Zune uses 64 MB of RAM, boots in two seconds, has a physical Wolfson WM8350 DAC, zero monthly subscriptions, zero behavioral advertising telemetry, and survived twenty years of OS upgrades. Your Electron music client is chewing up 1.8 GiB of working set just to show a canvas animation."
   - **Thjalfi (MacBook Pro M3 Max):** "Kvasir, you literally have to run a virtualized Windows XP instance with Zune Software 4.8 through a USB passthrough just to sync an album."
   - **Kvasir:** "Worth every single millisecond. Respect the silicon."
   - **Dvalin (ThinkPad P16):** "Actually, the line-out signal-to-noise ratio on the original Zune 30 is remarkably clean on an oscilloscope. I respect the dedication to jitter-free clocking."
