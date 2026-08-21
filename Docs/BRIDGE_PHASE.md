# Bridge phase — resume compatibility growth on the hardened base

Per the post-Phase-AF master prompt (§4), once Phase AG (allocator
hardening), the hardware-evidence track, and Phase AH (this doc set) land, the
guest-kernel compatibility strategy resumes — now sitting on a meaningfully
more solid foundation: a syscall-boundary-audited, Miri-clean, ASan-clean,
continuously-fuzzed, soak-tested hypervisor instead of a merely-working one.

This document names the **next concrete unclosed item** so growth work starts
after the audit discipline, not before it.

## Why now
Hardening first was always the point: growth work built on an audited
foundation is worth more than the same growth work built on an unaudited one.
The guest-kernel work is exactly the kind of large, security-relevant surface
that benefits most from landing after the audit.

## Where the roadmap stands
- **Phase V (proof of concept):** real BusyBox apps already run inside the
  guest — the existence proof that a guest userspace can be driven by the
  capability-scoped agent. Closed.
- **Phase W / X (deepening what runs inside the guest):** the next unclosed
  work. Concretely, in priority order:
  1. **Broaden the guest app set** beyond the Phase V BusyBox subset —
     identify which real workloads fail today and close the syscalls/ABIs
     they need, each with a contract test (the project's standard: a
     compatibility feature without a regression test is not done).
  2. **Deepen POSIX/Windows projection** as unprivileged translation layers
     that do not expand the TCB (per the architecture's "compatibility via
     projection" principle).
  3. **Attempt a Windows guest** as the stretch milestone — the hardest
     compatibility surface, and the one that most benefits from the
     allocator/SMP/ACPI groundwork now in place.

## Preconditions already satisfied (do not redo)
- Syscall boundary audit (24/24), Miri + ASan in CI, nightly fuzzing with
  real corpus growth, 63.6M-step soak (0 violations).
- Allocator hardening (Phase AG) — see `Docs/THREAT_MODEL.md`.
- Hardware evidence: real MADT (8 LAPICs/4C-8T), 19 real ACPI tables, 44 PCI
  devices through the real parsers; VT-x confirmed firmware-capable (Windows
  blocks, reversible). See `Docs/HARDWARE_EVIDENCE.md`.

## Entry point for the next session
Pick up Phase W/X item 1: enumerate the guest apps that fail, open one issue
per missing syscall/ABI, and land each behind a contract test. Keep the
ground rules: clean lockfiles, full suite, raw output, honest
closed/reduced/inherent, evidence committed, independently-checkable claims
with a verify command.

## Honest status
This bridge phase is a **planning/next-step document**, not a deliverable that
changes code. No guest-kernel growth was performed in this session; the
hardening phases it depends on (AG, hardware evidence, AH) are what were
completed. The first growth change should not start in parallel with those —
they have now finished, so the bridge is unblocked.
