# Aegis — Next Master Prompt (post Phase AF)

*Repo: github.com/Ashura-asura/Pointless_OS. Current verified state:
`ac0d22f` — syscall boundary audit (24/24), Miri + ASan both in CI,
continuous nightly fuzzing with real corpus growth (1,872 new inputs
verified in one run), 63.6M-step chaos/soak with 0 violations. This
document is self-contained.*

---

## 0. What's actually left, and why this order

Four of six hardening phases from the prior prompt are done, fast and
well-verified — don't repeat them. What's left:

- **Phase AG (allocator hardening)** and **Phase AH (process docs)** —
  the two hardening phases not yet started.
- **The hardware-evidence track** — entirely untouched. Given the
  "one continuously-running laptop, no other hardware" constraint, this
  is real, cheap, currently-missing evidence — do it now, not later.
- **A bridge back to compatibility growth** — with hardening this far
  along, it's now safe to resume Track A (the guest-kernel strategy)
  without that work sitting on a less-audited foundation.

Order: **AG then the hardware-evidence track (parallel-safe with AG)
then AH then the bridge phase.** AH goes last on purpose — a threat
model document is more accurate written after AG's allocator work and
the hardware evidence exist, not before.

Ground Rules unchanged: clean lockfiles, full suite, raw output in
commits, count totals yourself, stop on failure, closed/reduced/
inherent stated honestly, evidence committed not left local-only,
independently-checkable claims shown with the command to verify them.

---

## 1. Phase AG — Allocator and core-data-structure hardening

Not yet started. Still the right next code-level phase — Miri (Phase
AD) already validates memory-safety logic where it can be host-tested,
but the frame allocator and any custom heap/arena code are exactly the
subsystem class where Phase AD's own methodology (host-testable
extraction, Miri, targeted fuzzing) hasn't been specifically pointed
yet.

1. Audit the frame allocator (and any bump/arena allocators used
   elsewhere in the kernel) for: double-free detection, allocation-size
   sanity checks against actually-available memory before committing
   (the frame-bitmap fix from earlier this project's history already
   established this discipline for one code path — extend it
   everywhere memory is handed out, not just where it was already
   fixed once), and use-after-free mitigation where feasible in
   `no_std`.
2. Add a dedicated fuzz target for the allocator specifically —
   adversarial alloc/free sequences (sizes at boundaries, rapid
   cycling, exhaustion), wired into the same continuous nightly
   fuzzing infrastructure Phase AE just built (don't create a second,
   separate fuzzing system — extend the one that already works).
3. Run the new allocator fuzz target under Miri too, following Phase
   AD's exact host-testable-extraction pattern.

**Definition of Done:** a dedicated allocator fuzz target running
nightly alongside the existing ones, zero crashes over a stated real
run duration, and documented hardening properties (what's guarded
against, what's accepted risk and why — not everything needs to be
guarded, but every gap should be a decision, not an oversight).

**Verify:** the new fuzz target's nightly corpus growth visible in git
history the same way Phase AE's is; Miri output for the allocator's
host-testable logic, clean.

---

## 2. Hardware-evidence track (parallel-safe with AG)

Still entirely untouched — do this regardless of where AG/AH land,
it's real, low-risk, currently-missing evidence.

1. **Extract real ACPI/PCI/SMBIOS data from the running Windows host.**
   Export real RSDP/RSDT/MADT tables, real PCI config space, real
   SMBIOS data (RWEverything, or PowerShell's `Get-CimInstance
   Win32_*` classes, or a small dedicated dump tool if those don't give
   raw enough bytes). Commit the raw exported bytes as fixtures under
   something like `aegis-kernel/hardware-fixtures/` — real firmware
   data, not synthetic.
2. Write a test that feeds these real fixtures through the kernel's
   actual ACPI/PCI/SMBIOS parsers (the same parsers already fuzzed
   with synthetic data) and asserts they parse without error and
   produce sane, expected values (the real device list, the real CPU
   topology) — this is a genuinely different, valuable kind of
   evidence from synthetic fuzzing: proof the parsers handle this
   specific laptop's actual firmware quirks, not just adversarial
   byte patterns.
3. **Check whether VT-x is actually blocked by firmware or by
   Windows.** Check Core Isolation / Memory Integrity settings
   (Windows Security -> Device Security) before assuming the BIOS
   itself disables it — this is often the actual blocker on modern
   Windows laptops, not the firmware setting itself. If disabling Core
   Isolation (or finding the real BIOS toggle) unblocks VT-x, that's a
   real, reversible, one-time change worth making — it upgrades every
   future hypervisor test from TCG emulation to real nested-VMX,
   without ever touching bare metal.
4. **One real USB canary boot**, using the already-built
   `build-canary.ps1` tooling. Short, non-destructive by design,
   internal disk untouched. This is the one piece of evidence nothing
   else in this document substitutes for — genuine full-system
   bare-metal behavior, real timing, real firmware.

**Definition of Done:** real hardware-descriptor fixtures committed and
passing through the real parsers; a clear yes/no on whether VT-x is
actually available once Windows-side blockers are ruled out; one
completed, evidence-committed USB canary boot (or, if it doesn't
succeed cleanly, an honest account of exactly what happened and why —
a failed first attempt is real, valuable information too, not a reason
to omit this section).

**Verify:** the committed fixtures plus a passing test; the canary
boot's serial log, committed the same way every other phase's evidence
has been.

---

## 3. Phase AH — Process maturity docs

Now that AG and the hardware-evidence track exist, this can be written
accurately rather than aspirationally.

1. `SECURITY.md` — vulnerability reporting process, response
   expectations, scope.
2. A real threat model document — explicitly naming the adversary
   classes this project's test suite already effectively covers
   (malicious ring-3 task, malicious network peer, malicious hypervisor
   guest) plus, now that the hardware-evidence track has run, an honest
   statement of what's proven under emulation/virtualization versus
   what's proven on real hardware.
3. Fold the allocator's documented hardening properties (Phase AG) and
   the hardware-evidence results into this doc rather than scattering
   them — one coherent security posture document, not fragments.

**Definition of Done:** `SECURITY.md` and the threat model doc exist,
committed, cross-linked from the README the same way every other doc
already is.

---

## 4. Bridge phase — resume compatibility growth on the now-hardened base

Once AG/AH and the hardware-evidence track land: resume the guest-
kernel compatibility strategy (Phase V's real BusyBox apps were the
proof of concept — Phase W/X from that roadmap, deepening what runs
inside the guest and eventually attempting a Windows guest) is now
sitting on meaningfully more solid ground — a syscall-boundary-audited,
Miri-clean, ASan-clean, continuously-fuzzed, soak-tested hypervisor
instead of a merely-working one. That was always the point of doing
hardening now rather than later: growth work built on an audited
foundation is worth more than the same growth work built on an
unaudited one. Pick up that roadmap's next unclosed item once this
document's phases land — don't start it in parallel with AG/AH, let
the hardening finish first this one time, since the guest-kernel work
is exactly the kind of large, security-relevant surface that benefits
most from landing after the audit discipline, not before it.
