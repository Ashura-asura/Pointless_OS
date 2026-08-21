# Security Policy

This document describes how to report security vulnerabilities in the
Pointless OS / Aegis research substrate, what to expect, and the current
scope of the security effort.

## Scope

Pointless OS is an **experimental operating system research repository**. It
is intended for research, evaluation, and engineering experimentation — **not
for production deployment** where untrusted code or untrusted networks are
in scope. Aegis (the kernel + hypervisor substrate) is a deliberately small
trusted computing base under active hardening.

In scope for this policy:
- The `aegis-kernel` crate (syscall boundary, allocator, capability model,
  drivers, ACPI/PCI/SMBIOS parsers, networking stack).
- The `aegis` capability model crates and the `uefi-boot` loader.
- The `agent` / `policy_engine` / `supervisor` userspace security machinery
  (AI agents as capability-scoped principals, not TCB).

Out of scope (research-only / not yet a security boundary):
- Guest-OS compatibility layers (POSIX/Windows projection) — explicitly
  unprivileged translation, not part of the TCB.
- Anything gated on bare-metal hardware the project cannot yet run on
  (see `Docs/HARDWARE_EVIDENCE.md`).

## Threat model

The adversary classes the test suite already covers are documented in
[`Docs/THREAT_MODEL.md`](Docs/THREAT_MODEL.md). Read it before filing — many
"vulnerabilities" are already exercised by adversarial contract tests or
fuzzing and are either guarded or recorded as accepted, decided risks.

## Reporting a vulnerability

1. **Do not open a public issue** for a suspected vulnerability.
2. Report privately to the maintainers (security contact channel for the
   repo), including:
   - A precise description of the affected subsystem and the violated
     security property (isolation, capability integrity, memory safety,
     no-self-escalation).
   - A minimal reproduction (command, inputs, or fuzz corpus entry) and the
     observed vs expected behavior.
   - The commit/branch the behavior was observed on.
3. If you used a fuzzing input, include the corpus file (and the fuzz target /
   AFL++/`cargo-fuzz` invocation) so the finding is reproducible.

## Response expectations

- **Acknowledgement:** within a few days of a well-formed report.
- **Triage:** we classify against the existing threat model and the
  closed/reduced/inherent inventory in `Docs/THREAT_MODEL.md`. Findings that
  duplicate an already-decided accepted risk are closed with a reference, not
  silence.
- **Fix:** guarded regressions get an adversarial test (the project's
  standard — a fix without a regression test for a security bug is not
  considered done). Fixes land in a security branch and are merged with the
  raw evidence (test output / fuzz corpus) attached, per the project's
  ground rules.
- **Honesty over polish:** if a report identifies a gap we intentionally
  accept (inherent to `no_std` / emulator-only verification), we say so and
  record it in the threat model rather than papering over it.

## Verification discipline (why we trust reports)

Every security-relevant claim in this repo is expected to be
**independently checkable** with a command. See
[`Docs/THREAT_MODEL.md`](Docs/THREAT_MODEL.md) for the command-to-verify
associated with each covered property, and `Docs/HARDWARE_EVIDENCE.md` for
what is proven under emulation vs real hardware.
