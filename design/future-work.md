# Future Work — Design Only, Not Implemented

These items are part of the Aegis design (see `os-from-first-principles.md` and
`ARCHITECTURE.md`) but are **not implemented**. They are sequenced after the
capability-scoped AI-agent prototype (roadmap Phases 0–6) and are described
here so the main docs only claim what is implemented and verified today.

One-line pointer for the main docs:
> Design only, not implemented — see design/future-work.md.

---

## Master roadmap (Phases 0–7) — status

- **Phase 0** (honest docs) — done.
- **Phase 1** (capability rights) — done.
- **Phase 2** (least authority + revocation) — done.
- **Phase 3** (live capability-denial demo) — done.
- **Phase 4** (conformance harness) — done: `aegis/crates/conformance` replays
  the kernel's live capability trace against the model and proves the model's
  authorization verdicts agree with the kernel's recorded verdicts at every
  step (fixture: the ring-3 denial demo, verified under QEMU).
- **Phases 5–7** (live supervision demo, capability-scoped AI-agent prototype,
  one real subsystem over NVMe) — next, sequenced below.

---

## Windows/Linux compatibility

The design doc calls full native fidelity **inherent-cannot-be-closed**. Its
actual answer is:

- **Linux**: a translation-layer (Wine-style) / WSL2-lineage path — not a full
  syscall reimplementation. The design doc is explicit that full
  reimplementation of the Linux syscall surface is a permanent maintenance
  tax chasing a moving target.
- **Windows**: hardware-virtualized Windows-in-a-sandboxed-VM for full-fidelity
  legacy support, plus a thin translation layer only for well-behaved modern
  Win32/UWP apps. Full Windows compatibility without licensing Windows itself
  or running a real Windows kernel is **not a solved problem anywhere**
  (design doc §5).

**Status today:** two narrow, model-level translation layers exist in
`aegis-kernel` (Linux syscall ABI + ELF loader, 32 tests; Windows NT ABI +
PE32+ loader, 31 tests) — these are contract tests over buffers, not a live
compat runtime. The VM-based execution vehicles are not built (they need a
hypervisor). Scope is a target niche, not general parity.

## Distributed / fleet transparency

Also **inherent** (CAP theorem). The design doc's stance: don't build "your
network is one more machine, fully transparently."

- Build locality and partition failure as **visible and fail-safe by default**
  (deny/block on stale or unreachable state), not hidden.
- Cross-machine capabilities exist as an explicit, opt-in extension using
  cryptographically-verifiable capability tokens (macaroon/biscuit-style),
  never assuming a trusted LAN.

**Status today:** the `fleet` crate is a two-node in-process model (envelope,
peer trust, HMAC chain, remote attenuation, recipient binding) with 15
contract tests. No sockets, no consensus, no split-brain handling; partition
behavior is deliberately not modeled.

## GPU compositor / graphical shell

Not inherent — ordinary deferred UI work, lowest risk of the deferred items.
It can start once Phases 1–6 give it a real substrate.

- GPU access is capability-scoped command-queue submission (Vulkan/user-mode
  submission shape); compositing, window management and the graphics stack
  are ordinary userspace services.
- Today the only live display is the VGA text console (80x25 white-on-black
  mirror of the COM1 log). No framebuffer graphics, no GPU accel, no
  mouse/keyboard input.
- Shell runtime, window manager, object graph, and input dispatcher exist as
  model-level contract tests (24 tests), not a live UI.

## Broader AI orchestration

Expanding the Phase-6 `restart-service` role into a role library of more
roles/agents is legitimate future work — but every new role goes through the
same **grant/audit/adversarial-test discipline** as Phase 6, never a
shortcut.

Permanent rule, applies here forever, not just during the prototype: **the AI
is never in the trusted computing base.** An agent's decision logic never sits
near the trust boundary; every check on what an agent can do is enforced by
the kernel's capability mechanism, never by the agent's own code trusting
itself.

**Status today:** agent runtime, usage profiler, adaptive grants, and policy
engine exist as model-level contract tests (23 tests) and an adaptive-ceiling
verification suite (14 tests). No live AI integration.

## Package / update polish

Least urgent. Packages and system update already have reasonable model-level
coverage (7 + 5 contract tests). Revisit after Phase 7's storage work, since
packages logically sit on top of object-store.