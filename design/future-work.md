# Future Work — Design Only, Not Implemented

These items are part of the Aegis design (see `os-from-first-principles.md` and
`ARCHITECTURE.md`) but are **not implemented**. They are sequenced after the
capability-scoped AI-agent prototype (roadmap Phases 0–6) and are described
here so the main docs only claim what is implemented and verified today.

> **Status update (roadmap §10):** every deferred item below has now been
> implemented at its honest scope and verified (see `HONEST_STATUS.md` and the
> `design/master-roadmap.md` §10 rows). This file keeps the *design* reasoning
> and the honest remaining limits of each — the full-fidelity vehicles are
> still not built and are documented as such.

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
  one real subsystem over NVMe) — done.
- **§10 deferred items** — done at honest scope (see per-item status below).

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

**Status today:** the personality translation layers are implemented and
exercised live (`linux_compat.rs`+`linux_abi.rs`+`pe_loader.rs`; `win_compat.rs`+
`nt_abi.rs`), each gating every translated op on a `CapabilityScope`; live proof
at `uefi-boot/serial-p11.log`. **Inherent limits kept honest:** full Windows
fidelity needs a hypervisor (not built); full Linux fidelity needs a real
ring-3 trap (not built) — translation layer only, not a full reimplementation.

## Distributed / fleet transparency

Also **inherent** (CAP theorem). The design doc's stance: don't build "your
network is one more machine, fully transparently."

- Build locality and partition failure as **visible and fail-safe by default**
  (deny/block on stale or unreachable state), not hidden.
- Cross-machine capabilities exist as an explicit, opt-in extension using
  cryptographically-verifiable capability tokens (macaroon/biscuit-style),
  never assuming a trusted LAN.

**Status today:** the `fleet` crate is a two-node in-process model (envelope,
peer trust, HMAC chain, remote attenuation, recipient binding, explicit
locality) with 22 contract tests. **Partition behavior is now modeled**
fail-closed: each peer carries reachability state (heartbeat/last-seen vs. a
configurable staleness window + explicit `mark_unreachable`), and a remote
capability is denied (`PeerUnreachable`/`PeerStale`) when its issuer is
partitioned or stale. Honest limit kept: no sockets, no consensus/split-brain
*resolution* — the model denies on stale/unreachable state, it does not heal
the partition.

## GPU compositor / graphical shell

Not inherent — ordinary deferred UI work, lowest risk of the deferred items.
It can start once Phases 1–6 give it a real substrate.

- GPU access is capability-scoped command-queue submission (Vulkan/user-mode
  submission shape); compositing, window management and the graphics stack
  are ordinary userspace services.
- Today the only live display is the VGA text console (80x25 white-on-black
  mirror of the COM1 log). No framebuffer graphics, no GPU accel, no mouse;
  keyboard input now works live (real PS/2 IRQ path driving Tab-focus +
  arrow-move — see HONEST_STATUS.md).
- Shell runtime, window manager, object graph, and input dispatcher exist as
  model-level contract tests, not a live UI.

**Status today:** the kernel now has a real compositor
(`aegis-kernel/src/compositor.rs`): an allocation-free, purely functional paint
that composites the `WindowManager`'s z-ordered visible windows into one
screen — overlap occlusion, region+screen clipping, hidden-window skip,
unrendered-window transparency — 8 contract tests, exercised live at
`uefi-boot/serial-p12.log`. **Honest substrate:** the VM's real display is the
VGA text-mode buffer, so a "pixel" is one text cell; the capability-scoped GPU
*service* (queue=SEND, framebuffer=READ|WRITE, compositor=READ grants,
dead-compositor refusal) lives in the model `crates/devices`. Still not built:
framebuffer/accelerated graphics, mouse input (PS/2 keyboard input is done —
Tab cycles focus, arrows move the focused window, serial- and screen-verified
under QEMU).

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

**Status today:** the role library is now two roles — `restart-service`
(READ|CONTROL over one task, no GRANT) and the `observe-service` watchdog
(READ over one task only, no CONTROL, no GRANT) — both kernel-declared,
granted by the gated `role_grant` syscall 18, with adversarial self-escalation
denials tested and live proof at `uefi-boot/serial-p9.log`.

## Package / update polish

Least urgent. Packages and system update already have reasonable model-level
coverage. Revisit after Phase 7's storage work, since packages logically sit on
top of object-store.

**Status today:** done — the package/system-update model runs on top of the
Phase-7 NVMe store (`aegis-kernel/src/update.rs`): generations staged as
`gen-N`, health-gated activation, rollback to last known good, content-addressed
COW boot-view pointer, payload dedup; 9 `update` tests + 1 `nvme_store` boundary
test; live proof at `uefi-boot/serial-p10.log`.