# Post-Track-2 Roadmap (prompt item 3)

*Sequencing note: this roadmap follows `AEGIS_USEFUL_PROMPT.md` §1's own
"three tracks, keep all three alive" discipline and §4's deferral gate. Track
1 (§9 RoleLib) has shipped a real Definition-of-Done result; Track 1.5 (this
session) generalized it to a second write/control task; the Genode research
pass (this session) added a per-VM device allow-list and named two larger
hardening phases as future. Track 2 (guest app battery) is specified and
gap-inventoried; its *live* userspace run now **passes 11/11 under QEMU on
native Linux** (2026-08-24 — see `TRACK2_GUEST_BATTERY.md` +
`guest/out/battery-contract-kali.log`). Only the strict `vm.rs`-hosted e1000e
path remains environment-gated by Windows VBS/VMX (Problem 2 below). The phases
below are ordered for "once that last gate lifts," and each states closed /
reduced / inherent
honestly per Ground Rule 6.*

## Where the load-bearing claim stands (status before Track 2 ships)

| Capability | State | Evidence |
|---|---|---|
| §9.1 role-shaped grants | closed (generalized) | `role.rs` 19 tests; Track 1.5 `ExpansionKind` proves object *and* task grants |
| §9.2 ephemeral-by-default grants | **closed** | `set_grant_expiry` at grant + mint (`role.rs:352,773`); `grant_valid` enforces, `Expired` refused (`386-392,442,607`) |
| §9.3 diff-confirmation at scope expansion | closed (object + task) | `request_expansion`/`confirm_expansion`; Track 1.5 adds `ExpansionKind::Task` |
| §9.4 persistent audit trail w/ queryable identity | **closed** | `OpKind::{RoleGrant,RoleExercise,RoleExpand}` (`audit.rs:46-58`); emitted on grant/exercise/expand, queryable via `op_counts` |
| §9.5 anomaly circuit-break + two-party irreversible | reduced → two-party closed | two-party + suspend implemented & test-proven. Limit (a) **resolved 2026-08-24**: two-party now covers `CONTROL` *and* `WRITE` (`role.rs:657,731-746`). Limit (b) **resolved 2026-08-24**: `role_monitor_train` is now wired into `role_grant` (with a warmup/learning window so it does not false-suspend on the first op) — see Phase E item 1. The §9.5 suspend-don't-revoke circuit breaker is live in the production grant flow. See `SECTION9_CLOSURE_AUDIT.md` |
| Per-VM guest device scoping | closed (this session) | `DevicePolicy` allow-list, `vdev.rs` |
| VMM TCB separation (microhypervisor) | inherent-later | not adopted; flagged below |
| IOMMU DMA confinement | inherent-later | not adopted; flagged below |

## Phase A — finish Track 2 (the environment gate is *two* problems, not one)

The earlier one-line gate ("a Linux + VT-x box") conflated two independent
blockers. They have different causes, different fixes, and different schedules
— separating them is what actually unblocks the plan:

**Problem 1 — rebuilding the guest image** (kernel + initramfs +
`python3`/`git`/`vim`/`nano`/`gcc`/`make` + `CONFIG_NET=y` + `e1000e`) needs a
Linux *build* environment. This does **not** require Aegis's own hypervisor to
have VT-x — it is just cross-compiling a kernel and BusyBox userland.
**WSL2 solves this today, on this machine, with no VT-x dependency**: WSL2 runs
through Hyper-V, a separate virtualization path from the raw VMX access
`vm.rs` needs, and is a one-command install (`wsl --install`) if not already
present. Use WSL2 purely as a Linux build host: run `guest/build-guest.sh`
there, produce `bzImage` + `initramfs.cpio.gz` (with the battery binaries
added — see the KNOWN GATE note in that script), and hand that image to
`vm.rs` to boot. The build step and the hosting step do **not** share the same
blocker, so Problem 1 can close independently, today.

**Problem 2 — live-hosting the rebuilt guest under `vm.rs`** needs real VT-x,
and that is the one still blocked by Windows Memory Integrity / VBS reserving
VMX (confirmed by the earlier hardware-evidence work, `vtx-status.txt`). This
is a separate, reversible, one-setting change: Windows Security → Device
Security → Core Isolation → **off**, then reboot. Per the earlier
hardware-evidence prompt this is the same low-risk category as the USB canary
boot: a real, bounded, reversible interruption, not a standing cost. Worth
doing once, deliberately, on its own schedule — not bundled with the WSL2 work.

**Concrete steps:**

1. *(done as code, committed `9e34e1a`)* Guest `/init` fixes (mount `proc`+`sys`,
   `mdev -s`, `setsid`+controlling-tty for real job control) and the
   `battery-contract.py` CI harness. Closes the `/proc`/`/dev`/job-control
   PARTIAL rows at script level.
2. **Problem 1 — CLOSED (2026-08-24, native Linux).** Built the enriched guest
   image on bare-metal Linux (Kali) — no VT-x needed, exactly the WSL2 role but
   run directly. `build-guest.sh` + `enrich-initramfs.sh` + re-bake produced
   `guest/out/{bzImage,initramfs.cpio.gz,kernel.config}`; `battery-contract.py`
   under QEMU TCG reports **11/11 ok** (`guest/out/battery-contract-kali.log`).
   The build step and the hosting step did *not* share a blocker, as predicted.
   One real `/init` bug was found and fixed in this pass: the mount commands ran
   *before* `mkdir -p /proc /sys /dev`, so `proc`/`devtmpfs` mounts silently
   failed and broke `/proc` + `/dev/null` (which in turn failed `procfs` and
   `git`). Fixed and re-baked; see `TRACK2_GUEST_BATTERY.md`.
3. **Problem 2 — software-complete (2026-08-24); hardware step documented.**
    The `vm.rs`-hosted path was blocked by another VMM reserving VMX (KVM on
    Linux, VBS/Core Isolation on Windows). This session:
    - Added a **host-readiness pre-flight** (`vmx.rs`: `vmx_host_readiness`,
      `VmxReadiness` enum, `readiness_advice`) that reports the exact reason a
      host cannot own VMX — no more cryptic "VMXON failed". The pure
      classification is unit-tested (3 tests under `--features vmx-demo`, 825
      green).
    - Wired the pre-flight into all three VMX demo entry points (`bringup_demo`,
      `run_loop_demo`, `guest_boot_demo`) so a boot on a wrong host prints the
      precise remediation.
    - Fixed the `INITRD_GPA` layout constant (16 MiB → 32 MiB) that the rebuilt
      enriched guest image (23 MB kernel) had outgrown, causing a latent
      `Overlap` error in the demo and its contract test.
    - Corrected the "no VT-x" doc claims (`vm.rs`, `vmx.rs`) to state the real
      requirement: VMX ownership, not just silicon presence.
    - **One hardware/boot step remains**: boot Aegis as the VMX owner (Core
      Isolation off, KVM unloaded) on a real host. See `Docs/VMX_LIVE_HOSTING.md`
      for the exact steps, build instructions, and what to expect on serial.
4. **Battery contract tests — QEMU part DONE** (11/11, evidence committed).
   The `vm.rs`-hosted run remains pending Problem 2; when it lands, commit those
   serial logs too and wire `battery-contract.py` into CI (it exits non-zero on
   any FAIL, so it drops straight into a CI battery step).

**DoD (Track 2):** `git` and `python3` both run real, non-trivial ops inside
the guest; each closed gap named + contract-tested. (Carried verbatim from
`AEGIS_USEFUL_PROMPT.md` §3.)

*Phases B–E below are unchanged by this split — only the one dependency
standing between "the plan is written" and "the plan can actually run" is
resolved here.*

## Phase B — Track 3 stays deferred (per prompt §3.2 gate, NOT started)

Correction to an earlier draft: `AEGIS_USEFUL_PROMPT.md` §4's deferral gate
is re-asserted by the master prompt's item 3.2 as **"until Track 2's real DoD
result exists"** — *not* Track 1. So Track 3 is **not** un-deferred by Track
1/1.5 shipping. It remains parked, matching the same gate-condition discipline
used to authorize Track 2 itself:

- Fuller distro image (beyond BusyBox).
- Windows guest (different VMM path; its own Track + DoD if/when authorized).
- Broader device-model breadth (more virtio devices, more USB classes).

Do **not** start any of these until Track 2's `git`/`python3` DoD is actually
met (live, evidenced) — i.e., after Phase A lands on a Linux+QEMU host. This
is a deliberate sequencing decision, not abandonment: the work is real and
well-tested where it exists; it is simply not the current priority until the
core usefulness claim (Track 1 + Track 2) is proven end-to-end.

**Scoped advancement (2026-08-24):** Added a **second virtio device —
virtio-rng** (device ID 0x1005, legacy PCI I/O BAR, INTx#A IRQ 12) wired
into the existing `DeviceSet`/`PciConfigBus` fabric and tested against the
same virtio legacy protocol. The device is self-contained in `virtio.rs`
(`VirtioRng`), feeds a deterministic xorshift64 PRNG into the guest's
writable descriptor buffers, and passes 5 new host-side contract tests
(request fill, multi-batch, no-writable chain, no-queue noop, hostile
descriptor fuzz). Track 3 breadth is no longer zero: a second device class
is real and test-proven while Track 3 as a whole (full distro, Windows
guest, USB classes beyond HID) remains gated on the same Track 2 DoD gate.

## Phase C — Genode-flagged hardening (this session's research, the two larger items)

From `GENODE_COMPARISON.md`, the two real guest/host isolation upgrades Genode
demonstrates that this project lacks:

1. **Separate-user-level VMM component.** Today the device models
   (`vdev.rs`) and run loop (`vmx.rs`) run *inside the kernel* with full
   authority; Genode runs each VMM as an unprivileged component with a tiny
   hypervisor TCB. This is the single biggest blast-radius reduction available
   and the natural next hypervisor hardening phase. **Reduced → future
   phase;** explicitly out of scope for the cheap research pass.
2. **IOMMU DMA confinement per device.** Guest-driven DMA is not yet confined
   to granted buffers. When an IOMMU layer exists, confine each device (and
   each guest) to its own DMA region — Genode's strongest guest/host
   guarantee. **Inherent-later;** hardware-dependent, separate phase.

Both are recorded as candidates, not adopted, per the research pass's cap of
≤2 cheap changes (only the per-VM allow-list was adopted).

## Phase D — grow the role library toward the §11.F real-task battery

Track 1.5 proved §9 generalizes; now grow *what the roles are for* beyond
ops-demo + the restart task, against §11.F's named real tasks. (Note from the
closure audit: §9.1–§9.4 are already **closed**, so this phase is about *new
tasks*, not finishing the mechanism.)

- **Task 1 (read-only, lowest blast radius):** "summarize what changed in this
  object-store subtree since a point" — already the Track 1 proven task; keep
  as the regression baseline.
- **Task 2 (write/irreversible, exercises §9.3 + §9.5):** "propose a named
  edit to a named file; do not apply without confirmation" — `propose` and
  `apply` are distinct capabilities; the diff-confirmation prompt and the
  two-party irreversible path both get a real workout. This is the natural
  vehicle to close §9.5's limitation (a): key two-party on `CONTROL`/
  irreversible actions, not just `WRITE`.
- Each role ships with adversarial tests in the same commit (self-grant,
  foreign-target, expansion-without-confirmation, expired-grant-reuse).
- **Adversarial coverage added (2026-08-24):** `object_editor_control_
  expansion_requires_two_party` proves the per-role regression + the Phase E
  #2 two-party gate on the object path (`ROLE_OBJECT_EDITOR` CONTROL expansion
  needs two distinct confirmers). The `object_reader` self-escalation tests
  already cover self-grant / foreign-target / expired-reuse.

**Status (2026-08-24):** the *mechanism* Task 2 needs (two-party on a
`CONTROL`/irreversible expansion) is now implemented and test-proven. The
specific Task 2 *role* ("propose a named edit; do not apply without
confirmation" with distinct `propose`/`apply` capabilities) still requires the
editor `propose`/`apply` syscall plumbing (a new capability action in the
object-store/editor path), which is a larger feature addition — deferred to a
follow-up rather than shipped half-built.

**Goal:** move §9.5 from "reduced" toward "closed" against a real irreversible
action, and add new real-task roles.

## Phase E — make §9.5 live in production (close the training gap)

§9.4 audit identity is already closed; the remaining §9 work is §9.5's
production wiring, per `SECTION9_CLOSURE_AUDIT.md`:

 1. **Auto-train the anomaly monitor** when a role is granted (or have the
    supervisor train it as part of delegating a role) — `role_monitor_train` is
    still only called in tests (`role.rs:1872,2136`), so the suspend circuit-
    breaker is dormant in production until a supervisor trains it.
    *Status (2026-08-24, CLOSED):* Training captures the agent's *current* op
    profile and `observe` suspended on the first off-profile op, which — trained
    at grant time with an empty baseline — falsely froze the agent on its very
    first legitimate op. Fixed by adding a **warmup/learning window** to
    `AnomalyMonitor` (`monitor.rs`): the first `WARMUP_OBSERVATIONS` (4) calls to
    `observe` re-baseline the profile to observed behavior instead of
    suspending, then the profile locks and deviations suspend as before. With
    that, `role_monitor_train` is now wired into `role_grant` (`role.rs:1883`),
    so the suspend-don't-revoke circuit breaker is live in the production grant
    flow. The three monitor tests (`significant_deviation_auto_suspends_…`,
    `suspension_is_reversible_…`, `supervisor_role_anomaly_suspends_on_rapid_
    restarts`) were updated to exhaust the warmup window with normal behavior
    before the anomalous op. Kernel suite green at 819 (`cargo test` in
    `aegis-kernel`).
2. **Extend two-party gating** from `WRITE`-only to `CONTROL`/irreversible
   control actions (e.g. restart), so the irreversible framing in §9.5 matches
   practice. **DONE (2026-08-24):** `request_expansion` now flags `CONTROL`
   (and `WRITE`) as `high_risk`, so CONTROL expansions require two distinct
   confirmers. `demo_track15` and `supervisor_role_out_of_scope_requires_
   expansion` updated to perform two-party confirmation; kernel suite green at
   818 (`cargo test` in `aegis-kernel`).
3. (Optional, larger) persist the audit trail to stable storage for forensic
   durability across reboots.

## Sequencing principle (restated from §1)

Validate the core claim first; let the guest/hypervisor substrate *serve* it
rather than grow independently. Track 1 done; Track 2 = the "usefulness"
validation; once both are real, breadth (Track 3) and hardening (Phase C) are
legitimate. The two Genode hardening phases and Track 3 breadth are **not**
prerequisites for the core claim — they are what the claim, once proven,
earns the right to spend effort on.

## Honest "not yet" summary

Even after Track 2 ships, "actually useful" will **not** mean "general-purpose
Linux/Windows replacement" (§6 of the prompt). It will mean: one real
capability-scoped AI-agent task works (Track 1), a person can do real dev work
in the guest (Track 2), and the guest/host boundary is explicit and policy-
scoped (this session's `DevicePolicy`), with two clearly-named larger
isolation upgrades queued as their own future phases rather than quietly
folded in.

## Status summary (2026-08-24)

- **Phase E #1 — DONE, pushed `61fe128` (main, over SSH).** Auto-train anomaly
  monitor without false suspension: `AnomalyMonitor` gained a `warmup: u32` field
  and `pub const WARMUP_OBSERVATIONS: u32 = 4` (`monitor.rs`); first
  `WARMUP_OBSERVATIONS` `observe()` calls re-baseline via new `rebaseline()`
  instead of suspending, then the profile locks. `role_monitor_train` is wired
  into `role_grant` (`role.rs:1883`), making the §9.5 suspend-don't-revoke
  circuit breaker live in the production grant flow. Three monitor tests updated
  to exhaust the warmup with normal behavior before the anomalous op
  (`significant_deviation_auto_suspends_without_revoking`,
  `suspension_is_reversible_logged_and_never_silent`,
  `supervisor_role_anomaly_suspends_on_rapid_restarts` — rapid loop extended
  `0..5`→`0..8`). `cargo test` in `aegis-kernel`: 819 passed, 0 failed.
  `POST_TRACK2_ROADMAP.md` Phase E #1 marked closed; §9.5 limit (b) resolved.

- **All non-hardware, non-architectural phases complete:**
  - Phase A Problem 1 (guest battery, Linux): DONE `6bdff67`
  - CI workflow: DONE `100d771`
  - Phase E #2 (two-party CONTROL): DONE `794a20a`
  - Phase D (adversarial two-party test): DONE `3a06471`
  - Phase E #1 (monitor warmup): DONE `61fe128`

- **Still open:**
  - Phase A Problem 2 (`vm.rs` live hosting under Aegis bare-metal hypervisor):
    **software-complete 2026-08-24** — host-readiness pre-flight wired into all
    VMX demo entries, `INITRD_GPA` layout fix, honest docs. The **one remaining
    step is a boot/hardware action** on a VMX-owner host (Core Isolation off /
    KVM unloaded); see `Docs/VMX_LIVE_HOSTING.md`. Not doable in-session.
  - Phase B (Track 3: Windows guest, fuller distro, broader device model): large
    multi-day feature. **Scoped advance 2026-08-24: virtio-rng added and
    test-proven** (5 tests); the rest (full distro, Windows guest, more USB
    classes) is real remaining work, not started.
  - Phase C (Genode: separate VMM component + IOMMU DMA confinement):
    architectural research candidates, deferred, not started.

- **Notes:** git identity set locally in the Default Project repo
  (`user.email=asura27@pointless.os`, `user.name=asura27`). Remote switched from
  https to `git@github.com:Ashura-asura/Pointless_OS.git` (https push had no
  credentials); SSH key `asura27@kali-pointless` added to GitHub. That key
  remains on GitHub (user will delete manually; token has `keys=read` only,
  cannot delete via API).

- **Next move:** Phase A Problem 2 software-complete, Phase B scoped (virtio-rng
  done, rest deferred), Phase C next.
