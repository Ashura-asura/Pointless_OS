# Post-Track-2 Roadmap (prompt item 3)

*Sequencing note: this roadmap follows `AEGIS_USEFUL_PROMPT.md` §1's own
"three tracks, keep all three alive" discipline and §4's deferral gate. Track
1 (§9 RoleLib) has shipped a real Definition-of-Done result; Track 1.5 (this
session) generalized it to a second write/control task; the Genode research
pass (this session) added a per-VM device allow-list and named two larger
hardening phases as future. Track 2 (guest app battery) is specified and
gap-inventoried but its *live* run is environment-gated on this Windows/VBS
host (no VT-x for `vm.rs` hosting, no Linux toolchain to rebuild the guest) —
see `TRACK2_GUEST_BATTERY.md`. The phases below are ordered for "once the
environment gate lifts," and each states closed / reduced / inherent
honestly per Ground Rule 6.*

## Where the load-bearing claim stands (status before Track 2 ships)

| Capability | State | Evidence |
|---|---|---|
| §9.1 role-shaped grants | closed (generalized) | `role.rs` 19 tests; Track 1.5 `ExpansionKind` proves object *and* task grants |
| §9.2 ephemeral-by-default grants | **closed** | `set_grant_expiry` at grant + mint (`role.rs:352,773`); `grant_valid` enforces, `Expired` refused (`386-392,442,607`) |
| §9.3 diff-confirmation at scope expansion | closed (object + task) | `request_expansion`/`confirm_expansion`; Track 1.5 adds `ExpansionKind::Task` |
| §9.4 persistent audit trail w/ queryable identity | **closed** | `OpKind::{RoleGrant,RoleExercise,RoleExpand}` (`audit.rs:46-58`); emitted on grant/exercise/expand, queryable via `op_counts` |
| §9.5 anomaly circuit-break + two-party irreversible | reduced | two-party + suspend implemented & test-proven, but **two named limits**: (a) two-party is `WRITE`-keyed not `CONTROL` (`role.rs:649,731-746`); (b) `role_monitor_train` only called in tests, never in the production grant flow, so the suspend breaker is dormant until a supervisor trains it (`role.rs:1872,2136` only). See `SECTION9_CLOSURE_AUDIT.md` |
| Per-VM guest device scoping | closed (this session) | `DevicePolicy` allow-list, `vdev.rs` |
| VMM TCB separation (microhypervisor) | inherent-later | not adopted; flagged below |
| IOMMU DMA confinement | inherent-later | not adopted; flagged below |

## Phase A — finish Track 2 the moment the env allows (closure of existing gaps)

Reachable *as code now*, live-run only on a Linux + VT-x box:

1. Guest `/init` fixes (no behavioral risk, pure userspace): mount `proc`+`sys`,
   `mdev -s`/`devtmpfs` population, `setsid` + `TIOCSCTTY` the shell for real
   job control. Closes the `/proc`, `/dev`, and job-control PARTIAL rows in
   `TRACK2_GUEST_BATTERY.md`.
2. Rebuild guest with `python3`/`git`/`vim`/`nano`/`gcc`/`make` and
   `CONFIG_NET=y` + `e1000e` (the §3 DoD's clone-over-network path).
3. Run the battery contract tests (shell→python3→git→vim/nano→gcc/make) and
   commit the serial logs as evidence (Ground Rule 7).
4. Wire each contract test into the CI battery so the gaps are regression-gated.

**DoD (Track 2):** `git` and `python3` both run real, non-trivial ops inside
the guest; each closed gap named + contract-tested. (Carried verbatim from
`AEGIS_USEFUL_PROMPT.md` §3.)

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

**Closed/reduced:** Track 3 breadth remains **reduced** by design (§11.G:
compatibility breadth is premature relative to the core claim even after Track
1/2 — it is allowed now, not mandated).

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

**Goal:** move §9.5 from "reduced" toward "closed" against a real irreversible
action, and add new real-task roles.

## Phase E — make §9.5 live in production (close the training gap)

§9.4 audit identity is already closed; the remaining §9 work is §9.5's
production wiring, per `SECTION9_CLOSURE_AUDIT.md`:

1. **Auto-train the anomaly monitor** when a role is granted (or have the
   supervisor train it as part of delegating a role) — today `role_monitor_
   train` is only called in tests (`role.rs:1872,2136`), so the suspend
   circuit-breaker is dormant until a supervisor trains it.
2. **Extend two-party gating** from `WRITE`-only to `CONTROL`/irreversible
   control actions (e.g. restart), so the irreversible framing in §9.5 matches
   practice.
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
