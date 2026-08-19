# Uncovered from First Principles — Audit-Driven Gap Inventory

*Status: 2026-08-19, following the external security audit of the real kernel
(`aegis-kernel/`). This file is the honest inventory of what the design doc's
"from first principles" claims do **not** yet cover, split into three hard
categories: **CLOSED** (found + fixed + test-covered), **DESIGNED/NOT
REFACTORED** (real gaps with a concrete fix design, deliberately not
half-implemented), and **GATED** (cannot be done here at all — hardware,
proof, or model-architecture ceilings). Nothing in this file outruns the test
evidence in `HONEST_STATUS.md` and `SECURITY_AUDIT.md`.*

---

## 1. CLOSED by the 2026-08-19 hardening pass

The audit verified the source and found one **critical** and several
**high/medium** boundary bugs. All were real, all are now fixed with
fail-closed semantics (deny, never panic, never touch out-of-range memory),
and each fix has an adversarial regression test.

| Finding | Where | Fix | Tests |
|---|---|---|---|
| **Critical** — `ipc_cap_grant` lacked the `dst < MAX_TASKS && dst_slot < MAX_CAPS` bounds check that `ipc_cap_revoke` has; an out-of-range recipient reached raw `set_task_cap` pointer arithmetic | `aegis-kernel/src/ipc.rs` (~line 234) | Added the bounds guard, mirroring `ipc_cap_revoke` | `cap_grant_refuses_out_of_range_recipient` |
| `ipc_reply` could write into an arbitrary task frame by passing a forged `caller` index | `aegis-kernel/src/ipc.rs` | Validate `caller < MAX_TASKS` **and** `caller == ENDPOINTS[ep].caller` before deref | `reply_refuses_forged_and_out_of_range_callers` |
| netif syscalls (`sys_net_connect/send/recv/close`) indexed slots without bounds checks | `aegis-kernel/src/netif.rs` | Slot bounds checks on all four | `net_syscalls_refuse_out_of_range_slots` |
| Raw task accessors (`task_state`/`set_task_state`/`task_cap`/`set_task_cap`/`task_frame_ptr`/`unblock_task`/`grant_cap`) had no index guards | `aegis-kernel/src/tasks.rs` | All guarded: out-of-range → no-op/OOB-safe, never panic | `raw_accessors_refuse_out_of_range_indices` |
| Cap-resolved index paths (tasks via caps, endpoints, regions) lacked defense-in-depth id bounds | `aegis-kernel/src/{supervisor,ipc,mem}.rs` | `caps_task`/`caps_endpoint`/`caps_region`/`region()` all bounds-check the resolved id | covered by the adversarial tests above |
| Syscall ABI: every syscall number reachable with hostile task/slot/endpoint indices | `aegis-kernel/src/hardening_fuzz.rs` | Fixed-seed syscall-boundary fuzz drives each syscall with per-number fuzzed/zeroed args; 0 panics, 0 OOB, current task never moved | `syscall_boundary_rejects_hostile_indices` |

**Regression result:** kernel suite went from 737 → **754** tests (plain),
**757** with `--features vmx-demo`; `cargo fmt --check` and
`cargo clippy --all-targets -- -Dwarnings` are clean.

One documented caveat inside the hardening work: the syscall-boundary fuzz
excludes syscall number 8 (`EndpointCreate`) because it has no index args but
*does* mint endpoints, which would exhaust the endpoint table and perturb two
unrelated IPC tests. The exclusion is asserted in the test source, not hidden.

---

## 2. DESIGNED / NOT REFACTORED — real gaps we are not half-fixing

The audit's **HIGH** findings are real design flaws. We verified them in
source, wrote the fix design, and chose **not** to refactor at audit time:
each touches the kernel-wide capability representation (~15 files), carries a
real regression risk we cannot soak on physical hardware, and would land
between the "found a bug" and "fixed a bug" states with no test that genuinely
distinguishes them. This section records the design. **2.1 and 2.2 were
implemented and test-closed in the same pass that shipped the audit's other
fixes (kernel 761 plain / 764 vmx-demo); 2.3 remains a genuine backlog item.**

### 2.1 Generation-safe object identity (stale-handle risk)

- **Gap:** `Cap::Task(u32)` (and the raw index capabilities) name tasks by
  bare index. `spawn_impl` reuses a `Zombie` slot when the task table is full
  (`aegis-kernel/src/tasks.rs`, ~line 400). A task holding a stale
  `Cap::Task(i)` therefore gains access to whoever later occupies slot `i`.
  The audit rates this the most serious unresolved item.
- **Why it is low-risk today (not a fix):** capabilities minted by the kernel
  (`spawn`/`endpoint`/`region`) always point at live objects — the stub
  task/endpoint/region code paths are fixed functions, not user-extensible
  allocators — and slot reuse requires exhausting the table first. It is
  still a design flaw.
- **Fix design (ObjectID):** replace bare indices with
  `struct ObjectID { index: u32, generation: u32 }`; `spawn_impl` increments
  the slot's generation on reuse; every accessor
  (`task_state`, `task_cap`, `task_frame_ptr`, …) verifies
  `slots[id.index].generation == id.generation` before deref, so a stale
  handle fails closed instead of aliasing. The capability ABI carries the
  generation; syscall-boundary fuzz must then fuzz `(index, generation)` pairs.
- **STATUS: IMPLEMENTED + TEST-CLOSED.** `Oid { index, generation }` (see
  `cap.rs`, `tasks.rs`); payloaded caps carry it, every resolve does a
  single bounds+generation gate, slot reuse bumps the generation, and three
  dedicated stale-handle tests prove a reused slot's old cap is denied
  (`tasks.rs`, `channel.rs`, `netif.rs`). The ABI deliberately passes raw
  indices only — the generation never crosses to ring-3.

### 2.2 Centralized user-pointer validation

- **Gap:** syscall pointer arguments (message payloads, bulk-copy buffers,
  netif buffers) are cast and used directly by the write/ipc/mem copy paths.
  The syscall-boundary fuzz pins pointer args to the scratch buffer VA and
  forces bulk-copy lengths to 0 precisely because of this — a generic
  positional fuzz on pointer args caused `STATUS_ACCESS_VIOLATION 0xc0000005`
  during development. That is documented in the fuzz module, not papered over.
- **Fix design:** a single `copy_from_user`/`copy_to_user` gate that (a) takes
  the calling task's map bounds, (b) rejects any pointer outside the task's
  mapped range or not in user (ring-3) pages, and (c) never panics on a bad
  range. All syscall copy paths route through it; the fuzz test then fuzzes
  pointer args too, with the gate (not a scratch buffer) as the defense.
- **STATUS: IMPLEMENTED + TEST-CLOSED.** `user_ptr.rs` provides
  `validate_range`/`copy_from_user`/`copy_to_user` doing a strict 4-level
  walk over the calling task's PML4 (kernel context is a trusted bypass); the
  write/ipc/mem/channel/netif copy paths all route through it, deferred IPC
  copies validate against the OWNING task's PML4, and a 3-test gate suite
  plus a direct gate-walk fuzz exercise it adversarially.

### 2.3 Flat CSpace, no derivation tree (already admitted)

- The capability space is a flat two-level table (`cap_parts` + per-slot
  caps); revocation is instance-named, there is no seL4-style guard-page /
  derivation tree, and there is no capability *retrieval* (a task holding a
  cap cannot copy it to a peer — hence the orchestrator shares the boot
  context's CSpace rather than giving the agent its own). This was admitted
  in the design and HONEST_STATUS rows; it is restated here because the audit
  independently flagged it. A derivation tree is the natural sequel to 2.1
  (guarded entries would hold ObjectIDs), but it is a new subsystem, not a
  hardening patch.

---

## 3. GATED — cannot be closed from this machine or at this scope

These are unchanged, honest ceilings; they are listed so "what remains" is
exhaustive:

- **Physical-hardware certification.** Every device driver, the GOP-first
  display backend, the VT-d-style DMA gate, and the polled NIC/TCP stack are
  QEMU/OVMF-verified only. Nothing has run on physical hardware. No real
  VT-x exists on the host, so the Aegis-hosted VMX vehicle cannot execute
  locally either (the guest image runs standalone under QEMU).
- **Coverage-guided fuzzing.** Phase M is 180M-input/2-seed (random +
  mutation) over `decode_entries`/`parse_elf`/`parse_pe`; the new in-kernel
  fuzz is fixed-seed. Neither is coverage-guided. Porting a libFuzzer-style
  driver into the kernel harness (guest-side coverage or emulated counters)
  is real Phase 12 work.
- **Inductive proof ceiling.** TLA+ model-checking is finite-instance
  (AegisCapabilities 331k states, AegisCeiling 5.64M states). An seL4-class
  inductive proof was explicitly not chosen (see HONEST_STATUS "DECISION —
  kernel lineage"). The ceiling stands.
- **Secure boot / attestation / TPM.** Not built; no loader-verification
  chain exists beyond UEFI's own Secure Boot support (untested here).
- **Model-architecture ceilings.** The capability model has no cap-transfer
  IPC, so the orchestration crate's agent is task-scoped/revocable but shares
  the boot CSpace; the fleet crate is an in-process two-node model (no real
  network sockets, no Raft/Paxos/Byzantine) with live consensus living in the
  kernel `mesh.rs`.

---

## How to read this file

- **CLOSED items need no action** beyond the regression suite that now
  encodes them (761/764 kernel, 136 workspace, 22 bootloader).
- **DESIGNED/NOT REFACTORED items are the top of the real engineering
  backlog**: 2.3 (derivation tree) is the only one left; 2.1 (ObjectID) and
  2.2 (pointer gate) were closed in the audit-follow-up pass. It lands with
  its own fail-closed tests and a full-suite regression.
- **GATED items are ceilings, not laziness.** Each is a hard dependency on
  hardware, a proof methodology decision, or a model boundary the design doc
  itself defers. They are tracked in `master-roadmap.md` and
  `HONEST_STATUS.md` and must not be silently downgraded to "done".