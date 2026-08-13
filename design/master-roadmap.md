# Aegis / Pointless_OS — Master Roadmap Prompt

*Repo: github.com/Ashura-asura/Pointless_OS. This file is self-contained —
it doesn't assume you've read any prior conversation. Hand this whole file
to whoever (or whatever agent) works on the repo next.*

---

## 0. Context — read this before doing anything

This project has two separate, individually competent artifacts sharing
one repo:

1. A **bare-metal kernel** (`aegis-kernel/`) — boots real hardware under
   QEMU/OVMF, has a scheduler, real IPC, memory isolation (NX bits,
   page-fault-driven), live PCI enumeration, live NVMe block I/O, FAT16
   reads. Its own capability mechanism is real but minimal: one object
   type (`Cap::Endpoint`), no rights bitset.
2. A **formally-modeled capability-kernel spec** (`aegis/crates/*`) — TLA+
   model-checked (six invariants, 331k states), well-tested in isolation
   (121 contract tests as of this writing).

**These do not talk to each other.** `aegis-kernel/Cargo.toml` has zero
dependencies on the `aegis/` workspace. The model's tests prove things
about a simulation; they prove nothing about the kernel that actually
boots. This is the single most important thing to fix, and everything
below is sequenced around fixing it.

There is also a design document in this repo,
`os-from-first-principles.md`, that already answers most of the "what
should this actually be" questions. Its most important verdict (§11): the
smallest prototype that proves the architecture is a minimal
capability-scoped AI-agent execution context that (1) gets a *role*, not a
raw capability list, (2) can request expansion via a diff-confirmed grant
flow, (3) provably cannot self-escalate under adversarial testing, (4)
does one real task. Everything in this roadmap builds toward that target,
not toward "finish everything in the README."

**One hard rule from the design doc that overrides everything else,
permanently, not just during prototyping:** the AI is never in the
trusted computing base. Full stop. No phase below, and no future work
after this roadmap ends, should put an agent's decision logic anywhere
near the trust boundary. Every check on what an agent can do must be
enforced by the kernel's capability mechanism, never by the agent's own
code trusting itself.

**Decision already made, stated here so it isn't re-litigated:** don't
migrate to seL4, despite the design doc's own general-case recommendation
to build on seL4 rather than a from-scratch kernel. That advice is correct
for someone starting with nothing. This project already has real,
hardware-verified work below the capability line (boot, paging, NX, PCI,
NVMe) that a seL4 migration would throw away for no benefit toward this
project's actual goal (a unified, unique system) — as opposed to a
different goal (publishable formal verification), which this isn't. Keep
the existing kernel. Grow its capability model to match the spec's shape
instead of adopting seL4's.

---

## 1. Ground rules for every phase (from this repo's own `GROUND_RULES.md`)

Apply these to every commit in every phase below, no exceptions:

1. Before testing: delete the relevant `Cargo.lock` (`aegis/`,
   `aegis-kernel/`, `uefi-boot/` as applicable) for a clean slate.
2. Run the full test suite for whichever crate(s) the change touched —
   not just the new tests.
3. Paste the **complete raw** `cargo test` output into the commit
   message. Not a summary. Not "all tests pass." The raw terminal output.
4. Count the test total **yourself**, from that raw output, before
   writing any number into a doc. Do not trust a remembered or previously
   stated figure.
5. Any `FAILED` or `error` line: stop, fix it, restart from step 1. Never
   commit around a known failure, even in an unrelated part of the suite.
6. Never claim a limitation is closed when it's only reduced. Use the
   design doc's own three-way split for any "Known Limits" writing:
   **closed** (fixed, tested), **reduced** (better than before, not
   solved), **inherent** (cannot be closed by better engineering — CAP
   theorem under partition, proving AI behavior vs. its ceiling, the
   compatibility moat — say so plainly, don't imply progress here).

---

## 2. Phase 0 — Freeze scope, fix the framing

**No new code. Documentation and repo hygiene only.**

1. Create `design/future-work.md`. Move any README/ARCHITECTURE content
   describing Windows/Linux compatibility, distributed/fleet
   transparency, GPU compositor, or AI orchestration beyond what Phase 6
   below actually builds, into that file. Leave a one-line pointer in the
   main docs: "Design only, not implemented — see design/future-work.md."
2. Remove those moved items from any current test-count or feature
   summary anywhere in the repo — headline docs should only describe
   what's implemented today.
3. Grep the whole repo (docs and code comments) for "self-healing",
   "immune", "heal", "biological" and replace with "supervision tree" /
   "circuit breaker" language. This isn't cosmetic — biological framing
   invites exactly the "it heals itself, don't worry about it" thinking a
   circuit-breaker system should actively discourage (this is the design
   doc's own reasoning, §3, not an added preference).
4. Consolidate to a single "Known Limits" section (merge
   `HONEST_STATUS.md` and `ARCHITECTURE.md` if both have one) using the
   closed/reduced/inherent split from Ground Rule 6 above.

**Definition of Done:** no doc describes an unimplemented feature as if
live; one Known Limits section, not several disagreeing ones; zero
biological-healing language remains outside `design/future-work.md`.

**Verify:** `grep -ril "self-healing\|immune\|biological" . --include="*.md" --include="*.rs"` returns nothing outside `design/future-work.md`.

---

## 3. Phase 1 — Grow the kernel's own capability model

**Goal:** bring `aegis-kernel/src/cap.rs` up to the model's vocabulary,
implemented by hand in `no_std` (don't try to import `capability-core` —
different runtime assumptions, already investigated, rejected).

1. Extend `Cap` beyond `Endpoint(u32)`/`None`: add `Task(u32)` and
   `MemRegion(u32)`. Skip `GrantRoot`/`Creator` — model-only concepts with
   no kernel counterpart yet; add later only if a real use case appears.
2. Add a rights bitset carried alongside each capability: `READ`, `WRITE`,
   `SEND`, `RECV`, `GRANT`, `CONTROL` at minimum (use the `bitflags` crate
   if `no_std`-compatible, or hand-roll — note the choice in the commit).
3. Change `CapTable` slots to carry `(Cap, Rights)` instead of bare `Cap`.
4. Update every call site in `ipc.rs` to check the rights the operation
   needs (`ipc_call` → `SEND`, `ipc_serve` → `RECV`, etc.). Missing right
   → return `-1` (matching the existing denial convention), never panic.
5. Add kernel contract tests, same style as the existing `hardening.rs`:
   one per new object type, one proving denial without the right, one
   proving success with it.

**Definition of Done:** `Cap` has at least `None`/`Endpoint`/`Task`/
`MemRegion`; every capability carries explicit rights; the existing IPC
demo still boots with 0 exceptions under QEMU — this phase must not
regress the live boot.

**Verify:** `cd aegis-kernel && cargo test` (new + existing tests pass) +
existing QEMU/OVMF boot check, 0 exceptions.

---

## 4. Phase 2 — Make two invariants real

Don't implement all six of the model's invariants. Pick two, implement
them as enforced kernel behavior, prove each with a contract test.

1. **Least authority:** a newly spawned task must start with an empty
   capability table — `task_spawn` must never implicitly grant anything
   beyond what's explicitly given afterward via `ipc_cap_grant`. Audit
   `tasks.rs::spawn`; if already true (likely, `CapTable::new` should
   zero it), add the explicit contract test proving it rather than
   relying on it being true by omission. If not true, fix it.
2. **Revocation:** add a syscall (`ipc_cap_revoke` or similar) letting a
   `CONTROL`-rights holder invalidate a capability it previously granted.
   After revocation, further use of that capability by the revoked task
   must return `-1`, never panic, never silently succeed.

For each: a contract test that constructs the violating scenario directly
and asserts the kernel denies it.

**Definition of Done:** named tests for least-authority and revocation
that fail on current `main`, pass after this phase; no regressions.

**Verify:** `cd aegis-kernel && cargo test least_authority && cargo test
revocation && cargo test` (full suite, raw output pasted per Ground Rule 3).

---

## 5. Phase 3 — Live denial demo

Only do this after Phases 1–2 exist — there's nothing real to deny before
then.

1. In `main.rs`, add a third ring-3 task that is **not** granted the echo
   endpoint capability.
2. It attempts `ipc_call` against that endpoint anyway.
3. Print the `-1` denial to serial + VGA, same as the existing demo's
   success path.
4. Confirm (via a follow-up print) the kernel and the other two tasks
   keep running normally afterward.
5. Add this evidence line to the Known Limits/Verified doc from Phase 0,
   matching the existing format for other verified rows.

**Definition of Done:** QEMU boot log shows legitimate IPC succeeding,
unauthorized IPC denied with `-1`, and the boot finishing with 0
exceptions — demonstrated live, not just unit-tested (Phase 2 already
covers the unit-test version).

**Verify:** capture the QEMU serial log; confirm all three tasks' behavior
appears in it.

---

## 6. Phase 4 — Conformance harness (the actual fix for the disconnection)

Don't merge the two crates. Build a trace-based bridge instead.

1. Design a shared trace format (newline-delimited JSON, or a small
   custom binary format — pick whichever is easiest to emit from `no_std`
   kernel code): `{op, actor, target, cap_id, rights, result}`.
2. **Kernel side:** feature-gated trace emitter (`cfg(feature = "trace")`,
   so it doesn't affect the normal boot build) in `ipc.rs`/`tasks.rs` for
   every capability-relevant syscall used in the Phase 1–3 demo.
3. **Model side:** a small harness (in `capability-core` or a new
   `conformance` crate) that reads a trace file and replays each op
   against the model's `Kernel` type, asserting the model's invariant
   checks (I1 and whichever you implemented in Phase 2) agree with the
   real kernel's recorded `result` at every step.
4. Capture one real trace from the Phase 3 boot demo (legitimate call +
   denied call), check it in as a fixture
   (`conformance/traces/ring3-demo.trace`).
5. Add a test replaying that fixture, asserting 100% model/kernel
   agreement. **This is the headline artifact of the whole roadmap** — the
   first test in the repo that touches both crates' behavior in one
   assertion.

**Definition of Done:** at least one real (not hand-written) trace replays
cleanly with full agreement; the harness accepts new traces, not a
one-off script.

**Verify:** `cargo test -p conformance` shows N operations replayed, N
agreements, 0 disagreements.

---

## 7. Phase 5 — Real supervision-tree runtime

`supervision-tree` currently only exists in the model. Port the
circuit-breaker logic to react to real kernel task-lifecycle events, now
that Phases 1–4 give it a real capability system underneath.

1. Add a real `TaskKill` notification path in `tasks.rs` — when a task
   dies (from the existing NX/isolation fault-kill logic, or a new
   explicit kill syscall), post it somewhere a supervisor task can
   observe (a dedicated kernel object, or a reserved endpoint).
2. Implement a minimal `Supervisor` as an IPC-based ring-3 task (try this
   before considering kernel-resident — keeps policy out of the kernel,
   matching the "AI/policy never in the TCB" philosophy) that: is told
   about one supervised task at spawn, observes its `TaskKill`, respawns
   it under a bounded restart count, and after the bound, **escalates**
   (distinct logged "gave up" message) rather than looping forever.
3. Demo: deliberately crash a supervised task via the existing fault-kill
   path; show one restart, then escalation after repeated crashes.

**Definition of Done:** a real crash on real (QEMU) hardware triggers a
real respawn, and the bounded-restart-then-escalate behavior is visible
in the boot log — not a model simulation of either.

**Verify:** QEMU boot log: crash → kill event → respawn → (repeat to
bound) → escalation message → kernel continues, 0 exceptions.

---

## 8. Phase 6 — Capability-scoped AI-agent prototype (the actual target)

This is `os-from-first-principles.md` §11.F's own definition of done.
Build exactly this, nothing broader, now that Phases 1–5 give it real
capabilities, real denial, and real supervision to sit on.

1. Define one role: `restart-service` = `Task::CONTROL` over one specific,
   named task. Don't build a general role framework yet — one role,
   correctly enforced, is the point of this phase.
2. Build an agent execution context — a ring-3 task starting with *zero*
   capabilities, that can only act after being granted the role.
3. Build the grant flow as an explicit, loggable step (a human, or a
   scripted stand-in for the prototype, reviews and confirms). Every
   grant goes into an append-only audit log (reuse
   `capability-core::AuditLog`'s shape, reimplemented kernel-side).
4. **The actual point of this phase — adversarial test:** the agent
   attempts an action outside its role's scope (control a task it wasn't
   granted; try to grant itself an additional capability). Assert this is
   denied by the Phase 1/2 kernel mechanism specifically — not by
   anything in the agent's own code. The agent must have no code path
   that could self-escalate even if its logic were fully compromised.
5. Wire the agent to the Phase 5 supervisor: its one real task is
   "restart this specific crashed service, and nothing else, on request"
   — the design doc's own exact example.

**Definition of Done:** the agent performs its one granted task; the
adversarial test in step 4 passes specifically because of a kernel-level
denial; every grant appears in the audit log.

**Verify:**
```
cd aegis-kernel && cargo test agent_role_grant
cd aegis-kernel && cargo test agent_cannot_self_escalate   # the headline result
```
Plus a QEMU boot log: role grant → agent restarts the crashed service →
agent's escalation attempt denied → audit log contains both events.

**Status: COMPLETE** (P6 committed, `uefi-boot/serial-p6.log`).
Delivered exactly the one-role prototype above: `restart-service` is the
sole role in `aegis-kernel/src/role.rs` (`Role { id, name, rights, grants }`,
rights = `READ|CONTROL` over one task, `grants` empty — the role cannot be
re-granted); the ring-3 agent (task 8) starts with an empty CSpace and only
acts after the supervisor (scripted human-reviewer stand-in) runs syscall 18
`RoleGrant` (kernel-gated: grantor must hold a `Cap::Task(target)` with the
role's exact rights); the agent's one real task is restarting the crashed
service task (syscall 16), and every self-escalation attempt — self-grant,
foreign role-grant, foreign kill — is denied by the Phase 1/2 capability
mechanism (returns `-1`) with an `OpKind::RoleGrant`/agent audit record, all
dumped by `dump_agent_flow` at boot. 4 new kernel tests
(`agent_role_grant`, `agent_cannot_self_escalate`,
`role_grant_never_panics_and_denies_garbage`, `locate_at_reads_handoff_from_any_address`);
kernel suite now 336 passing.

A layout-dependent boot regression discovered while verifying P6 was fixed
in the same phase: the UEFI loader's fixed boot-info handoff page (0x10000)
grew into the kernel image once the linker placed `.got` at 0xffa8–0x10068;
the loader's handoff write then corrupted GOT slots and the kernel faulted at
boot (`RIP=0x700000000`). Fix: the loader now writes the handoff on the first
page strictly above the image (`image_end`) and passes its address to `_start`
in `%rdi`; the kernel reads it via `boot_info::locate_at(addr)` and reserves
the handoff pages in the frame allocator. No fixed low address can ever
collide with the image again.

---

## 9. Phase 7 — One real subsystem (only after Phase 6 is done)

Don't parallelize this with Phases 1–6 — it's explicitly lower priority
than proving the architecture.

**Recommended:** port `aegis/crates/object-store`'s content-addressing
(hash-named immutable blocks, COW mutable layer) to write through the
kernel's real NVMe block I/O instead of an in-memory model. Reuse the
already-hardened `decode_entries` bounds-checking logic directly — it was
fixed specifically to be safe against real, possibly-corrupted disk
content. Add a kernel contract test reading back a deliberately corrupted
on-disk block (bit-flipped, truncated), confirming no panic.

**Definition of Done:** left open deliberately — scope this for real once
you reach it, not from here.

### P7 landed (see commit "master roadmap P7")

`aegis-kernel/src/nvme_store.rs` writes the Phase 4 object-store semantics
through the kernel's real QEMU NVMe device: hash-named immutable blocks
plus a COW mutable dir layer over flat on-disk LBAs (header + index +
data region at LBA 8192+), SHA-256 content addressing, cross-checked
digest verify on reads, and a deliberate bit-flip corruption test proving
the store detects a bad block and keeps running without panicking. Two
real driver bugs surfaced and were fixed on the live device:

- **Queue size is 0s-based.** QEMU builds queues of `qsize + 1` entries
  (NVMe spec), so advertising `QUEUE_SIZE` (16) created 17-entry rings;
  on the wrap the controller fetched one slot past the never-written end
  of the SQ buffer (all zeroes -> FLUSH, nsid 0) and replied
  `INVALID_NSID`. Fixed by advertising `QUEUE_SIZE - 1`, exactly as the
  admin AQA already did.
- **The CQ head doorbell was never rung.** Polled completion queues still
  must ring the CQ head doorbell to release consumed slots; without it
  QEMU reports the ring full once `qsize` completions are outstanding and
  every later completion stalls. Added CQ head doorbell writes to both
  `wait_completion` and `wait_io_completion`.

Verified live under QEMU/OVMF: single `put` round-trip proves
insert-dedup, digest-verified readback, COW dir versioning, and
corruption recovery — all against the kernel's real NVMe driver.

---

## 10. What happens to the deferred items (Windows/Linux compat, distributed transparency, GPU shell, broader AI orchestration)

Not cut — sequenced, and only after Phase 6:

- **Windows/Linux compat:** the design doc calls full native fidelity
  inherent-cannot-be-closed. Its actual answer: VM-based fidelity for
  Windows, translation-layer (Wine-style) for Linux — not a full syscall
  reimplementation. Scope for a target niche, not general parity.
- **Distributed/fleet transparency:** also inherent (CAP theorem). Don't
  build "your network is one more machine, fully transparent." Build
  locality and partition failure as visible and fail-safe by default
  (deny/block on stale or unreachable state), not hidden.
- **GPU compositor / graphical shell:** not inherent, just deferred.
  Ordinary UI work, lowest risk of the deferred items, can start once
  Phases 1–6 give it a real substrate.
- **Broader AI orchestration:** expanding the Phase 6 role library to
  more roles/agents is legitimate future work — but every new role goes
  through the same grant/audit/adversarial-test discipline as Phase 6,
  never a shortcut. The "AI never in the TCB" rule from Section 0 applies
  permanently here, not just during the prototype.
- **Package/update polish:** least urgent; already has reasonable
  model-level coverage. Revisit after Phase 7's storage work, since
  packages logically sit on top of object-store.

---

## 11. Timeline (rough, at solo hobbyist pace)

- Phase 0: days, not weeks.
- Phases 1–3: 2–3 weeks each, sequential.
- Phase 4: 2–3 weeks — the highest-value phase, don't rush it.
- Phase 5: 3–4 weeks.
- Phase 6: 4–6 weeks — this is the finish line for "proves the
  architecture."
- Total to Phase 6, done properly: roughly 4–5 months.
- Phase 7 onward: open-ended, start only after Phase 6 is verified.
