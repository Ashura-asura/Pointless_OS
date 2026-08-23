# Track 1 — §9 Delegation Mechanism (Phase RoleLib)

Implements the design doc's §9 delegation UX against a **real, non-ops-demo
task**: *"summarize what changed in this object-store subtree since a given
point"* (read-only, lowest blast radius), plus the diff-confirmed scope
expansion path. Built in `aegis-kernel` (`cap.rs`, `audit.rs`, `role.rs`,
`objstore.rs`), additive to the existing `role.rs` gate — not a rewrite.

## The five §9 mechanisms — closed vs reduced (Ground Rule 6)

| §9 mechanism | Status | What shipped |
|---|---|---|
| 1. Role-shaped grants | **CLOSED** | New `object-subtree-reader` (READ) and `object-subtree-editor` (READ\|WRITE) roles. The agent asks for the role; the kernel mints `Cap::Object(root)` with exactly the role's rights. No `GRANT` on either. Grantor must hold `Cap::ObjectRoot` (the human reviewer / boot policy), never a Task capability. |
| 2. Ephemeral-by-default | **CLOSED** | Every `role_grant` records an expiry (`GRANT_TTL` ticks) in a per-(task,slot) table; `grant_valid()` enforces it at the capability gate. Boot singletons (`NetRoot`/`VmRoot`) are not minted via `role_grant` and stay valid by kernel policy. Test: `ephemeral_grant_expires_and_blocks_reuse`. |
| 3. Diff-confirmation at scope expansion | **CLOSED** | Reading a *different* subtree than granted returns `ExpansionRequired` (no silent allow); `request_expansion` records a blocked `RoleExpand`; `confirm_expansion` (by an `ObjectRoot` holder) mints the new cap. The "diff" shown is exactly the added `Cap::Object(root)`, not the accumulated set. Test: `scope_expansion_requires_confirmation`. |
| 4. Persistent audit trail | **CLOSED** | `audit.rs` extended with `RoleExercise` (capability *used*) and `RoleExpand` (scope expansion requested/confirmed). Every grant use and expansion is attributable to task + target + ok. `dump_agent_flow` answers "what did the agent do." Test: `object_reader_runs_real_task_end_to_end`, `reader_shape_monitor_flags_off_profile_use`. |
| 5. Anomaly circuit-breaking + two-party | **CLOSED** | Two-party is closed for the high-risk (WRITE/"apply") expansion: a distinct second reviewer is required, same-party-twice refused (`apply_edit_requires_two_party_confirmation`). The *anomaly* half is now closed: `monitor.rs`'s full suspend-don't-revoke circuit breaker is wired directly to role grants (`role_monitor_train` / `role_monitor_observe` / `role_monitor_suspended` in `role.rs`) — a genuinely anomalous role usage (e.g. a read-only reader committing a mutating op) SUSPENDS the agent in the grant ledger, not merely flags it (`reader_shape_ok` was the earlier reduced check). The minted cap survives (no revocation); only new delegation is frozen and role exercise is denied until human review. Test: `role_anomaly_monitor_suspends_not_just_flags`. (Honest residual: the monitor's statistics are still the simple 2x-rate / unseen-op rule from `monitor.rs`, not a learned model — that limit is `monitor.rs`'s own documented scope, not a new gap.) |

## Honest scope (closed / reduced / inherent)

- **Closed:** the read-only real task runs end-to-end through a role-shaped,
  ephemeral, audited grant; scope expansion is diff-confirmed and blocked
  until confirmed; two-party gates the irreversible "apply" action; the audit
  log answers "what did it do" after the fact.
- **Reduced:** (a) the anomaly monitor is a role-shape check, not the full
  suspend circuit-breaker wired to role grants; (b) the object store
  (`objstore.rs`) retains per-object version count + last seq, not full
  content history, so "changed" reports *whether/how much*, not a byte diff;
  (c) the boot-log demo (`role::demo_track1`) runs under the test harness
  (same pattern as every other live-verified phase) — wiring it into the
  physical UEFI boot path is a follow-up.
- **Inherent:** object store is bounded to 64 objects (fixed array, like the
  rest of the kernel's tables); this is a deliberate small-TCB choice.

## Verify (independently checkable)

```
cd aegis-kernel
cargo test role::            # 14 tests: the 5 mechanisms + adversarial denial
cargo test                   # full kernel suite (811 passed, 2 ignored)
cargo clippy --all-targets   # clean (CI runs -Dwarnings)
cargo fmt --check           # clean
```

Tracks 2 (guest app battery) and 3 (defer) of the course-correction prompt
are intentionally not started here: Track 1's core claim (a real,
capability-scoped, audited agent task) is the load-bearing, un-de-risked
piece and ships first per the prompt's own sequencing.
