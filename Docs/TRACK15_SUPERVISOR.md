# Track 1.5 — §9 Generalization Check (Phase RoleLib-2)

The master prompt's first post-Track-1 task: prove the five §9 delegation
mechanisms are a *real* mechanism, not a one-off overfit to the single task
Track 1 proved them against (`object-subtree-reader`, read-only,
object-store-shaped). The discipline is identical to insisting on more than
one fuzz-corpus seed, applied one level up: a mechanism proven against one
task could still be accidentally shaped to that task's specific risk/capability
profile.

## The second task

**"Monitor a supervised task's health and restart it"** — deliberately a
*write/control*-shaped task (kill + respawn a task), reusing the existing
supervision-tree primitives but gated through the §9 `restart-service` role
grant instead of the original hardcoded role. This is the opposite shape from
Track 1's read-only subtree summary.

## All five mechanisms, exercised for real

| §9 mechanism | How the second task exercises it |
|---|---|
| 1. Role-shaped grants | `role_grant(ROLE_RESTART_SERVICE)` mints exactly `Cap::Task(svc)` with READ\|CONTROL, no GRANT — the agent never assembles its own cap. |
| 2. Ephemeral-by-default | The granted restart cap carries a `GRANT_TTL` expiry; reuse after lapse is refused at the gate (`Expired`). |
| 3. Diff-confirmation at scope expansion | Restarting a *different* task than granted returns `ExpansionRequired`; nothing is minted until a reviewer confirms. The "diff" is exactly the added `Cap::Task(other)`. |
| 4. Persistent audit trail | Every restart attempt (success and refusal) is a `RoleExercise`/`RoleExpand` record attributable to agent + target, answerable by `dump_agent_flow`. |
| 5. Anomaly circuit-breaking | Rapid repeated restarts outside the trained profile SUSPEND the agent in the grant ledger (suspend-don't-revoke); the suspended agent's role exercise is then denied. |

Run it: `cargo test role::` (19 tests; the `supervisor_role_*` and
`track15_boot_demo` tests are the new ones).

## Honest finding: §9 was NOT a complete one-off, but it WAS object-shaped

This is the actual result of the generalization check, stated plainly
(Ground Rule 6). The §9 *exercise* path needed **zero** task-specific
special-casing — `supervise_restart` reuses `resolve_task_cap` /
`role_monitor_*`, structurally identical to `objstore_subtree_summary`. That
part generalizes cleanly.

But two pieces of the machinery were implicitly **object-store-typed**, and
Track 1.5 forced them to be generalized:

1. **The scope-expansion mint was `Cap::Object`-only.** `confirm_expansion`
   minted a single hardcoded capability type. Track 1.5 added an
   `ExpansionKind` (Object / Task) so the same expansion pipeline mints the
   correct capability type, with the *live generation* for Task caps. This is
   the correct generalization, not a hack — it makes mechanism 3 genuinely
   capability-type-agnostic rather than overfit. (Where it was found:
   `role.rs` `PendingExpand` + `confirm_expansion`.)

2. **The expansion-confirmation authority was hardwired to `Cap::ObjectRoot`.**
   A Task-scoped expansion to `other` can only be confirmed by a holder of
   `CONTROL` over `other` — the *same bar the grantor gate uses for the
   Task-shaped roles* — not by an object-policy singleton. Generalized the
   authorization check in `confirm_expansion` to match the capability kind.
   (Object expansions still require `ObjectRoot`, as before.)

Net: the mechanisms were ~80% general and 20% object-shaped; Track 1.5 turned
the 20% into the capability-type-agnostic form the mechanism *should* have
had. The mechanism is a real mechanism, not a well-built one-off — but it
shipped its first proof carrying an object-shaped assumption that this second
task caught.

## Residual limitations (named, not patched around)

- **Two-party confirmation (mechanism 5) is `WRITE`-gated, not
  control-gated.** A `WRITE` (object "apply") expansion requires a distinct
  second reviewer; a `CONTROL` (restart a new task) expansion currently
  requires only a *single* confirmation from a holder of `CONTROL` over the
  target. The "irreversible action" framing in §9.5 is therefore presently
  scoped to object edits, not to task control/restart. This is a real, named
  gap: a restart of a *new* task is arguably as irreversible as an object
  apply, and should arguably also be two-party. Left as a documented
  limitation rather than quietly extended, because mechanism 5's two-party
  contract is explicitly `WRITE`-shaped in the current code and changing it is
  its own decision, not a Track 1.5 side-effect.
- **The anomaly monitor is still a role-shape (op-count) check, not a learned
  model** — unchanged from Track 1; the deviation rule is the simple 2x-rate /
  unseen-op rule from `monitor.rs`.
- **The suspend monitor is never auto-trained in the production flow (closure
  audit, `SECTION9_CLOSURE_AUDIT.md`).** `role_monitor_train` is only called
  in tests (`role.rs:1872,2136`); there is no production call site that trains
  the monitor on role grant. `role_monitor_observe` is wired into every role
  exercise (`role.rs:479,551`), so once trained the breaker fires — but until
  a supervisor trains it, `observe()` is a no-op and the suspend circuit-
  breaker is dormant in a real deployment. The logic is implemented and
  test-proven; only the production training trigger is missing.
- **The boot-log demo (`demo_track15`) runs under the test harness**, same as
  every other live-verified phase; wiring both Track 1 and Track 1.5 demos
  into the physical UEFI boot path is a shared follow-up.

## Verify (independently checkable)

```
cd aegis-kernel
cargo test role::            # 19 tests: §9 x2 tasks + adversarial denial
cargo test                  # full kernel suite (818 passed, 2 ignored)
cargo clippy --all-targets  # clean (CI runs -Dwarnings)
cargo fmt --check           # clean
```
