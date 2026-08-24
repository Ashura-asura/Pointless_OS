# §9 Delegation-Mechanism Closure Audit

*Prompt header claimed "all 5 of §9's delegation mechanisms closed" at
`214422d`. This audit reads the actual implementation (`role.rs`, `audit.rs`,
`monitor.rs`) and states per-mechanism closed / reduced / inherent honestly,
with `file:line` evidence. It corrects two inaccurate "reduced" claims I made
earlier in `POST_TRACK2_ROADMAP.md` (§9.2 and §9.4 are in fact closed) and
replaces them with the one mechanism that is genuinely reduced (§9.5).*

## Verdict per mechanism

| # | Mechanism (AEGIS_USEFUL_PROMPT §2) | Verdict | Evidence |
|---|---|---|---|
| §9.1 | Role-shaped grants | **CLOSED** (generalized) | `role.rs:144-172` role defs carry exact `rights`; `role_grant` mints exactly `role.rights` (`role.rs:339-363`); generalized to `Cap::Task` via `ExpansionKind` (`role.rs:626,648,765-771`) |
| §9.2 | Ephemeral-by-default | **CLOSED** | `set_grant_expiry` at grant (`role.rs:352-356`) and at expansion mint (`773`); `grant_valid` enforces window (`386-392`); `Expired` refused for object (`442`) and task (`607`) caps |
| §9.3 | Diff-confirmation at expansion | **CLOSED** | `request_expansion` mints nothing, returns pending id, records `RoleExpand` (`648-670`); `confirm_expansion` mints only after authorization + (for high-risk) second confirmer (`680-776`) |
| §9.4 | Persistent audit trail, queryable identity | **CLOSED** | `OpKind::{RoleGrant,RoleExercise,RoleExpand}` (`audit.rs:46-58`); emitted on grant (`357-362`), object exercise (`475,489`), task exercise (`547,563`), expand (`668,774`); queryable via `audit::op_counts` (`1701,1922,1937,1949`) |
| §9.5 | Anomaly circuit-break + two-party irreversible | **REDUCED** | see below — two named limitations, (a) two-party is `WRITE`-keyed; (b) the suspend monitor is never auto-trained in the production flow |

## §9.5 — what is actually closed vs reduced

**Closed in code + tests:**
- Lightweight shape check `reader_shape_ok` (`role.rs:778-793`) flags a
  read-only grant that mutated.
- Full **suspend-don't-revoke** monitor from `monitor.rs` is wired to role
  grants: `role_monitor_*` (`role.rs:795-843`), `observe()` is called on every
  role exercise (`479, 551`), and `AnomalyMonitor::{observe,suspend,
  is_suspended}` exist (`monitor.rs:153,217,243`). `supervisor_role_anomaly_
  suspends_on_rapid_restarts` proves the suspend fires on a real anomalous
  pattern.
- **Two-party confirmation is implemented** for `high_risk` expansions:
  `high_risk = need.contains(Rights::WRITE)` (`role.rs:649`); a second,
  distinct confirmer is required before the cap mints (`731-746`).

**Reduced — limitation (a): two-party is `WRITE`-keyed, not control-keyed.**
The "irreversible action" that triggers two-party is `WRITE`/`apply` only.
Track 1.5's restart task is `CONTROL`-shaped, so a restart-scope expansion
requires a single confirmation. Restarting a supervised task is irreversible
in practice and arguably should also be two-party, but mechanism 5 currently
keys two-party to `WRITE`. Documented in `TRACK15_SUPERVISOR.md`.

**Reduced — limitation (b): the suspend monitor is never auto-trained in the
production flow.** `role_monitor_train` is invoked only inside tests
(`role.rs:1872, 2136`) and by an explicit supervisor; there is **no**
production call site that trains the monitor when a role is granted. Because
`observe()` is a no-op when no monitor is trained (`role_monitor_observe`
returns `false` for an untrained slot, `829-837`), in a real deployment the
circuit-breaker is **dormant** — it will not suspend anyone until some
supervisor component calls `role_monitor_train`. The mechanism is real and
proven in tests; it is simply not yet connected to the live grant path.

**Inherent (not a defect, stated for honesty):** the audit trail is an
in-RAM `static mut` ring (`audit.rs`), queryable post-hoc within a run but not
crash-/reboot-persistent. "Persistent" here means durable and attributable
during the session, not written to stable storage. Making it forensic across
reboots would require a logging sink (a separate, larger phase).

## Corrections to earlier docs

- `POST_TRACK2_ROADMAP.md` status table wrongly marked §9.2 and §9.4
  "reduced". Both are **closed** (this audit). §9.5 is the only reduced
  mechanism, with limitations (a) and (b) above.
- `POST_TRACK2_ROADMAP.md` Phase D ("close §9.2/§9.4") and Phase E ("close
  §9.4 properly") describe work that is already done; the remaining §9 work
  is §9.5: (a) extend two-party gating from `WRITE`-only to
  `CONTROL`/irreversible-control, and (b) wire `role_monitor_train` into the
  production supervisor/grant flow so the suspend circuit-breaker is live.

## What would make §9.5 "closed"

1. Key two-party confirmation on `CONTROL` (or a dedicated `IRREVERSIBLE`)
   rights bit, not just `WRITE`, so restart/control expansions also require a
   second distinct confirmer.
2. Auto-train the monitor on role grant (or have the supervisor train it as
   part of delegating a role), removing the dormant-in-production gap.
3. (Optional, larger) persist the audit trail to stable storage.

None of these are blocking for the core claim — §9.1–§9.4 are genuinely
closed and §9.5's two-party + suspend logic is implemented and test-proven;
the gap is the production wiring of training, which is a small, well-scoped
follow-up.
