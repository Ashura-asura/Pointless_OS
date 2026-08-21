//! Kernel role library (master-roadmap Phase 6): task-shaped roles defined by
//! the *kernel*, not by the requesting agent. An agent execution context
//! starts with zero capabilities and can only act after being granted a role;
//! a role expands to a specific, narrow capability set — the role is the
//! reviewable unit, and the grant is an explicit, audited step.
//!
//! Two roles exist today (master roadmap §10 "broader AI orchestration" takes
//! the Phase 6 prototype to a role library — the same discipline for every new
//! role: grant, audit, adversarial denial, never a shortcut).
//!
//! - `restart-service` — the design doc's own §11.F example: READ|CONTROL over
//!   ONE named task, with no GRANT right. The grantee can read the service's
//!   state and restart it.
//! - `observe-service` — a watchdog: READ over ONE named task only. The grantee
//!   can *see* the service's state but can never restart or kill it. A
//!   monitor is a different, narrower capability — observing is not a step
//!   toward controlling, and the gate enforces that even for a fully
//!   compromised observer.
//! - `query-advisor` (master roadmap Phase F) — network access to exactly ONE
//!   kernel-declared host (`netif::ADVISOR_HOST_IP`/`ADVISOR_HOST_PORT`), and
//!   nothing else. The grantee receives a `NetEndpoint` capability that is
//!   already bound to that one destination at mint time — it never calls
//!   `sys_net_socket` itself, so it never gets to choose where the socket
//!   points, and no syscall exists to rebind an endpoint once minted. No
//!   GRANT, so the capability cannot be re-delegated. The role's own network
//!   access can *advise* — the response is data, read into a bounded buffer —
//!   but it carries none of the rights (CONTROL, GRANT) that would let it
//!   authorize anything on its own. Acting on the advice still requires
//!   whatever capability that action already needed.
//!
//!   This role's isolation from `sys_net_socket` is now backed by two
//!   independent gates, not one: even setting aside that `role_grant` mints
//!   the socket directly (never through the syscall), an advisor-role agent
//!   that somehow *did* reach `sys_net_socket` would still be refused there —
//!   it holds no `Cap::NetRoot` (see `netif::sys_net_socket`'s gate, the
//!   closure of the previously-open "any task can mint a socket to any host"
//!   gap) and `NET_RIGHTS` never includes the `CONTROL` right `NetRoot`
//!   requires. `advisor_cannot_escape_host_scope` below exercises this
//!   directly.
//!
//! Every role is declared by the kernel, installs exactly its declared right
//! set, and never carries GRANT: there is no syscall that mints GRANT onto a
//! role cap, and `role_grant` installs exactly the role's declared set. This
//! mirrors the model crate's `grants::role`.
//!
//! The agent is never in the trusted computing base: every check on what it
//! can do is enforced here, at the kernel capability gate, never by the
//! agent's own code. A fully compromised agent cannot self-escalate because
//! the gate refuses it — the agent has no code path that could widen its
//! authority even if all of it were malicious.

use crate::cap::{Cap, CapSlot, Rights, NET_RIGHTS};
use crate::tasks::{current_idx, set_task_cap, task_cap, MAX_CAPS, MAX_TASKS};

/// `restart-service` = READ|CONTROL over one named task, no GRANT.
pub const ROLE_RESTART_SERVICE: u32 = 0;
/// `observe-service` = READ over one named task only (a watchdog: it can see
/// the service's state, it can never restart or kill it), no GRANT, no CONTROL.
pub const ROLE_OBSERVE_SERVICE: u32 = 1;
/// `query-advisor` = SEND|RECV on a `NetEndpoint` bound to the one
/// kernel-declared advisor host, no GRANT. See the module docs above.
pub const ROLE_QUERY_ADVISOR: u32 = 2;

/// A role declared by the kernel. `rights` is the *exact* set the grantee
/// will be allowed — the system declares it, never the requesting agent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Role {
    pub id: u32,
    pub name: &'static str,
    pub rights: Rights,
    /// Whether the role may ever re-delegate. False for every role today:
    /// a role-granted cap never carries GRANT, so an agent cannot mint new
    /// authority from an existing grant.
    pub grants: bool,
    /// False for a `Task`-shaped role (`restart-service`, `observe-service`):
    /// the grantee receives `Cap::Task(target)` with `rights`, and `target`
    /// names the object the capability points at.
    ///
    /// True for a network-shaped role (`query-advisor`): the grantee receives
    /// a `Cap::NetEndpoint` bound to the kernel-declared advisor host, never
    /// to `target`. `target` is still required and still audited — it names
    /// the service this advisory access is granted *in the context of* (the
    /// grantor must hold at least READ over it, i.e. watchdog-level standing)
    /// — but it is not what the resulting capability points at. Keeping the
    /// same `(grantee, target, dst_slot)` grant shape lets a network-scoped
    /// role reuse the exact grant/audit pipeline every other role already
    /// goes through, rather than inventing a parallel one.
    pub network_scoped: bool,
}

/// The one role the kernel knows. The grantee may read the named service's
/// state (READ) and restart it (CONTROL); the absence of GRANT is what makes
/// self-escalation impossible at the gate.
pub const RESTART_SERVICE: Role = Role {
    id: ROLE_RESTART_SERVICE,
    name: "restart-service",
    rights: Rights::READ.union(Rights::CONTROL),
    grants: false,
    network_scoped: false,
};

/// `observe-service` = READ over one named task only. The grantee can query
/// the named service's state but has no CONTROL: restarting or killing it is
/// refused at the gate. This is the watchdog complement to `restart-service` —
/// a different, narrower capability that exists so that "monitoring" is not a
/// step toward "controlling" even for a fully compromised observer.
pub const OBSERVE_SERVICE: Role = Role {
    id: ROLE_OBSERVE_SERVICE,
    name: "observe-service",
    rights: Rights::READ,
    grants: false,
    network_scoped: false,
};

/// `query-advisor` = SEND|RECV on a `NetEndpoint` bound to the one
/// kernel-declared advisor host (`netif::ADVISOR_HOST_IP`/`ADVISOR_HOST_PORT`).
/// No GRANT — the capability cannot be re-delegated — and no CONTROL of any
/// kind: this role can read an HTTPS response into a bounded buffer and
/// nothing more. It cannot restart, kill, or grant anything; the advisory
/// answer is input to whichever role's own logic reads it, never authority.
pub const QUERY_ADVISOR: Role = Role {
    id: ROLE_QUERY_ADVISOR,
    name: "query-advisor",
    rights: NET_RIGHTS,
    grants: false,
    network_scoped: true,
};

/// The role registry. Reviewable once per role type, not per grant.
pub const ALL_ROLES: [Role; 3] = [RESTART_SERVICE, OBSERVE_SERVICE, QUERY_ADVISOR];

/// Look up a role by id.
pub fn lookup(id: u32) -> Option<&'static Role> {
    ALL_ROLES.iter().find(|r| r.id == id)
}

/// Syscall 18: grant role `role_id` over task `target` to `grantee`, installing
/// the role's exact capability set at `dst_slot` in the grantee's CSpace.
///
/// Gate (kernel-enforced; the agent's own code never checks itself): the
/// *grantor* — the currently running task — must hold a Task capability on
/// `target` carrying at least the role's exact rights. A grantor with no
/// authority over the target is refused. The role is declared by the kernel,
/// so the grantee receives exactly the role's set and nothing else.
///
/// Returns 0 on success, -1 on any refusal. Never panics: every argument is
/// bounds-checked before any table is touched, and every outcome (success and
/// refusal alike) is recorded in the kernel audit log (`OpKind::RoleGrant`).
pub fn role_grant(role_id: u64, grantee: u64, target: u64, dst_slot: u64) -> i64 {
    let cur = current_idx();
    let role = match lookup(role_id as u32) {
        Some(r) => r,
        None => {
            crate::audit::record(
                cur,
                crate::audit::OpKind::RoleGrant,
                Some(target as u32),
                false,
            );
            return -1;
        }
    };
    // Bounds-check both tables before touching either (a malformed argument
    // must be refused, never a panic). `target` too: it names a task table
    // slot, and a stale or out-of-range target must never be minted into a
    // capability.
    if (grantee as usize) >= MAX_TASKS
        || (dst_slot as usize) >= MAX_CAPS
        || (target as usize) >= MAX_TASKS
    {
        crate::audit::record(
            cur,
            crate::audit::OpKind::RoleGrant,
            Some(target as u32),
            false,
        );
        return -1;
    }
    // The grantor must hold a Task cap on `target` carrying enough authority
    // to make this grant. For a Task-shaped role that means the role's exact
    // rights (the grantor can only hand out what it already has). For a
    // network-shaped role (`query-advisor`) `target` is not what the grantee
    // ends up holding — it is the service this advisory access is granted in
    // the context of — so the bar is watchdog-level standing (READ) over
    // that service, matching the spec's own wiring: the observe-service
    // watchdog is what earns the right to ask for advice about what it
    // watches.
    let required = if role.network_scoped {
        Rights::READ
    } else {
        role.rights
    };
    let authorized = (0..MAX_CAPS).any(|s| match task_cap(cur, s) {
        CapSlot {
            cap: Cap::Task(t_oid),
            rights,
        } => {
            // The cap must name the target AND still be live (the generation
            // must match the task that currently occupies the slot): a stale
            // capability minted against a previous occupant of `target`'s
            // index must not authorize a grant over whoever lives there now.
            t_oid.index as usize == target as usize
                && crate::tasks::task_generation(target as usize) == t_oid.generation
                && rights.contains(required)
        }
        _ => false,
    });
    if !authorized {
        crate::audit::record(
            cur,
            crate::audit::OpKind::RoleGrant,
            Some(target as u32),
            false,
        );
        return -1;
    }
    // The role is declared by the kernel: install exactly its rights. A role
    // never carries GRANT, so the grantee cannot re-delegate the role.
    if role.network_scoped {
        // The grantee never calls `sys_net_socket` for this capability — the
        // kernel mints the socket itself, bound to the one host it declares.
        // The agent has no code path that could choose a different
        // destination, because there is no argument here for it to supply.
        let Some(oid) = crate::netif::open_advisor_endpoint() else {
            crate::audit::record(
                cur,
                crate::audit::OpKind::RoleGrant,
                Some(target as u32),
                false,
            );
            return -1;
        };
        set_task_cap(
            grantee as usize,
            dst_slot as usize,
            CapSlot {
                cap: Cap::NetEndpoint(oid),
                rights: role.rights,
            },
        );
    } else {
        // Mint the grantee's capability against the CURRENT identity of the
        // target slot (bounds-checked above): the grantee must name the task
        // that is actually there, with a live generation.
        let Some(oid) = crate::tasks::task_oid(target as usize) else {
            crate::audit::record(
                cur,
                crate::audit::OpKind::RoleGrant,
                Some(target as u32),
                false,
            );
            return -1;
        };
        set_task_cap(
            grantee as usize,
            dst_slot as usize,
            CapSlot {
                cap: Cap::Task(oid),
                rights: role.rights,
            },
        );
    }
    crate::audit::record(
        cur,
        crate::audit::OpKind::RoleGrant,
        Some(target as u32),
        true,
    );
    0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::supervisor::{task_kill, task_restart, task_state};
    use crate::tasks::{set_current_for_test, spawn};

    extern "sysv64" fn dummy() -> ! {
        loop {
            core::hint::spin_loop();
        }
    }

    fn clean_world() {
        crate::audit::reset_for_test();
        crate::tasks::reset_table_for_test();
        for i in 0..MAX_TASKS {
            for s in 0..MAX_CAPS {
                set_task_cap(i, s, CapSlot::empty());
            }
        }
    }

    /// The DoD grant test: a grantor holding the role's rights over the target
    /// grants `restart-service` to a zero-cap agent. The agent receives EXACTLY
    /// READ|CONTROL over the named task — READ to query state, CONTROL to
    /// restart it — and no GRANT. The granted cap rides the real gates: the
    /// agent can observe and restart the crashed service.
    #[test]
    fn agent_role_grant() {
        let _g = crate::kernel_state_guard();
        clean_world();
        unsafe {
            // svc = task 0, grantor = task 1, agent = task 2.
            let (svc, grantor, agent) = (0usize, 1usize, 2usize);
            spawn("svc", dummy, 0x100000).unwrap();
            spawn("grantor", dummy, 0x200000).unwrap();
            spawn("agent", dummy, 0x300000).unwrap();
            // The agent starts with zero capabilities: a role grant is the only
            // way it acquires authority.
            assert!((0..MAX_CAPS).all(|s| task_cap(agent, s).cap == Cap::None));
            // The grantor holds READ|CONTROL over the service — the role's
            // exact rights — installed by the kernel as the scripted stand-in.
            set_task_cap(
                grantor,
                0,
                CapSlot {
                    cap: Cap::Task(crate::cap::Oid::new(svc as u32, 0)),
                    rights: Rights::READ.union(Rights::CONTROL),
                },
            );
            set_current_for_test(grantor);
            assert_eq!(
                role_grant(ROLE_RESTART_SERVICE as u64, agent as u64, svc as u64, 0),
                0
            );
            // The grantee's slot 0 is exactly the role's set: Task(svc) with
            // READ|CONTROL and no GRANT.
            let got = task_cap(agent, 0);
            assert_eq!(got.cap, Cap::Task(crate::cap::Oid::new(svc as u32, 0)));
            assert!(got.rights.contains(Rights::READ));
            assert!(got.rights.contains(Rights::CONTROL));
            assert!(!got.rights.contains(Rights::GRANT), "role never grants");
            assert_eq!(
                got.rights.bits(),
                (Rights::READ.union(Rights::CONTROL)).bits()
            );
            // The granted cap rides the real gates, now as the agent.
            set_current_for_test(agent);
            assert_eq!(task_state(0), 1, "READ lets the agent query the service");
            crate::tasks::kill_task(svc);
            assert_eq!(task_state(0), 0, "service is dead");
            assert_eq!(task_restart(0), 0, "CONTROL lets the agent restart it");
            assert!(
                crate::tasks::is_task_alive(svc),
                "the agent's one real task succeeded"
            );
        }
    }

    /// The headline Phase-6 result: the agent cannot self-escalate, and the
    /// refusal is the kernel's, not the agent's. The agent holds only the
    /// granted `restart-service` cap (READ|CONTROL, no GRANT). Every attempt to
    /// widen that authority is refused at the capability gate: delegating the
    /// role needs GRANT (denied), controlling a task it was never granted
    /// needs a Task cap over it (denied), and re-granting a role over a task
    /// the grantor does not control is refused. There is no syscall that mints
    /// GRANT onto a role cap, so the agent has no code path that could
    /// escalate even if every line of it were compromised.
    #[test]
    fn agent_cannot_self_escalate() {
        let _g = crate::kernel_state_guard();
        clean_world();
        unsafe {
            // svc = task 0, other = task 1, grantor = task 2, agent = task 3.
            let (svc, other, grantor, agent) = (0usize, 1usize, 2usize, 3usize);
            spawn("svc", dummy, 0x100000).unwrap();
            spawn("other", dummy, 0x200000).unwrap();
            spawn("grantor", dummy, 0x300000).unwrap();
            spawn("agent", dummy, 0x400000).unwrap();
            // Grantor grants the role to the agent.
            set_task_cap(
                grantor,
                0,
                CapSlot {
                    cap: Cap::Task(crate::cap::Oid::new(svc as u32, 0)),
                    rights: Rights::READ.union(Rights::CONTROL),
                },
            );
            set_current_for_test(grantor);
            assert_eq!(
                role_grant(ROLE_RESTART_SERVICE as u64, agent as u64, svc as u64, 0),
                0
            );
            set_current_for_test(agent);

            // 1) Delegating the role onward requires GRANT on the role cap —
            //    the role has none, so the grant is denied at the gate.
            assert_eq!(
                crate::ipc::ipc_cap_grant(other as u64, 0, 0),
                -1,
                "no GRANT in the role: the agent cannot re-delegate"
            );
            assert_eq!(
                task_cap(other, 0).cap,
                Cap::None,
                "nothing landed in the peer's CSpace"
            );

            // 2) Controlling a task it was never granted requires a Task cap
            //    over it — the agent holds only the service cap, so kill and
            //    restart of the other task are denied.
            set_task_cap(
                agent,
                1,
                CapSlot {
                    cap: Cap::Task(crate::cap::Oid::new(other as u32, 0)),
                    rights: Rights::READ,
                },
            );
            // Even with READ on the other task, CONTROL is absent: no restart.
            assert_eq!(task_restart(1), -1, "CONTROL is per-task, never ambient");

            // 3) Re-granting itself a role over a task the grantor does not
            //    control is refused — the grantor gate checks authority over
            //    the target, not the grantee's wishes.
            assert_eq!(
                role_grant(ROLE_RESTART_SERVICE as u64, agent as u64, other as u64, 2),
                -1,
                "no Task cap with the role's rights over the other task"
            );

            // 4) There is no widening syscall at all: the agent cannot mint
            //    GRANT onto its own cap. The audit log attributes every step —
            //    the agent's only Grant record is the refusal above, never a
            //    success.
            assert_eq!(
                crate::audit::op_counts(agent)[crate::audit::OpKind::Grant.index()],
                1,
                "the agent's only Grant record is its refused delegation"
            );
            assert!(!crate::audit::ever_succeeded(
                agent,
                crate::audit::OpKind::Grant,
                svc as u32
            ));
            // The audit log attributes every step: the grantor's role grant
            // succeeded, and the agent's own role-grant attempts are denials —
            // the agent never successfully performed a role grant.
            assert!(crate::audit::ever_succeeded(
                grantor,
                crate::audit::OpKind::RoleGrant,
                svc as u32
            ));
            assert!(
                !crate::audit::ever_succeeded(agent, crate::audit::OpKind::RoleGrant, svc as u32),
                "the agent never successfully granted itself anything"
            );
        }
    }

    /// §10 "broader AI orchestration": a second role through the SAME
    /// discipline as Phase 6. A grantor holding READ over the service grants
    /// `observe-service` to a zero-cap agent. The agent receives EXACTLY READ —
    /// no CONTROL, no GRANT. It can query the service's state (its one real
    /// task as a watchdog) but restarting the crashed service is refused at the
    /// gate: observation never becomes control.
    #[test]
    fn observer_role_grant() {
        let _g = crate::kernel_state_guard();
        clean_world();
        unsafe {
            // svc = task 0, grantor = task 1, agent = task 2.
            let (svc, grantor, agent) = (0usize, 1usize, 2usize);
            spawn("svc", dummy, 0x100000).unwrap();
            spawn("grantor", dummy, 0x200000).unwrap();
            spawn("agent", dummy, 0x300000).unwrap();
            // The agent starts with zero capabilities.
            assert!((0..MAX_CAPS).all(|s| task_cap(agent, s).cap == Cap::None));
            // The grantor holds READ over the service — the observe role's
            // exact right set — as the scripted stand-in for a human reviewer.
            set_task_cap(
                grantor,
                0,
                CapSlot {
                    cap: Cap::Task(crate::cap::Oid::new(svc as u32, 0)),
                    rights: Rights::READ,
                },
            );
            set_current_for_test(grantor);
            assert_eq!(
                role_grant(ROLE_OBSERVE_SERVICE as u64, agent as u64, svc as u64, 0),
                0
            );
            // The grantee's slot 0 is exactly the role's set: Task(svc) with
            // READ only, no CONTROL, no GRANT.
            let got = task_cap(agent, 0);
            assert_eq!(got.cap, Cap::Task(crate::cap::Oid::new(svc as u32, 0)));
            assert!(got.rights.contains(Rights::READ));
            assert!(
                !got.rights.contains(Rights::CONTROL),
                "watchdog has no CONTROL"
            );
            assert!(!got.rights.contains(Rights::GRANT), "role never grants");
            assert_eq!(got.rights.bits(), Rights::READ.bits());
            // The granted cap rides the real gates, now as the agent.
            set_current_for_test(agent);
            assert_eq!(task_state(0), 1, "READ lets the watchdog query the service");
            // The one thing a watchdog must NOT be able to do: restart.
            crate::tasks::kill_task(svc);
            assert_eq!(task_state(0), 0, "the watchdog can see it crashed");
            assert_eq!(
                task_restart(0),
                -1,
                "observation never becomes control: restart refused at the gate"
            );
            assert!(!crate::tasks::is_task_alive(svc), "the service stays dead");
        }
    }

    /// §10: the observe agent cannot turn its watch into a restart. Its cap is
    /// exactly READ over the service — no CONTROL, no GRANT — so restarting,
    /// killing, delegating, or re-granting itself `restart-service` is refused
    /// by the kernel capability gate. Same adversarial discipline as Phase 6,
    /// applied to the second role.
    #[test]
    fn observer_cannot_self_escalate() {
        let _g = crate::kernel_state_guard();
        clean_world();
        unsafe {
            // svc = task 0, other = task 1, grantor = task 2, agent = task 3.
            let (svc, other, grantor, agent) = (0usize, 1usize, 2usize, 3usize);
            spawn("svc", dummy, 0x100000).unwrap();
            spawn("other", dummy, 0x200000).unwrap();
            spawn("grantor", dummy, 0x300000).unwrap();
            spawn("agent", dummy, 0x400000).unwrap();
            // Grantor grants the observe role to the agent.
            set_task_cap(
                grantor,
                0,
                CapSlot {
                    cap: Cap::Task(crate::cap::Oid::new(svc as u32, 0)),
                    rights: Rights::READ,
                },
            );
            set_current_for_test(grantor);
            assert_eq!(
                role_grant(ROLE_OBSERVE_SERVICE as u64, agent as u64, svc as u64, 0),
                0
            );
            set_current_for_test(agent);

            // 1) Delegating the role onward needs GRANT — the role has none.
            assert_eq!(
                crate::ipc::ipc_cap_grant(other as u64, 0, 0),
                -1,
                "no GRANT in the observe role: the agent cannot re-delegate"
            );

            // 2) Restarting the service needs CONTROL — the observe role has
            //    none. Even after the service dies, the watchdog can only watch.
            crate::tasks::kill_task(svc);
            assert_eq!(task_restart(0), -1, "CONTROL is per-task, never ambient");

            // 3) Killing a task it was never granted needs CONTROL — refused.
            assert_eq!(task_kill(1), -1, "no CONTROL over the other task");

            // 4) Re-granting itself `restart-service` over the service needs a
            //    Task cap with READ|CONTROL over it — the agent holds only READ,
            //    so the grantor gate refuses.
            assert_eq!(
                role_grant(ROLE_RESTART_SERVICE as u64, agent as u64, svc as u64, 2),
                -1,
                "a watchdog cannot upgrade its observe role to a restart role"
            );

            // 5) The audit log attributes everything: the agent's Grant and
            //    RoleGrant records are denials only — it never succeeded at
            //    anything it was not granted.
            assert!(!crate::audit::ever_succeeded(
                agent,
                crate::audit::OpKind::RoleGrant,
                svc as u32
            ));
            assert!(!crate::audit::ever_succeeded(
                agent,
                crate::audit::OpKind::TaskSpawn,
                svc as u32
            ));
        }
    }

    /// The gate refuses unknown roles and out-of-range targets with -1, never
    /// a panic, and records the refusal.
    #[test]
    fn role_grant_never_panics_and_denies_garbage() {
        let _g = crate::kernel_state_guard();
        clean_world();
        unsafe {
            spawn("svc", dummy, 0x100000).unwrap();
            spawn("grantor", dummy, 0x200000).unwrap();
            let (svc, grantor, agent) = (0usize, 1usize, 2usize);
            set_task_cap(
                grantor,
                0,
                CapSlot {
                    cap: Cap::Task(crate::cap::Oid::new(svc as u32, 0)),
                    rights: Rights::READ.union(Rights::CONTROL),
                },
            );
            set_current_for_test(grantor);
            // Unknown role id.
            assert_eq!(role_grant(999, agent as u64, svc as u64, 0), -1);
            // Out-of-range grantee task.
            assert_eq!(
                role_grant(
                    ROLE_RESTART_SERVICE as u64,
                    MAX_TASKS as u64 + 5,
                    svc as u64,
                    0
                ),
                -1
            );
            // Out-of-range destination slot.
            assert_eq!(
                role_grant(
                    ROLE_RESTART_SERVICE as u64,
                    agent as u64,
                    svc as u64,
                    MAX_CAPS as u64 + 5
                ),
                -1
            );
            // A grantor with no authority over the target is refused.
            set_current_for_test(agent);
            assert_eq!(
                role_grant(ROLE_RESTART_SERVICE as u64, grantor as u64, svc as u64, 0),
                -1
            );
            // No capability ever landed.
            assert_eq!(task_cap(agent, 0).cap, Cap::None);
            assert_eq!(
                task_cap(grantor, 0).cap,
                Cap::Task(crate::cap::Oid::new(svc as u32, 0))
            );
        }
    }

    /// Phase F: the DoD grant test for `query-advisor`. A grantor holding
    /// READ over the watched service (watchdog-level standing) grants
    /// `query-advisor` to a zero-cap agent. The agent receives a
    /// `NetEndpoint` — NOT a `Task` cap — bound to the kernel-declared
    /// advisor host, with exactly SEND|RECV and no GRANT.
    #[test]
    fn advisor_role_grant() {
        let _g = crate::kernel_state_guard();
        clean_world();
        unsafe {
            // svc = task 0, grantor = task 1, agent = task 2.
            let (svc, grantor, agent) = (0usize, 1usize, 2usize);
            spawn("svc", dummy, 0x100000).unwrap();
            spawn("grantor", dummy, 0x200000).unwrap();
            spawn("agent", dummy, 0x300000).unwrap();
            assert!((0..MAX_CAPS).all(|s| task_cap(agent, s).cap == Cap::None));
            // The grantor holds READ over the service — watchdog-level
            // standing is enough to ask for advice about what it watches.
            set_task_cap(
                grantor,
                0,
                CapSlot {
                    cap: Cap::Task(crate::cap::Oid::new(svc as u32, 0)),
                    rights: Rights::READ,
                },
            );
            set_current_for_test(grantor);
            assert_eq!(
                role_grant(ROLE_QUERY_ADVISOR as u64, agent as u64, svc as u64, 0),
                0
            );
            let got = task_cap(agent, 0);
            let id = match got.cap {
                Cap::NetEndpoint(id) => id,
                other => panic!("query-advisor must grant a NetEndpoint, got {other:?}"),
            };
            assert!(got.rights.contains(Rights::SEND));
            assert!(got.rights.contains(Rights::RECV));
            assert!(!got.rights.contains(Rights::GRANT), "role never grants");
            assert!(
                !got.rights.contains(Rights::CONTROL),
                "advisory access carries no CONTROL of anything"
            );
            assert_eq!(got.rights.bits(), crate::cap::NET_RIGHTS.bits());
            // The socket the kernel minted is bound to exactly the
            // kernel-declared advisor host — not `svc`, not anything the
            // grantor or agent named.
            assert_eq!(
                crate::netif::socket_remote(id.index as u16),
                Some((
                    crate::netif::ADVISOR_HOST_IP,
                    crate::netif::ADVISOR_HOST_PORT
                )),
                "the granted endpoint is bound to the one kernel-declared advisor host"
            );
        }
    }

    /// Phase F headline result: the query-advisor agent cannot parlay its one
    /// narrow network capability into anything beyond reading a response from
    /// its pre-approved host. Every escape attempt is refused by the kernel
    /// capability gate, not by any check in the agent's own logic.
    #[test]
    fn advisor_cannot_escape_host_scope() {
        let _g = crate::kernel_state_guard();
        clean_world();
        unsafe {
            // svc = task 0, other = task 1, grantor = task 2, agent = task 3.
            let (svc, other, grantor, agent) = (0usize, 1usize, 2usize, 3usize);
            spawn("svc", dummy, 0x100000).unwrap();
            spawn("other", dummy, 0x200000).unwrap();
            spawn("grantor", dummy, 0x300000).unwrap();
            spawn("agent", dummy, 0x400000).unwrap();
            set_task_cap(
                grantor,
                0,
                CapSlot {
                    cap: Cap::Task(crate::cap::Oid::new(svc as u32, 0)),
                    rights: Rights::READ,
                },
            );
            set_current_for_test(grantor);
            assert_eq!(
                role_grant(ROLE_QUERY_ADVISOR as u64, agent as u64, svc as u64, 0),
                0
            );
            let advisor_slot_cap = task_cap(agent, 0);
            let Cap::NetEndpoint(net_id) = advisor_slot_cap.cap else {
                panic!("setup: expected a NetEndpoint cap");
            };
            set_current_for_test(agent);

            // 1) No syscall exists to rebind an endpoint's destination: the
            //    binding recorded on the live socket is still exactly the
            //    advisor host, unchanged, after the agent holds the cap.
            assert_eq!(
                crate::netif::socket_remote(net_id.index as u16),
                Some((
                    crate::netif::ADVISOR_HOST_IP,
                    crate::netif::ADVISOR_HOST_PORT
                )),
                "nothing the agent can do rebinds the granted endpoint"
            );

            // 2) Delegating the role onward needs GRANT — the role has none.
            assert_eq!(
                crate::ipc::ipc_cap_grant(other as u64, 0, 1),
                -1,
                "no GRANT in query-advisor: the agent cannot re-delegate its network access"
            );

            // 3) The agent holds no Task capability at all (its one cap is a
            //    NetEndpoint), so it cannot act as a role_grant grantor over
            //    ANY target — it has no authority to escalate itself into
            //    restart-service, observe-service, or a second advisor grant
            //    naming a different host-adjacent target.
            assert_eq!(
                role_grant(ROLE_RESTART_SERVICE as u64, agent as u64, svc as u64, 2),
                -1,
                "a NetEndpoint cap carries no Task authority to grant from"
            );
            assert_eq!(
                role_grant(ROLE_QUERY_ADVISOR as u64, agent as u64, other as u64, 2),
                -1,
                "the agent cannot mint itself a second advisor grant either"
            );

            // 4) The one capability the agent holds cannot be used to control
            //    the service it's advising about: CONTROL was never part of
            //    NET_RIGHTS, so there is no restart/kill path through it —
            //    unlike restart-service, nothing here ever touches
            //    supervisor::task_restart/task_kill in the first place.
            assert!(
                !advisor_slot_cap.rights.contains(Rights::CONTROL),
                "advisory network access was never wired to any control right"
            );

            // 5) The audit trail attributes everything: the agent never
            //    succeeded at a RoleGrant naming a target other than the one
            //    it was legitimately granted advisory context for.
            assert!(!crate::audit::ever_succeeded(
                agent,
                crate::audit::OpKind::RoleGrant,
                svc as u32
            ));
            assert!(!crate::audit::ever_succeeded(
                agent,
                crate::audit::OpKind::RoleGrant,
                other as u32
            ));

            // 6) Phase E item 2 closure, checked in the Phase F context
            //    specifically: even setting aside that `role_grant` never
            //    routes through `sys_net_socket` at all, the agent could
            //    not have reached raw socket-minting authority even if it
            //    tried directly — it holds no `Cap::NetRoot` anywhere in
            //    its CSpace (its one cap is the granted `NetEndpoint`), so
            //    the syscall-level gate refuses it independently of the
            //    role system. Two gates, not one: this is what the
            //    project's own honest-status note flagged as still open
            //    ("any task can mint a socket to any host directly") and
            //    what closes it.
            assert_eq!(
                crate::netif::sys_net_socket(1, 0x0A000202, 8080),
                -1,
                "no Cap::NetRoot anywhere in the agent's CSpace: sys_net_socket refuses it"
            );
            assert!(
                (0..MAX_CAPS).all(|s| task_cap(agent, s).cap != Cap::NetRoot),
                "the query-advisor grant never installs NetRoot"
            );
        }
    }
}
