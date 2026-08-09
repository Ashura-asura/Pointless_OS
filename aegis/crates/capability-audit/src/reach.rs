//! Reachability: what a task actually holds, and which delegation edges exist.
//!
//! `holdings(t)` is the set of (kind, rights) pairs exercisable *now* — liveness is
//! the kernel's rule (expired caps are not projected). The task's own self cap is
//! structural (kernel-enforced lifecycle control of itself only) and is excluded, so
//! manifests declare *external* authority, not the mandatory self slot.
//!
//! `edges(t)` = tasks where t holds a GRANT-carrying naming cap: t could push
//! narrowed copies of everything it holds into that task's table (I2 clamps rights,
//! so the ceiling is exactly holdings(t)). The auditor surfaces those edges as
//! delivery-overhang warnings when the target's manifest is narrower.

use crate::manifest::Declared;
use capability_core::{CapView, Kernel, ObjectId, ObjectKind, Rights, TaskHandle};
use std::collections::{BTreeMap, BTreeSet};

/// The authority unit: a declared pair (kind, rights).
pub type Authority = BTreeSet<Declared>;

/// Per-task live caps, projected by the kernel (expiry already filtered).
pub fn snapshot(kernel: &Kernel, tasks: &[TaskHandle]) -> BTreeMap<TaskHandle, Vec<CapView>> {
    tasks
        .iter()
        .map(|&t| (t, kernel.caps_of(t)))
        .collect()
}

/// One self cap is mandatory for every task (kernel-enforced); it confers control of
/// the task's own lifecycle and nothing outside it, so it never has to be declared.
fn is_structural_self(t: TaskHandle, cap: CapView) -> bool {
    cap.obj == t.id() && cap.kind == ObjectKind::Task
}

/// What each task can currently exercise, self cap excluded.
pub fn holdings<'a>(snap: &'a BTreeMap<TaskHandle, Vec<CapView>>) -> BTreeMap<TaskHandle, Authority> {
    snap.iter()
        .map(|(&t, caps)| {
            let authority = caps
                .iter()
                .filter(|c| !is_structural_self(t, **c))
                .map(|c| Declared {
                    kind: c.kind,
                    rights: c.rights,
                })
                .collect();
            (t, authority)
        })
        .collect()
}

/// Delegation edges: `from` could push narrowed copies of everything it holds into
/// `into` because it holds a GRANT-carrying cap naming that task (I6 does not lift
/// this ceiling — consent gates *delivery*, not the authority deliverable).
///
/// Targets resolve only against the tasks in the snapshot: identity is kernel-owned
/// (a `TaskHandle` cannot be fabricated from an object id), so the auditor never
/// names a task it was not given.
pub fn delivery_edges(snap: &BTreeMap<TaskHandle, Vec<CapView>>) -> Vec<(TaskHandle, TaskHandle)> {
    let known: BTreeMap<ObjectId, TaskHandle> = snap.keys().map(|&t| (t.id(), t)).collect();
    let mut out = Vec::new();
    for (&from, caps) in snap {
        for cap in caps {
            if cap.kind == ObjectKind::Task
                && cap.rights.contains(Rights::GRANT)
                && !is_structural_self(from, *cap)
            {
                if let Some(&into) = known.get(&cap.obj) {
                    out.push((from, into));
                }
            }
        }
    }
    out.sort();
    out.dedup();
    out
}