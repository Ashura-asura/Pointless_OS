//! The resource model (design doc §8): hierarchical budgets over the
//! supervision tree, metered from kernel truth, enforced by the governor's
//! recycle — not by forging new kernel authority.
//!
//! The kernel's close contract already *is* resource control at the authority
//! boundary: a task can only touch what it holds, and memory is only what its
//! caps can reach. What the design doc leaves to the tree is *budgeting*: the
//! supervisor divides a total budget hierarchically, meters actual use from the
//! kernel's own records, and recycles an over-budget service by revoking its
//! install anchor — the same ordinary revocation any software is subject to.
//! A service can never overrun authority, only its budget; recycling it
//! returns the world to its envelope.
//!
//! Honest limits: CPU time is metered as ops in the kernel audit log (every
//! op is one executed unit; the log is the scheduler's clock), memory as the
//! WRITE-reachable bytes of a task's live regions, and v1 has no dynamic
//! re-scheduling — a recycled service must be reinstalled with the same
//! budget.

use capability_core::{AuditFilter, CapHandle, Kernel, ObjectKind, Rights, TaskHandle};

/// CPU in "executed op" units — every successful audit record attributed to a
/// task is one unit of its running time (the audit log is the scheduler's
/// clock).
pub type CpuUnits = u64;

/// Memory in bytes a task could write through caps it actually holds.
pub type MemBytes = u64;

/// One service's envelope.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Budget {
    pub cpu: CpuUnits,
    pub mem: MemBytes,
}

impl Budget {
    pub const ZERO: Budget = Budget { cpu: 0, mem: 0 };
}

/// The allocation ledger: a hierarchy of budgets mirroring the supervision
/// tree. Children are subdivisions of their parent: the ledger refuses an
/// overcommit (a parent cannot hand out more than it was given — giving is
/// losing) and refuses a second parent (the tree stays a tree), so a fixed
/// total can never be stretched by accounting.
#[derive(Debug)]
pub struct Alloc {
    pub total: Budget,
    nodes: Vec<Node>,
}

#[derive(Debug)]
pub struct Node {
    pub task: TaskHandle,
    pub budget: Budget,
    pub parent: Option<usize>,
    pub children: Vec<usize>,
}

impl Alloc {
    pub fn root(task: TaskHandle, total: Budget) -> Alloc {
        Alloc {
            total,
            nodes: vec![Node {
                task,
                budget: total,
                parent: None,
                children: Vec::new(),
            }],
        }
    }

    /// What `parent` already committed to its children.
    fn committed(&self, parent: usize) -> Budget {
        self.nodes[parent]
            .children
            .iter()
            .fold(Budget::ZERO, |acc, &i| Budget {
                cpu: acc.cpu + self.nodes[i].budget.cpu,
                mem: acc.mem + self.nodes[i].budget.mem,
            })
    }

    /// Give `child` a budget carved out of `parent`'s. The child is registered
    /// on demand and must not already have a parent; the grant must not
    /// overcommit the parent's envelope. Refused allocations change nothing.
    pub fn give(
        &mut self,
        parent: TaskHandle,
        child: TaskHandle,
        budget: Budget,
    ) -> Result<(), &'static str> {
        let parent_idx = self
            .nodes
            .iter()
            .position(|n| n.task == parent)
            .ok_or("unknown parent: the ledger only divides what the tree has")?;
        let given = self.committed(parent_idx);
        if given
            .cpu
            .checked_add(budget.cpu)
            .map_or(true, |c| c > self.nodes[parent_idx].budget.cpu)
            || given
                .mem
                .checked_add(budget.mem)
                .map_or(true, |m| m > self.nodes[parent_idx].budget.mem)
        {
            return Err("overcommit refused: a parent cannot subdivide more than it holds");
        }
        if let Some(existing) = self.nodes.iter().position(|n| n.task == child) {
            if self.nodes[existing].parent.is_some() {
                return Err("a service has exactly one parent: the tree stays a tree");
            }
            self.nodes[existing].budget = budget;
            self.nodes[existing].parent = Some(parent_idx);
        } else {
            self.nodes.push(Node {
                task: child,
                budget,
                parent: Some(parent_idx),
                children: Vec::new(),
            });
        }
        let child_idx = self.nodes.iter().position(|n| n.task == child).unwrap();
        self.nodes[parent_idx].children.push(child_idx);
        Ok(())
    }

    /// What `task` still has to give away: its own budget minus everything it
    /// already committed to children.
    pub fn remaining(&self, task: TaskHandle) -> Option<Budget> {
        let idx = self.nodes.iter().position(|n| n.task == task)?;
        let given = self.committed(idx);
        Some(Budget {
            cpu: self.nodes[idx].budget.cpu - given.cpu,
            mem: self.nodes[idx].budget.mem - given.mem,
        })
    }

    /// Ledger round-trip: what the root could hand out is exactly what was
    /// handed to its subtree's toplevels plus what it kept.
    pub fn entry(&self, task: TaskHandle) -> Option<&Node> {
        self.nodes.iter().find(|n| n.task == task)
    }
}

/// Kernel-truth metering. Neither meter trusts any bookkeeping other than the
/// kernel's own: the audit log for CPU, the cap tables for memory.
pub struct Meter;

impl Meter {
    /// CPU spent: every successful audit record attributed to the task. The
    /// log is append-only and attributed by the kernel, so this is exactly
    /// what the task executed — nothing more, nothing less.
    pub fn cpu_spent(k: &Kernel, task: TaskHandle) -> CpuUnits {
        k.audit()
            .query(Some(task.id()), AuditFilter::Success)
            .count() as CpuUnits
    }

    /// Resident memory: total bytes the task could currently write through
    /// WRITE-bearing region caps — the direct cap-table truth.
    pub fn resident(k: &mut Kernel, task: TaskHandle) -> MemBytes {
        let mut total = 0u64;
        for slot in 0..256u32 {
            if let Ok(info) = k.cap_info(task, CapHandle(slot)) {
                if info.kind == ObjectKind::MemRegion && info.rights.contains(Rights::WRITE) {
                    if let Ok(len) = k.mem_len(task, CapHandle(slot)) {
                        total += len as u64;
                    }
                }
            }
        }
        total
    }
}

/// The governor: recycle an over-budget service by revoking its install anchor
/// (every minted cap dies) — exactly the revocation any software is subject
/// to; the controller holds no special authority, only the anchors installs
/// created. The kernel remains the only enforcer of anything.
pub fn recycle(k: &mut Kernel, owner: TaskHandle, anchor: CapHandle) -> Result<(), ()> {
    k.revoke(owner, anchor).map_err(|_| ())
}