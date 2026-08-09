//! The audit log. Every operation — successful or failed — appends one record. This is
//! what turns "we hope the scoping was right" into "we can check whether it was".

use crate::objects::{ObjectId, ObjectKind};
use crate::rights::Rights;
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpKind {
    CreateTask,
    CreateEndpoint,
    CreateMemRegion,
    CreateGrantRoot,
    Copy,
    Grant,
    Destroy,
    Revoke,
    Send,
    Recv,
    MemRead,
    MemWrite,
    TaskKill,
    TaskSpawn,
    TaskState,
    ExpireCheck,
}

impl fmt::Display for OpKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditRecord {
    pub tick: u64,
    pub caller: ObjectId,
    pub op: OpKind,
    pub target: Option<ObjectId>,
    pub target_kind: Option<ObjectKind>,
    pub rights: Rights,
    pub ok: bool,
    pub detail: String,
}

impl AuditRecord {
    pub(crate) fn new(
        tick: u64,
        caller: ObjectId,
        op: OpKind,
        target: Option<ObjectId>,
        target_kind: Option<ObjectKind>,
        rights: Rights,
        ok: bool,
        detail: impl Into<String>,
    ) -> AuditRecord {
        AuditRecord {
            tick,
            caller,
            op,
            target,
            target_kind,
            rights,
            ok,
            detail: detail.into(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditFilter {
    All,
    Failed,
    Success,
    Ops(&'static [OpKind]),
}

#[derive(Debug, Clone, Default)]
pub struct AuditLog {
    records: Vec<AuditRecord>,
}

impl AuditLog {
    pub(crate) fn append(&mut self, rec: AuditRecord) {
        self.records.push(rec);
    }

    pub fn len(&self) -> usize {
        self.records.len()
    }

    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    /// Query the log: records for one caller, optionally filtered by outcome or op kind.
    pub fn query(
        &self,
        caller: Option<ObjectId>,
        filter: AuditFilter,
    ) -> impl Iterator<Item = &AuditRecord> {
        let iter = self.records.iter();
        iter.filter(move |r| {
            if let Some(c) = caller {
                if r.caller != c {
                    return false;
                }
            }
            match filter {
                AuditFilter::All => true,
                AuditFilter::Failed => !r.ok,
                AuditFilter::Success => r.ok,
                AuditFilter::Ops(ops) => ops.contains(&r.op),
            }
        })
    }

    /// Has this caller ever successfully performed `op` on `target`?
    pub fn ever_succeeded(
        &self,
        caller: ObjectId,
        op: OpKind,
        target: ObjectId,
    ) -> bool {
        self.query(Some(caller), AuditFilter::All)
            .any(|r| r.ok && r.op == op && r.target == Some(target))
    }
}