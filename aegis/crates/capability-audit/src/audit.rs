//! The audit proper: compare reachable authority against the manifests and emit
//! violations (build breakers) and warnings (latent ceilings).
//!
//! A report is clean iff there are no violations. Warnings never fail the build —
//! they are the tool's honest answer to "what *could* happen if a grantor gets
//! lazy", which the exercised-holdings check cannot see by itself.

use crate::manifest::{Declared, Manifest, Repo};
use crate::reach;
use capability_core::{ObjectKind, Rights, TaskHandle};
use std::collections::BTreeMap;

/// A capability pair that is too powerful for a userspace service to request.
pub fn is_kernel_equivalent(pair: &Declared) -> bool {
    matches!(pair.kind, ObjectKind::Creator | ObjectKind::GrantRoot) || pair.rights == Rights::ALL
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Violation {
    /// The service holds a capability its manifest never declared.
    Undeclared { pair: Declared },
    /// A userspace repository's manifest demands kernel-equivalent authority.
    KernelEquivalent { pair: Declared },
}

impl core::fmt::Display for Violation {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Violation::Undeclared { pair } => write!(
                f,
                "holds {} with rights {} — not in the manifest (build breaks)",
                pair.kind, pair.rights
            ),
            Violation::KernelEquivalent { pair } => write!(
                f,
                "manifest demands kernel-equivalent {} rights {} from a userspace repo",
                pair.kind, pair.rights
            ),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum AuditWarning {
    /// `from` holds a GRANT-carrying naming cap into `into`, and could push narrowed
    /// copies of strictly more than `into`'s manifest declares.
    DeliveryOverhang { pair: Declared },
}

impl core::fmt::Display for AuditWarning {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            AuditWarning::DeliveryOverhang { pair } => write!(
                f,
                "delivery overhang: a GRANT-holding grantor could push {} with rights {} here",
                pair.kind, pair.rights
            ),
        }
    }
}

/// One bound service's line in the report.
#[derive(Debug, Clone)]
pub struct ServiceEntry {
    pub service: &'static str,
    pub repo: Repo,
    pub reachable: usize,
    pub declared: usize,
}

#[derive(Debug, Clone)]
pub struct AuditReport {
    pub entries: Vec<ServiceEntry>,
    pub violations: BTreeMap<&'static str, Vec<Violation>>,
    pub warnings: BTreeMap<&'static str, Vec<AuditWarning>>,
}

impl AuditReport {
    pub fn is_clean(&self) -> bool {
        self.violations.values().all(Vec::is_empty)
    }

    pub fn violation_count(&self) -> usize {
        self.violations.values().map(Vec::len).sum()
    }

    pub fn warning_count(&self) -> usize {
        self.warnings.values().map(Vec::len).sum()
    }
}

/// Bind every audited task to its manifest and run the audit. Tasks in the snapshot
/// without a binding are not audited (in this model, only bound services ship a
/// compiled manifest and a CI run).
pub fn audit(
    kernel: &capability_core::Kernel,
    bindings: &[(TaskHandle, &Manifest)],
) -> AuditReport {
    let tasks: Vec<TaskHandle> = bindings.iter().map(|(t, _)| *t).collect();
    let snap = reach::snapshot(kernel, &tasks);
    let holding = reach::holdings(&snap);
    let edges = reach::delivery_edges(&snap);

    let mut entries = Vec::new();
    let mut violations: BTreeMap<&'static str, Vec<Violation>> = BTreeMap::new();
    let mut warnings: BTreeMap<&'static str, Vec<AuditWarning>> = BTreeMap::new();

    for &(task, manifest) in bindings {
        let reachable = holding.get(&task).cloned().unwrap_or_default();
        entries.push(ServiceEntry {
            service: manifest.service,
            repo: manifest.repo,
            reachable: reachable.len(),
            declared: manifest.declares.len(),
        });

        let mut vs = Vec::new();
        for pair in &reachable {
            if !manifest.declares.contains(pair) {
                vs.push(Violation::Undeclared { pair: *pair });
            }
        }
        if !manifest.repo.is_kernel() {
            for pair in &manifest.declares {
                if is_kernel_equivalent(pair) {
                    vs.push(Violation::KernelEquivalent { pair: *pair });
                }
            }
        }
        vs.sort_by_key(|v| match v {
            Violation::Undeclared { pair } => (*pair, 0u8),
            Violation::KernelEquivalent { pair } => (*pair, 1u8),
        });
        vs.dedup();
        if !vs.is_empty() {
            violations.insert(manifest.service, vs);
        }
    }

    let bind: BTreeMap<TaskHandle, &Manifest> = bindings.iter().map(|(t, m)| (*t, *m)).collect();
    for &(from, into) in &edges {
        let (Some(mf), Some(mi)) = (bind.get(&from), bind.get(&into)) else {
            continue;
        };
        let deliverable = holding.get(&from).cloned().unwrap_or_default();
        let mut ws: Vec<AuditWarning> = deliverable
            .iter()
            .filter(|pair| !mi.declares.contains(pair))
            .map(|pair| AuditWarning::DeliveryOverhang { pair: *pair })
            .collect();
        ws.sort();
        ws.dedup();
        if !ws.is_empty() {
            let entry = warnings.entry(mi.service).or_default();
            for w in ws {
                entry.push(w);
            }
            let _ = mf;
        }
    }

    AuditReport {
        entries,
        violations,
        warnings,
    }
}
