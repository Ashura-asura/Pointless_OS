//! Service capability manifests: the declared ceiling of every service.
//!
//! A manifest names the repository class (kernel vs userspace service — the
//! repository boundary is the trust boundary, design doc §8) and the exact set of
//! (object kind, rights) pairs the service may ever hold. Anything not declared is
//! a build failure on arrival.

use capability_core::{ObjectKind, Rights};
use std::collections::BTreeSet;

/// Which repository a service ships from. Only [`Repo::Kernel`] may request
/// kernel-equivalent capabilities (design doc §10 [CLOSED]: "any repository outside
/// the kernel/bootloader repo starts requesting kernel-equivalent capabilities" is a
/// build failure).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Repo {
    Kernel,
    Service,
}

impl Repo {
    pub const fn is_kernel(self) -> bool {
        matches!(self, Repo::Kernel)
    }
}

/// One declared capability: holding an object of `kind` with at least `rights`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Declared {
    pub kind: ObjectKind,
    pub rights: Rights,
}

/// The declared authority budget of one service.
#[derive(Debug, Clone)]
pub struct Manifest {
    pub service: &'static str,
    pub repo: Repo,
    pub declares: BTreeSet<Declared>,
}

impl Manifest {
    pub const fn new(service: &'static str, repo: Repo) -> Manifest {
        Manifest {
            service,
            repo,
            declares: BTreeSet::new(),
        }
    }

    pub fn allow(mut self, kind: ObjectKind, rights: Rights) -> Manifest {
        self.declares.insert(Declared { kind, rights });
        self
    }

    pub fn declares(&self, kind: ObjectKind, rights: Rights) -> bool {
        self.declares.contains(&Declared { kind, rights })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manifest_is_a_declared_ceiling() {
        let m = Manifest::new("x", Repo::Service)
            .allow(ObjectKind::Task, Rights::READ)
            .allow(ObjectKind::MemRegion, Rights::READ.union(Rights::WRITE));
        assert!(m.declares(ObjectKind::Task, Rights::READ));
        assert!(m.declares(
            ObjectKind::MemRegion,
            Rights::READ.union(Rights::WRITE)
        ));
        assert!(!m.declares(ObjectKind::Task, Rights::CONTROL));
        assert!(!m.declares(ObjectKind::GrantRoot, Rights::GRANT));
    }
}