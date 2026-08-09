//! The update architecture (design doc §8): staged, health-gated, transactional
//! generations with a rollback that needs no capability authority at all.
//!
//! A generation is a fully installed system — booted from the store, not from
//! memory. The boot target is store *content*: the `current` file in a POSIX
//! view holds the generation descriptor, so switching generations is one COW
//! pointer flip in the store and nothing else. Staging installs a candidate
//! generation without touching the current one; activation requires the staged
//! generation to pass a user-supplied health check; rollback flips the pointer
//! back — the contract tests count the kernel-op records and prove the
//! rollback path executes zero authority operations (no grant, no revoke, no
//! spawn, no creation-root).
//!
//! The update machinery's *entire* authority is the install machinery it
//! already ships ([`packages::PackageManager::install`]) plus READ/WRITE on the
//! boot-view store object — generations are data, not principals, and the
//! updater is not a second root.

use capability_core::{Kernel, KernelError, KernelResult};
use object_store::{FlatView, Store};
use packages::{InstalledApp, Package, PackageManager};

/// The descriptor of one installed generation, persisted in the boot view.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GenerationDescriptor {
    pub n: u64,
    pub package: String,
}

/// Descriptor ↔ bytes: a tiny, dependency-free envelope ("n\nname").
pub fn encode_descriptor(d: &GenerationDescriptor) -> Vec<u8> {
    format!("{}\n{}", d.n, d.package).into_bytes()
}

pub fn decode_descriptor(b: &[u8]) -> Option<GenerationDescriptor> {
    let s = std::str::from_utf8(b).ok()?;
    let (n, name) = s.split_once('\n')?;
    Some(GenerationDescriptor {
        n: n.parse().ok()?,
        package: name.to_string(),
    })
}

/// What "healthy" means is supplied by the operator; the manager enforces the
/// *gating* (no activation without a passing check), not the health itself.
pub type Health = fn(&Kernel, &InstalledApp) -> bool;

/// One applied generation: the running install plus whether it passed its
/// health check at activation time (last-known-good tracking for rollback).
struct AppliedGen {
    descriptor: GenerationDescriptor,
    healthy_at_activation: bool,
}

/// A staged-but-not-activated candidate.
pub struct StagedGen {
    pub descriptor: GenerationDescriptor,
    pub app: InstalledApp,
}

pub struct UpdateManager {
    manager: PackageManager,
    /// The boot view: the store object that the "bootloader" reads on startup.
    /// `current` inside it holds the descriptor of the boot target.
    view: FlatView,
    applied: Vec<AppliedGen>,
    next_n: u64,
}

impl UpdateManager {
    pub fn new(manager: PackageManager, view: FlatView) -> UpdateManager {
        UpdateManager {
            manager,
            view,
            applied: Vec::new(),
            next_n: 1,
        }
    }

    /// What the bootloader would boot: the descriptor currently pinned in the
    /// store (None before the first activation). The boot target is durable
    /// store content, not memory.
    pub fn boot_target(
        &mut self,
        k: &mut Kernel,
        store: &mut Store,
    ) -> Option<GenerationDescriptor> {
        self.view
            .read_file(k, store, "current")
            .and_then(|b| decode_descriptor(&b))
    }

    /// Install `pkg` as a candidate generation. The current generation is not
    /// touched: this installs (manifest-gated by [`PackageManager`]) and writes
    /// the candidate's descriptor file — never the boot target.
    pub fn stage(
        &mut self,
        k: &mut Kernel,
        store: &mut Store,
        pkg: &Package,
    ) -> KernelResult<StagedGen> {
        let n = self.next_n;
        self.next_n += 1;
        let app = self
            .manager
            .install(k, store, &format!("gen-{n}-{}", pkg.name), pkg)?;
        let descriptor = GenerationDescriptor {
            n,
            package: pkg.name.to_string(),
        };
        let name = format!("gen-{n}");
        if !self.view.create_file(k, store, &name) {
            return Err(KernelError::InvalidOperation);
        }
        let _ = self.view.write_file(k, store, &name, &encode_descriptor(&descriptor));
        Ok(StagedGen { descriptor, app })
    }

    /// Activate the staged generation only if it passes its health check. The
    /// flip itself is a single content write to the boot view — no kernel
    /// authority beyond the config write the updater legitimately owns. On
    /// success the applied install is returned (so callers can audit it or
    /// revoke its anchor); returns None when the check fails, current
    /// untouched.
    pub fn activate(
        &mut self,
        k: &mut Kernel,
        store: &mut Store,
        staged: StagedGen,
        health: Health,
    ) -> Option<InstalledApp> {
        if !health(k, &staged.app) {
            return None;
        }
        if !self
            .view
            .write_file(k, store, "current", &encode_descriptor(&staged.descriptor))
        {
            return None;
        }
        self.applied.push(AppliedGen {
            descriptor: staged.descriptor,
            healthy_at_activation: true,
        });
        Some(staged.app)
    }

    /// Flip the boot target back to the last generation that (a) is not the
    /// current boot target and (b) passed its health check at activation.
    /// Rollback uses no grant, revoke, spawn, copy or creation-root operation
    /// — it is a content pointer flip, nothing more.
    pub fn rollback(&mut self, k: &mut Kernel, store: &mut Store) -> KernelResult<u64> {
        let current_n = self
            .applied
            .last()
            .map(|g| g.descriptor.n)
            .ok_or(KernelError::InvalidOperation)?;
        let descriptor = self
            .applied
            .iter()
            .rfind(|g| g.healthy_at_activation && g.descriptor.n != current_n)
            .map(|g| g.descriptor.clone())
            .ok_or(KernelError::InvalidOperation)?;
        // The old current stays fully installed (its caps were never touched);
        // only the pointer moves back — and the dethroned generation leaves the
        // applied history, so a second rollback has nothing left to restore.
        let _ = self
            .view
            .write_file(k, store, "current", &encode_descriptor(&descriptor));
        if let Some(pos) = self.applied.iter().rposition(|g| g.descriptor.n == current_n) {
            self.applied.truncate(pos);
        }
        Ok(descriptor.n)
    }
}