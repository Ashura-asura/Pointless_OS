//! The package model (design doc §8): installation grants exactly the
//! capabilities a package manifest declares up front, nothing ambient;
//! installation runs no code; and installation is transactional — one
//! per-install grant root anchors every minted cap (I4), so any failure rolls
//! the whole install back and the world is as it was.
//!
//! A package is a declared authority ceiling (a [`capability_audit::Manifest`])
//! plus an immutable, content-addressed payload of store blocks. Delivery is
//! derived and narrowed: every cap the app receives is minted from a source
//! cap the manager itself holds, under the install's own grant root; the
//! payload arrives as READ-only derived caps — the app can read its files but
//! cannot modify them or the store.
//!
//! Honest limits: the packager and the boot task are the same identity (v1 has
//! one service host); payload blocks are READ-visible to the app only after a
//! successful install (no separate code-signing key, no offline signing chain).

use capability_audit::{audit::audit, Manifest};
use capability_core::{
    CapHandle, Kernel, KernelError, KernelResult, ObjectKind, Rights, TaskHandle,
};
use object_store::{BlockId, Store};

/// One installable unit: a manifest (the declared ceiling, the repo boundary is
/// the trust boundary) plus content-addressed payload blocks.
#[derive(Debug, Clone)]
pub struct Package {
    pub name: &'static str,
    pub manifest: Manifest,
    /// (file name, block id) — file bytes live in the store, addressed by their
    /// own content hash; identical payloads across packages share blocks.
    pub payload: Vec<(String, BlockId)>,
}

impl Package {
    pub fn with_file(mut self, name: String, block: BlockId) -> Package {
        self.payload.push((name, block));
        self
    }
}

/// Everything an install left behind. `cap_slots` is precisely the set of caps
/// the app received: manifest-minted sources plus READ-only payload delivery.
#[derive(Debug, Clone)]
pub struct InstalledApp {
    pub task: TaskHandle,
    /// The app's naming cap in the manager's CSpace (the install anchor lives
    /// in the same space; the app itself may not name its peers here).
    pub task_cap: CapHandle,
    /// The per-install grant root: revoking it removes every minted cap.
    pub anchor: CapHandle,
    /// Slots in the app's CSpace that were minted for it during install.
    pub cap_slots: Vec<u32>,
}

/// Installs packages. v1: hosted by the boot task itself — the manager's
/// identity, the boot task and the store host are one and the same; what the
/// manager may grant is decided by the source caps it happens to hold.
pub struct PackageManager {
    service: TaskHandle,
    creator: CapHandle,
}

impl PackageManager {
    pub fn new(service: TaskHandle, creator: CapHandle) -> PackageManager {
        PackageManager { service, creator }
    }

    /// A cap the manager itself holds that can supply the declared request:
    /// same kind, superset of rights. The manager grants nothing it does not
    /// first hold — a package can never endow itself.
    fn source_for(&self, k: &Kernel, kind: ObjectKind, rights: Rights) -> KernelResult<CapHandle> {
        for slot in 0..256u32 {
            if let Ok(info) = k.cap_info(self.service, CapHandle(slot)) {
                if info.kind == kind && info.rights.superset_of(rights) {
                    return Ok(CapHandle(slot));
                }
            }
        }
        Err(KernelError::NoCap)
    }

    /// Install `pkg` as a fresh task. Steps:
    ///
    /// 1. spawn the app task and a *fresh* per-install grant root — the only cap
    ///    family the install may extend;
    /// 2. for every manifest declaration, mint a narrowed cap from a source the
    ///    manager holds — the kernel derives, never invents;
    /// 3. deliver the payload as READ-only derived caps;
    /// 4. audit the just-installed authority against the manifest; if anything
    ///    exceeds the ceiling (e.g. a kernel-equivalent request), roll back.
    ///
    /// Any failure tears the whole install down: the anchor is revoked (every
    /// minted cap dies) and the app task is revoked with it. Nothing else runs
    /// during install — the contract tests count the single CreateTask record
    /// and prove nothing else executes.
    pub fn install(
        &self,
        k: &mut Kernel,
        store: &mut Store,
        app_label: &str,
        pkg: &Package,
    ) -> KernelResult<InstalledApp> {
        let (app, app_cap) = k.create_task(self.service, self.creator, app_label)?;
        let anchor = k.create_grant_root(self.service, self.creator)?;
        let rollback = |k: &mut Kernel| {
            let _ = k.revoke(self.service, anchor);
            let _ = k.revoke(self.service, app_cap);
        };
        let mut cap_slots = Vec::new();
        for declared in &pkg.manifest.declares {
            let source = match self.source_for(k, declared.kind, declared.rights) {
                Ok(s) => s,
                Err(e) => {
                    rollback(k);
                    return Err(e);
                }
            };
            match k.grant_mint(self.service, anchor, source, app_cap, declared.rights, None) {
                Ok(slot) => cap_slots.push(slot.0),
                Err(e) => {
                    rollback(k);
                    return Err(e);
                }
            }
        }
        for (_, block) in &pkg.payload {
            let source = match store.block_cap(block) {
                Some(c) => c,
                None => {
                    rollback(k);
                    return Err(KernelError::NoCap);
                }
            };
            match k.grant_mint(self.service, anchor, source, app_cap, Rights::READ, None) {
                Ok(slot) => cap_slots.push(slot.0),
                Err(e) => {
                    rollback(k);
                    return Err(e);
                }
            }
        }
        let report = audit(k, &[(app, &pkg.manifest)]);
        if !report.is_clean() {
            rollback(k);
            return Err(KernelError::InvalidOperation);
        }
        Ok(InstalledApp {
            task: app,
            task_cap: app_cap,
            anchor,
            cap_slots,
        })
    }
}
