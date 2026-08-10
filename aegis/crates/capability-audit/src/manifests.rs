//! The manifests of the services in the prototype system. In the real deployment
//! each lives in the service's own repository next to its build (design doc §8); in
//! this workspace they are compiled in so the CI run (`cargo run -p capability-audit`
//! and every `cargo test`) can always answer "what is the TCB asking for".
//!
//! The rule being enforced: the *session* (boot-time authority holder) is the
//! kernel/bootloader-side actor; every task it creates — services and the assistant
//! alike — is a userspace service that may only ever hold what it declares.

use crate::manifest::{Manifest, Repo};
use capability_core::{ObjectKind, Rights};

/// The session: boot root, creator of every kernel object, holder of grant roots.
/// Kernel repo — the only one allowed to declare kernel-equivalent authority.
pub fn session() -> Manifest {
    Manifest::new("session", Repo::Kernel)
        .allow(ObjectKind::Creator, Rights::ALL)
        .allow(ObjectKind::Task, Rights::ALL)
        .allow(ObjectKind::GrantRoot, Rights::GRANT)
        .allow(
            ObjectKind::Endpoint,
            Rights::SEND.union(Rights::RECV).union(Rights::GRANT),
        )
}

/// The assistant: granted exactly the "restart-service" role — READ+CONTROL over the
/// named service, for the duration of the task. Everything else it holds (its
/// structural self cap) is infrastructure, not authority.
pub fn assistant() -> Manifest {
    Manifest::new("assistant", Repo::Service)
        .allow(ObjectKind::Task, Rights::READ.union(Rights::CONTROL))
}

/// The mail service: talks over the endpoint the session granted it (SEND+RECV).
pub fn smtp() -> Manifest {
    Manifest::new("smtp", Repo::Service)
        .allow(ObjectKind::Endpoint, Rights::SEND.union(Rights::RECV))
}

/// The time service: same scope — the endpoint, and nothing else.
pub fn ntp() -> Manifest {
    Manifest::new("ntp", Repo::Service)
        .allow(ObjectKind::Endpoint, Rights::SEND.union(Rights::RECV))
}
