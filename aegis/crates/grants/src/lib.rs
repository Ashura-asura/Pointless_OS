//! Role library and grant flow — design doc §9: grants are role-shaped, ephemeral by
//! default, diff-confirmed, and every exercised capability is logged.

pub mod grant;
pub mod monitor;
pub mod role;

pub use grant::{
    ActiveGrant, DiffLine, GrantPolicy, GrantService, GrantTarget, GrantedCap, PendingGrant,
    PendingTwoParty, PolicyEvent,
};
pub use monitor::Monitor;
pub use role::{CapRequest, Role, RoleLibrary};