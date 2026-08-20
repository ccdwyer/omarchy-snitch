//! Pure helpers for snitch-block: identity guards and per-app IP ownership.
//! nftables / cgroup / conntrack stay in the binary so unit tests run off-device.

pub mod ids;
pub mod owners;

pub use ids::{is_forbidden_app, sanitize_app, ForbiddenApp};
pub use owners::{exclusive_release, grant, OwnerMap};
