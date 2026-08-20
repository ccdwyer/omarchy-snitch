//! Pure helpers for snitch-block: identity guards, process forest, ownership.
//! Live nftables / conntrack exec stays in the binary so unit tests run off-device.

pub mod caller;
pub mod deps;
pub mod forest;
pub mod ids;
pub mod nft_verify;
pub mod owners;
pub mod restore;

pub use caller::{authorize_seed_pids, invoking_uid};
pub use deps::BlockingCaps;
pub use ids::{is_forbidden_app, sanitize_app, ForbiddenApp};
pub use owners::{exclusive_release, grant, OwnerMap};
