//! Unprivileged connection-monitor library used by `snitchd`.
//!
//! Live capture reads Linux `/proc`. Replay, GeoIP, seen-set keying, and
//! parsers are OS-independent so unit tests run on macOS.

pub mod event;
pub mod geo;
pub mod identity;
pub mod procfs;
pub mod seen;

pub use event::{AppIdentity, Connection, Endpoint, Event};
pub use geo::GeoDb;
pub use identity::AppResolver;
pub use procfs::{parse_proc_net, ParsedSocket, Protocol};
pub use seen::{network_key, SeenSet};
