use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SeenEntry {
    pub first_seen: u64,
    pub last_seen: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SeenFile {
    #[serde(default)]
    pub networks: HashMap<String, SeenEntry>,
}

pub struct SeenSet {
    path: PathBuf,
    data: SeenFile,
    dirty: bool,
}

impl SeenSet {
    pub fn load(state_dir: &Path) -> Self {
        let _ = std::fs::create_dir_all(state_dir);
        let path = state_dir.join("hosts.json");
        let data = std::fs::read_to_string(&path)
            .ok()
            .and_then(|t| serde_json::from_str(&t).ok())
            .unwrap_or_default();
        Self {
            path,
            data,
            dirty: false,
        }
    }

    /// Record a network. Returns true if this prefix has never been seen.
    /// Port 53 callers should still record but skip the bar pulse themselves.
    pub fn observe(&mut self, key: &str, now: u64) -> bool {
        if key.is_empty() {
            return false;
        }
        match self.data.networks.get_mut(key) {
            Some(e) => {
                e.last_seen = now;
                self.dirty = true;
                false
            }
            None => {
                self.data.networks.insert(
                    key.to_string(),
                    SeenEntry {
                        first_seen: now,
                        last_seen: now,
                    },
                );
                self.dirty = true;
                true
            }
        }
    }

    pub fn flush(&mut self) {
        if !self.dirty {
            return;
        }
        if let Some(parent) = self.path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        if let Ok(text) = serde_json::to_string_pretty(&self.data) {
            let tmp = self.path.with_extension("json.tmp");
            if std::fs::write(&tmp, text).is_ok() {
                let _ = std::fs::rename(&tmp, &self.path);
            }
        }
        self.dirty = false;
    }

    pub fn contains(&self, key: &str) -> bool {
        self.data.networks.contains_key(key)
    }

    pub fn len(&self) -> usize {
        self.data.networks.len()
    }
}

/// /24 for IPv4, /48 for IPv6. Mapped v4 is treated as v4.
pub fn network_key(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(v) => {
            let o = v.octets();
            format!("{}.{}.{}.0/24", o[0], o[1], o[2])
        }
        IpAddr::V6(v) => {
            if let Some(v4) = v.to_ipv4_mapped() {
                return network_key(IpAddr::V4(v4));
            }
            let s = v.segments();
            format!("{:x}:{:x}:{:x}::/48", s[0], s[1], s[2])
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn v4_slash24() {
        assert_eq!(
            network_key(IpAddr::V4(Ipv4Addr::new(142, 250, 190, 14))),
            "142.250.190.0/24"
        );
        assert_eq!(
            network_key(IpAddr::V4(Ipv4Addr::new(142, 250, 190, 99))),
            "142.250.190.0/24"
        );
    }

    #[test]
    fn v6_slash48() {
        let ip: Ipv6Addr = "2001:db8:abcd:12::1".parse().unwrap();
        assert_eq!(network_key(IpAddr::V6(ip)), "2001:db8:abcd::/48");
        let ip2: Ipv6Addr = "2001:db8:abcd:99::ffff".parse().unwrap();
        assert_eq!(network_key(IpAddr::V6(ip2)), "2001:db8:abcd::/48");
    }

    #[test]
    fn mapped_v4_uses_slash24() {
        let mapped = Ipv4Addr::new(8, 8, 8, 8).to_ipv6_mapped();
        assert_eq!(network_key(IpAddr::V6(mapped)), "8.8.8.0/24");
    }

    #[test]
    fn observe_is_new_then_old() {
        let dir = std::env::temp_dir().join(format!("snitch-seen-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let mut set = SeenSet::load(&dir);
        assert!(set.observe("1.2.3.0/24", 1000));
        assert!(!set.observe("1.2.3.0/24", 2000));
        set.flush();
        let set2 = SeenSet::load(&dir);
        assert!(set2.contains("1.2.3.0/24"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn cdn_rotation_same_prefix() {
        assert_eq!(
            network_key(IpAddr::V4(Ipv4Addr::new(104, 16, 1, 1))),
            network_key(IpAddr::V4(Ipv4Addr::new(104, 16, 1, 50)))
        );
    }
}
