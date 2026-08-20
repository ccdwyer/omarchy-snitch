//! Blocking-capability probe. Pure so unit tests run off-device.

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockingCaps {
    pub nft: bool,
    pub conntrack: bool,
    pub cgroupv2: bool,
}

impl BlockingCaps {
    pub fn from_presence(nft: bool, conntrack: bool, cgroupv2: bool) -> Self {
        Self {
            nft,
            conntrack,
            cgroupv2,
        }
    }

    pub fn ready(&self) -> bool {
        self.nft && self.conntrack && self.cgroupv2
    }

    pub fn missing(&self) -> Vec<&'static str> {
        let mut v = Vec::new();
        if !self.nft {
            v.push("nft");
        }
        if !self.conntrack {
            v.push("conntrack");
        }
        if !self.cgroupv2 {
            v.push("cgroupv2");
        }
        v
    }

    pub fn packages(&self) -> Vec<&'static str> {
        let mut v = Vec::new();
        if !self.nft {
            v.push("nftables");
        }
        if !self.conntrack {
            v.push("conntrack-tools");
        }
        v
    }

    /// Human-readable reason + required-packages hint. Empty when ready.
    pub fn hint(&self) -> String {
        if self.ready() {
            return String::new();
        }
        let missing = self.missing().join(", ");
        let mut parts = vec![format!("blocking unavailable ({missing} missing)")];
        let pkgs = self.packages();
        if !pkgs.is_empty() {
            parts.push(format!("install {}", pkgs.join(" and ")));
        }
        if !self.cgroupv2 {
            parts.push("cgroup v2 unified hierarchy required at /sys/fs/cgroup".into());
        }
        parts.push("need nftables, conntrack-tools, and cgroup v2 — monitoring still works".into());
        parts.join(" — ")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_present_is_ready() {
        let c = BlockingCaps::from_presence(true, true, true);
        assert!(c.ready());
        assert!(c.missing().is_empty());
        assert!(c.packages().is_empty());
        assert!(c.hint().is_empty());
    }

    #[test]
    fn missing_conntrack_names_package() {
        let c = BlockingCaps::from_presence(true, false, true);
        assert!(!c.ready());
        assert_eq!(c.missing(), vec!["conntrack"]);
        assert_eq!(c.packages(), vec!["conntrack-tools"]);
        let h = c.hint();
        assert!(h.contains("conntrack"));
        assert!(h.contains("conntrack-tools"));
        assert!(h.contains("monitoring still works"));
    }

    #[test]
    fn missing_nft_and_cgroup() {
        let c = BlockingCaps::from_presence(false, true, false);
        assert!(!c.ready());
        assert_eq!(c.missing(), vec!["nft", "cgroupv2"]);
        assert_eq!(c.packages(), vec!["nftables"]);
        let h = c.hint();
        assert!(h.contains("nftables"));
        assert!(h.contains("cgroup v2"));
    }
}
