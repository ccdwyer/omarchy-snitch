use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RestorePid {
    pub cgroup: String,
    pub uid: u32,
    pub starttime: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RestoreFile {
    #[serde(default)]
    pub pids: BTreeMap<String, RestorePid>,
}

pub fn parse_unified_cgroup(text: &str) -> Option<String> {
    for line in text.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("0::") {
            return Some(rest.to_string());
        }
    }
    None
}

pub fn is_root_cgroup(path: &str) -> bool {
    let p = path.trim();
    p.is_empty() || p == "/"
}

pub fn sys_path(cgroup_root: &Path, rel: &str) -> PathBuf {
    let rel = rel.trim_start_matches('/');
    cgroup_root.join(rel)
}

pub fn path_for(app: &str) -> PathBuf {
    PathBuf::from("/var/lib/snitch/cgroup-restore").join(format!("{app}.json"))
}

pub fn load(path: &Path) -> RestoreFile {
    let text = std::fs::read_to_string(path).unwrap_or_default();
    // Old files stored bare cgroup strings. Fail closed instead of restoring
    // a PID without uid/starttime.
    serde_json::from_str(&text).unwrap_or_default()
}

pub fn save(path: &Path, file: &RestoreFile) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("mkdir restore: {e}"))?;
    }
    let text = serde_json::to_string_pretty(file).map_err(|e| e.to_string())?;
    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, text).map_err(|e| format!("write restore: {e}"))?;
    std::fs::rename(&tmp, path).map_err(|e| format!("rename restore: {e}"))
}

/// nft `socket cgroupv2 level N` — N is the number of path components
/// under the cgroup root (`snitch.slice/snitch-app` → 2).
pub fn cgroup_match_level(rel: &str) -> u32 {
    let n = rel
        .trim_matches('/')
        .split('/')
        .filter(|s| !s.is_empty())
        .count();
    n.max(1) as u32
}

pub fn membership_matches(current: &str, original: &str) -> bool {
    let cur = current.trim();
    let orig = original.trim();
    if orig.is_empty() {
        return false;
    }
    cur == orig || cur.ends_with(orig) || orig.ends_with(cur)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_unified_line() {
        let text = "0::/user.slice/user-1000.slice/user@1000.service/app-firefox-1.scope\n";
        assert_eq!(
            parse_unified_cgroup(text).unwrap(),
            "/user.slice/user-1000.slice/user@1000.service/app-firefox-1.scope"
        );
    }

    #[test]
    fn rejects_root() {
        assert!(is_root_cgroup(""));
        assert!(is_root_cgroup("/"));
        assert!(!is_root_cgroup("/user.slice"));
    }

    #[test]
    fn match_level_from_path() {
        assert_eq!(cgroup_match_level("snitch.slice/snitch-firefox"), 2);
        assert_eq!(cgroup_match_level("/snitch.slice/snitch-firefox/"), 2);
        assert_eq!(cgroup_match_level("a/b/c"), 3);
    }

    #[test]
    fn membership_compare() {
        let orig = "/user.slice/user-1000.slice/user@1000.service/app-firefox-1.scope";
        assert!(membership_matches(orig, orig));
        assert!(!membership_matches("/snitch.slice/snitch-firefox", orig));
    }
}
