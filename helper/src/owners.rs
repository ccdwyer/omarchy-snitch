use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

/// app-id → set of IP strings that app added via block-ips.
pub type OwnerMap = BTreeMap<String, BTreeSet<String>>;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct OwnerFile {
    #[serde(default)]
    apps: BTreeMap<String, Vec<String>>,
}

pub fn load(path: &Path) -> OwnerMap {
    let text = std::fs::read_to_string(path).unwrap_or_default();
    let parsed: OwnerFile = serde_json::from_str(&text).unwrap_or_default();
    let mut map = OwnerMap::new();
    for (app, ips) in parsed.apps {
        map.insert(app, ips.into_iter().collect());
    }
    map
}

pub fn save(path: &Path, map: &OwnerMap) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("mkdir owners: {e}"))?;
    }
    let mut file = OwnerFile::default();
    for (app, ips) in map {
        file.apps.insert(app.clone(), ips.iter().cloned().collect());
    }
    let text = serde_json::to_string_pretty(&file).map_err(|e| e.to_string())?;
    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, text).map_err(|e| format!("write owners: {e}"))?;
    std::fs::rename(&tmp, path).map_err(|e| format!("rename owners: {e}"))
}

pub fn grant(map: &mut OwnerMap, app: &str, ips: &[String]) {
    let entry = map.entry(app.to_string()).or_default();
    for ip in ips {
        entry.insert(ip.clone());
    }
}

/// Drop `app` as an owner. Returns IPs that no remaining app owns (safe to
/// delete from the host-wide set) and IPs still held by someone else.
pub fn exclusive_release(map: &mut OwnerMap, app: &str) -> (Vec<String>, Vec<String>) {
    let owned = map.remove(app).unwrap_or_default();
    let mut still: BTreeSet<String> = BTreeSet::new();
    for ips in map.values() {
        still.extend(ips.iter().cloned());
    }
    let mut released = Vec::new();
    let mut retained = Vec::new();
    for ip in owned {
        if still.contains(&ip) {
            retained.push(ip);
        } else {
            released.push(ip);
        }
    }
    (released, retained)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn release_keeps_shared_ip() {
        let mut map = OwnerMap::new();
        grant(&mut map, "firefox", &["1.2.3.4".into(), "9.9.9.9".into()]);
        grant(&mut map, "chrome", &["1.2.3.4".into()]);
        let (released, retained) = exclusive_release(&mut map, "firefox");
        assert_eq!(released, vec!["9.9.9.9".to_string()]);
        assert_eq!(retained, vec!["1.2.3.4".to_string()]);
        assert!(map.get("chrome").unwrap().contains("1.2.3.4"));
        assert!(!map.contains_key("firefox"));
    }

    #[test]
    fn release_last_owner_drops_all() {
        let mut map = OwnerMap::new();
        grant(&mut map, "spotify", &["193.182.8.20".into()]);
        let (released, retained) = exclusive_release(&mut map, "spotify");
        assert_eq!(released, vec!["193.182.8.20".to_string()]);
        assert!(retained.is_empty());
        assert!(map.is_empty());
    }

    #[test]
    fn roundtrip_file() {
        let dir = std::env::temp_dir().join(format!("snitch-owners-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("endpoint-owners.json");
        let mut map = OwnerMap::new();
        grant(&mut map, "firefox", &["8.8.8.8".into()]);
        save(&path, &map).unwrap();
        let loaded = load(&path);
        assert!(loaded.get("firefox").unwrap().contains("8.8.8.8"));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
