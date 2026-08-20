use crate::event::AppIdentity;
use std::collections::HashMap;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub struct DesktopRecord {
    pub id: String,
    pub name: String,
    pub icon: String,
    pub exec_base: String,
    pub wm_class: String,
    pub path: PathBuf,
}

#[derive(Default)]
pub struct AppResolver {
    desktops: Vec<DesktopRecord>,
    /// exe path or basename → identity
    cache: HashMap<String, AppIdentity>,
    our_uid: u32,
}

impl AppResolver {
    pub fn new() -> Self {
        let mut r = Self {
            desktops: Vec::new(),
            cache: HashMap::new(),
            our_uid: current_uid(),
        };
        r.scan_desktops();
        r
    }

    pub fn our_uid(&self) -> u32 {
        self.our_uid
    }

    pub fn resolve(&mut self, pid: u32, uid: u32, exe: &str, comm: &str) -> AppIdentity {
        if uid != self.our_uid && pid != 0 {
            return system_identity(pid);
        }
        let exe_base = basename(exe);
        let key = if !exe.is_empty() {
            exe.to_string()
        } else {
            comm.to_string()
        };
        if let Some(hit) = self.cache.get(&key) {
            let mut cloned = hit.clone();
            cloned.pid = pid;
            return cloned;
        }
        let rec = self.match_desktop(&exe_base, comm);
        let ident = if let Some(d) = rec {
            AppIdentity {
                id: d.id.clone(),
                name: d.name.clone(),
                icon: d.icon.clone(),
                desktop: d.id.clone() + ".desktop",
                pid,
                system: false,
            }
        } else {
            let id = if !exe_base.is_empty() {
                sanitize_id(&exe_base)
            } else if !comm.is_empty() {
                sanitize_id(comm)
            } else {
                format!("pid-{pid}")
            };
            AppIdentity {
                id: id.clone(),
                name: pretty_name(&id),
                icon: id.clone(),
                desktop: String::new(),
                pid,
                system: false,
            }
        };
        self.cache.insert(key, ident.clone());
        ident
    }

    fn match_desktop(&self, exe_base: &str, comm: &str) -> Option<&DesktopRecord> {
        let needle = exe_base.to_lowercase();
        let comm_l = comm.to_lowercase();
        self.desktops.iter().find(|d| {
            (!d.exec_base.is_empty() && d.exec_base == needle)
                || (!d.wm_class.is_empty() && d.wm_class == needle)
                || (!d.id.is_empty() && d.id.to_lowercase() == needle)
                || (!comm_l.is_empty() && (d.exec_base == comm_l || d.wm_class == comm_l))
        })
    }

    fn scan_desktops(&mut self) {
        let mut dirs = Vec::new();
        if let Some(home) = std::env::var_os("HOME") {
            dirs.push(PathBuf::from(home).join(".local/share/applications"));
        }
        let data_dirs = std::env::var("XDG_DATA_DIRS")
            .unwrap_or_else(|_| "/usr/local/share:/usr/share".into());
        for d in data_dirs.split(':') {
            if !d.is_empty() {
                dirs.push(PathBuf::from(d).join("applications"));
            }
        }
        for dir in dirs {
            let entries = match std::fs::read_dir(&dir) {
                Ok(e) => e,
                Err(_) => continue,
            };
            for ent in entries.flatten() {
                let p = ent.path();
                if p.extension().and_then(|s| s.to_str()) != Some("desktop") {
                    continue;
                }
                if let Ok(text) = std::fs::read_to_string(&p) {
                    if let Some(rec) = parse_desktop(&text, &p) {
                        self.desktops.push(rec);
                    }
                }
            }
        }
    }
}

pub fn system_identity(pid: u32) -> AppIdentity {
    AppIdentity {
        id: "system".into(),
        name: "system".into(),
        icon: "system".into(),
        desktop: String::new(),
        pid,
        system: true,
    }
}

pub fn unknown_identity(pid: u32) -> AppIdentity {
    AppIdentity {
        id: "unknown".into(),
        name: "unknown".into(),
        icon: "unknown".into(),
        desktop: String::new(),
        pid,
        system: false,
    }
}

pub fn parse_desktop(text: &str, path: &Path) -> Option<DesktopRecord> {
    let mut in_entry = false;
    let mut name = String::new();
    let mut exec = String::new();
    let mut icon = String::new();
    let mut wm = String::new();
    let mut hidden = false;
    let mut no_display = false;
    for line in text.lines() {
        let line = line.trim();
        if line.starts_with('[') {
            in_entry = line.eq_ignore_ascii_case("[Desktop Entry]");
            continue;
        }
        if !in_entry || line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((k, v)) = line.split_once('=') else {
            continue;
        };
        match k {
            "Name" => name = v.to_string(),
            "Exec" => exec = v.to_string(),
            "Icon" => icon = v.to_string(),
            "StartupWMClass" => wm = v.to_lowercase(),
            "Hidden" if v.eq_ignore_ascii_case("true") => hidden = true,
            "NoDisplay" if v.eq_ignore_ascii_case("true") => no_display = true,
            _ => {}
        }
    }
    if hidden || name.is_empty() {
        let _ = no_display;
    }
    let file_stem = path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("")
        .to_string();
    let exec_base = exec_basename(&exec);
    if name.is_empty() && exec_base.is_empty() && file_stem.is_empty() {
        return None;
    }
    if icon.is_empty() {
        icon = exec_base.clone();
    }
    Some(DesktopRecord {
        id: file_stem,
        name,
        icon,
        exec_base,
        wm_class: wm,
        path: path.to_path_buf(),
    })
}

fn exec_basename(exec: &str) -> String {
    let first = exec.split_whitespace().next().unwrap_or("");
    let first = first.trim_matches('"');
    basename(first).to_lowercase()
}

fn basename(path: &str) -> String {
    path.rsplit('/').next().unwrap_or(path).to_string()
}

pub fn sanitize_id(raw: &str) -> String {
    let mut s = String::new();
    for c in raw.chars() {
        if c.is_ascii_alphanumeric() || c == '_' || c == '.' {
            s.push(c.to_ascii_lowercase());
        } else if c == '-' || c.is_whitespace() {
            if !s.ends_with('-') {
                s.push('-');
            }
        } else if !s.ends_with('-') {
            s.push('-');
        }
    }
    let s = s.trim_matches('-').to_string();
    if s.is_empty() {
        "app".into()
    } else {
        s
    }
}

fn pretty_name(id: &str) -> String {
    let mut out = String::new();
    let mut cap = true;
    for c in id.chars() {
        if c == '-' || c == '_' {
            out.push(' ');
            cap = true;
        } else if cap {
            out.extend(c.to_uppercase());
            cap = false;
        } else {
            out.push(c);
        }
    }
    out
}

fn current_uid() -> u32 {
    #[cfg(unix)]
    {
        libc_uid()
    }
    #[cfg(not(unix))]
    {
        0
    }
}

#[cfg(unix)]
fn libc_uid() -> u32 {
    // Avoid a libc crate dep: read from /proc/self or use the libc syscall via std.
    // std doesn't expose uid; parse `id -u` fallback, or use the nix-less libc wrapper.
    if let Ok(s) = std::fs::read_to_string("/proc/self/status") {
        for line in s.lines() {
            if let Some(rest) = line.strip_prefix("Uid:") {
                if let Some(uid) = rest.split_whitespace().next().and_then(|t| t.parse().ok()) {
                    return uid;
                }
            }
        }
    }
    std::env::var("UID")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(0)
}

pub fn read_exe(pid: u32) -> String {
    let p = format!("/proc/{pid}/exe");
    std::fs::read_link(&p)
        .ok()
        .and_then(|s| s.to_str().map(|t| t.to_string()))
        .unwrap_or_default()
}

pub fn read_comm(pid: u32) -> String {
    std::fs::read_to_string(format!("/proc/{pid}/comm"))
        .unwrap_or_default()
        .trim()
        .to_string()
}

pub fn read_status_uid(pid: u32) -> Option<u32> {
    let s = std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    for line in s.lines() {
        if let Some(rest) = line.strip_prefix("Uid:") {
            return rest.split_whitespace().next()?.parse().ok();
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_firefox_desktop() {
        let text = "[Desktop Entry]\nName=Firefox\nExec=/usr/lib/firefox/firefox %u\nIcon=firefox\nStartupWMClass=firefox\n";
        let rec = parse_desktop(text, Path::new("/usr/share/applications/firefox.desktop")).unwrap();
        assert_eq!(rec.name, "Firefox");
        assert_eq!(rec.exec_base, "firefox");
        assert_eq!(rec.icon, "firefox");
        assert_eq!(rec.id, "firefox");
        assert_eq!(rec.wm_class, "firefox");
    }

    #[test]
    fn sanitize_keeps_simple_ids() {
        assert_eq!(sanitize_id("firefox"), "firefox");
        assert_eq!(sanitize_id("Code - OSS"), "code-oss");
    }

    #[test]
    fn other_uid_is_system() {
        let mut r = AppResolver {
            desktops: vec![],
            cache: HashMap::new(),
            our_uid: 1000,
        };
        let id = r.resolve(1, 0, "/usr/bin/sshd", "sshd");
        assert!(id.system);
        assert_eq!(id.id, "system");
    }

    #[test]
    fn groups_by_desktop_not_pid() {
        let mut r = AppResolver {
            desktops: vec![DesktopRecord {
                id: "firefox".into(),
                name: "Firefox".into(),
                icon: "firefox".into(),
                exec_base: "firefox".into(),
                wm_class: "firefox".into(),
                path: PathBuf::from("/usr/share/applications/firefox.desktop"),
            }],
            cache: HashMap::new(),
            our_uid: 1000,
        };
        let a = r.resolve(10, 1000, "/usr/lib/firefox/firefox", "firefox");
        let b = r.resolve(11, 1000, "/usr/lib/firefox/firefox", "firefox");
        assert_eq!(a.id, b.id);
        assert_eq!(a.id, "firefox");
        assert_ne!(a.pid, b.pid);
    }
}
