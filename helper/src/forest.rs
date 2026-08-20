use std::collections::{BTreeSet, HashMap, HashSet};

/// Snapshot of one process used to expand a per-app forest without
/// swallowing an entire shared session cgroup.
#[derive(Debug, Clone)]
pub struct ProcIdentity {
    pub pid: u32,
    pub ppid: u32,
    pub uid: u32,
    pub exe_base: String,
    pub comm: String,
    /// Unified-hierarchy path relative to /sys/fs/cgroup, e.g. `/user.slice/.../app-firefox-*.scope`.
    pub cgroup: String,
    /// `/proc/<pid>/stat` starttime — pins the PID against reuse.
    pub starttime: u64,
    pub kthread: bool,
}

/// systemd user app scopes are private to the launched app. Session scopes are shared.
pub fn is_private_app_cgroup(path: &str) -> bool {
    let name = path.rsplit('/').next().unwrap_or("");
    if name.starts_with("session-") {
        return false;
    }
    name.ends_with(".scope") && name.starts_with("app-")
}

pub fn same_app(seed: &ProcIdentity, other: &ProcIdentity) -> bool {
    if other.pid < 2 || other.kthread || seed.kthread {
        return false;
    }
    if seed.uid != other.uid {
        return false;
    }
    if !seed.exe_base.is_empty() && seed.exe_base == other.exe_base {
        return true;
    }
    if !seed.comm.is_empty() && seed.comm == other.comm {
        return true;
    }
    false
}

/// Expand seed PIDs (typically those owning sockets) into the validated app
/// forest: matching ancestors + descendants by identity, plus **every
/// same-UID member** of a private app scope (helpers with other exe names).
pub fn collect_forest(seed_pids: &[u32], procs: &HashMap<u32, ProcIdentity>) -> Vec<u32> {
    let seeds: Vec<&ProcIdentity> = seed_pids.iter().filter_map(|p| procs.get(p)).collect();
    // Fail closed: never pass through PIDs that were missing from the snapshot
    // (kernel threads, gone, or unreadable). The caller must authorize seeds first.
    if seeds.is_empty() {
        return Vec::new();
    }

    let mut out: BTreeSet<u32> = BTreeSet::new();
    let identity = seeds[0];

    let mut roots: Vec<u32> = Vec::new();
    for s in &seeds {
        let mut cur = s.pid;
        let mut last = s.pid;
        loop {
            let Some(p) = procs.get(&cur) else { break };
            if !same_app(s, p) {
                break;
            }
            last = cur;
            if p.ppid < 2 {
                break;
            }
            cur = p.ppid;
        }
        roots.push(last);
    }

    for root in roots {
        let mut stack = vec![root];
        while let Some(pid) = stack.pop() {
            if !out.insert(pid) {
                continue;
            }
            for (opid, op) in procs {
                if op.ppid == pid && same_app(identity, op) {
                    stack.push(*opid);
                }
            }
        }
    }

    let mut by_cg: HashMap<&str, Vec<u32>> = HashMap::new();
    for (pid, p) in procs {
        by_cg.entry(p.cgroup.as_str()).or_default().push(*pid);
    }
    let seed_cgs: HashSet<String> = seeds.iter().map(|s| s.cgroup.clone()).collect();
    for cg in seed_cgs {
        if !is_private_app_cgroup(&cg) {
            continue;
        }
        if let Some(members) = by_cg.get(cg.as_str()) {
            for pid in members {
                if let Some(p) = procs.get(pid) {
                    // Private scope: same UID is enough. Chrome's crashpad /
                    // nacl_helper live here with different exe names.
                    if p.pid >= 2 && p.uid == identity.uid && !p.kthread {
                        out.insert(*pid);
                    }
                }
            }
        }
    }

    out.into_iter().filter(|p| *p >= 2).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn proc(pid: u32, ppid: u32, exe: &str, comm: &str, cg: &str) -> ProcIdentity {
        ProcIdentity {
            pid,
            ppid,
            uid: 1000,
            exe_base: exe.into(),
            comm: comm.into(),
            cgroup: cg.into(),
            starttime: 1000 + u64::from(pid),
            kthread: false,
        }
    }

    fn map(list: Vec<ProcIdentity>) -> HashMap<u32, ProcIdentity> {
        list.into_iter().map(|p| (p.pid, p)).collect()
    }

    #[test]
    fn walks_ancestors_and_siblings() {
        let session = "/user.slice/user-1000.slice/user@1000.service/session.slice";
        let procs = map(vec![
            proc(10, 1, "firefox", "firefox", session),
            proc(11, 10, "firefox", "firefox", session),
            proc(12, 10, "firefox", "firefox", session),
            proc(13, 1, "bash", "bash", session),
        ]);
        let forest = collect_forest(&[11], &procs);
        assert!(forest.contains(&10));
        assert!(forest.contains(&11));
        assert!(forest.contains(&12));
        assert!(!forest.contains(&13));
    }

    #[test]
    fn private_cgroup_includes_unrelated_parentage_siblings() {
        let cg = "/user.slice/user-1000.slice/user@1000.service/app-chrome-123.scope";
        let procs = map(vec![
            proc(20, 1, "chrome", "chrome", cg),
            proc(21, 1, "chrome", "chrome", cg),
            proc(22, 1, "chrome", "chrome", cg),
            proc(30, 1, "slack", "slack", "/user.slice/user-1000.slice/user@1000.service/app-slack-123.scope"),
        ]);
        let forest = collect_forest(&[20], &procs);
        assert_eq!(forest, vec![20, 21, 22]);
    }

    #[test]
    fn private_scope_includes_same_uid_helpers_with_other_exe() {
        let cg = "/user.slice/user-1000.slice/user@1000.service/app-chrome-123.scope";
        let procs = map(vec![
            proc(20, 1, "chrome", "chrome", cg),
            proc(21, 20, "nacl_helper", "nacl_helper", cg),
            proc(22, 1, "chrome_crashpad", "chrome_crashpad", cg),
            proc(99, 1, "chrome", "chrome", cg), // same uid+scope
        ]);
        // 99 has uid 1000 via proc() helper
        let forest = collect_forest(&[20], &procs);
        assert!(forest.contains(&20));
        assert!(forest.contains(&21), "helper with other exe must be included");
        assert!(forest.contains(&22), "crashpad with other exe must be included");
        assert!(forest.contains(&99));
    }

    #[test]
    fn shared_session_cgroup_does_not_swallow_other_apps() {
        let session = "/user.slice/user-1000.slice/user@1000.service/session-3.scope";
        assert!(!is_private_app_cgroup(session));
        let procs = map(vec![
            proc(40, 1, "spotify", "spotify", session),
            proc(41, 40, "spotify", "spotify", session),
            proc(50, 1, "code", "code", session),
        ]);
        let forest = collect_forest(&[41], &procs);
        assert!(forest.contains(&40));
        assert!(forest.contains(&41));
        assert!(!forest.contains(&50));
    }

    #[test]
    fn missing_seed_is_not_passed_through() {
        let procs = map(vec![proc(10, 1, "firefox", "firefox", "/user.slice")]);
        assert!(collect_forest(&[99], &procs).is_empty());
        assert!(collect_forest(&[1], &procs).is_empty());
    }

    #[test]
    fn foreign_uid_is_not_in_forest() {
        let mut other = proc(50, 1, "firefox", "firefox", "/user.slice");
        other.uid = 0;
        let procs = map(vec![
            proc(10, 1, "firefox", "firefox", "/user.slice"),
            other,
        ]);
        let forest = collect_forest(&[10], &procs);
        assert!(forest.contains(&10));
        assert!(!forest.contains(&50));
    }
}
