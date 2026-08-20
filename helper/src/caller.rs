//! Invoking-user identity and PID ownership checks for the privileged helper.
//!
//! The helper runs as root via pkexec. Caller-supplied PIDs must belong to the
//! unprivileged user who authorized the action — never the helper's euid.

use crate::forest::ProcIdentity;
use std::collections::HashMap;

/// `PF_KTHREAD` from linux/sched.h — kernel threads are not user applications.
pub const PF_KTHREAD: u32 = 0x0020_0000;

pub fn invoking_uid_from_env(
    pkexec_uid: Option<&str>,
    sudo_uid: Option<&str>,
    euid: u32,
) -> Result<u32, String> {
    if let Some(uid) = parse_env_uid(pkexec_uid) {
        return uid;
    }
    if let Some(uid) = parse_env_uid(sudo_uid) {
        return uid;
    }
    if euid != 0 {
        return Ok(euid);
    }
    Err("cannot determine invoking user (helper is root and PKEXEC_UID/SUDO_UID unset)".into())
}

fn parse_env_uid(raw: Option<&str>) -> Option<Result<u32, String>> {
    let s = raw.map(str::trim).filter(|s| !s.is_empty())?;
    Some(s.parse::<u32>().map_err(|_| format!("invalid caller uid {s}")))
}

/// Real invoking user. pkexec sets `PKEXEC_UID`; sudo sets `SUDO_UID`.
/// Never uses the helper's euid when that euid is root.
pub fn invoking_uid() -> Result<u32, String> {
    let pk = std::env::var("PKEXEC_UID").ok();
    let su = std::env::var("SUDO_UID").ok();
    invoking_uid_from_env(pk.as_deref(), su.as_deref(), current_euid())
}

pub fn current_euid() -> u32 {
    if let Ok(s) = std::fs::read_to_string("/proc/self/status") {
        for line in s.lines() {
            if let Some(rest) = line.strip_prefix("Uid:") {
                // real effective saved fs
                let mut it = rest.split_whitespace();
                let _real = it.next();
                if let Some(eff) = it.next().and_then(|t| t.parse().ok()) {
                    return eff;
                }
            }
        }
    }
    0
}

/// Flags and starttime from `/proc/<pid>/stat`.
/// After `comm`, field 7 is flags and field 20 is starttime (1-based man page
/// fields 9 and 22).
pub fn parse_stat_fields(stat: &str) -> Option<(u32, u64)> {
    let rparen = stat.rfind(')')?;
    let rest = stat[rparen + 1..].trim();
    let fields: Vec<&str> = rest.split_whitespace().collect();
    if fields.len() < 20 {
        return None;
    }
    let flags = fields[6].parse::<u32>().ok()?;
    let starttime = fields[19].parse::<u64>().ok()?;
    Some((flags, starttime))
}

pub fn is_kernel_thread(flags: u32) -> bool {
    flags & PF_KTHREAD != 0
}

/// Fail closed: PID 1, kernel threads, missing PIDs, and foreign UIDs are errors.
pub fn check_seed_pid(
    pid: u32,
    caller_uid: u32,
    procs: &HashMap<u32, ProcIdentity>,
) -> Result<(), String> {
    if pid < 2 {
        return Err(format!("refusing pid {pid} (pid 0/1)"));
    }
    let Some(p) = procs.get(&pid) else {
        return Err(format!("pid {pid} does not exist"));
    };
    if p.kthread {
        return Err(format!("refusing kernel thread pid {pid}"));
    }
    if p.uid != caller_uid {
        return Err(format!(
            "pid {pid} uid {} is not the invoking user {caller_uid}",
            p.uid
        ));
    }
    Ok(())
}

pub fn authorize_seed_pids(
    pids: &[u32],
    caller_uid: u32,
    procs: &HashMap<u32, ProcIdentity>,
) -> Result<Vec<u32>, String> {
    let mut out = Vec::new();
    for pid in pids {
        check_seed_pid(*pid, caller_uid, procs)?;
        if !out.contains(pid) {
            out.push(*pid);
        }
    }
    Ok(out)
}

/// Snapshot vs live identity: same PID, same starttime, still the invoking user.
pub fn identity_still_caller(
    snap: &ProcIdentity,
    now: &ProcIdentity,
    caller_uid: u32,
) -> bool {
    now.pid == snap.pid
        && now.pid >= 2
        && now.starttime == snap.starttime
        && now.uid == caller_uid
        && snap.uid == caller_uid
        && !now.kthread
        && !snap.kthread
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::forest::ProcIdentity;

    fn proc(pid: u32, uid: u32) -> ProcIdentity {
        ProcIdentity {
            pid,
            ppid: 1,
            uid,
            exe_base: "firefox".into(),
            comm: "firefox".into(),
            cgroup: "/user.slice/user-1000.slice".into(),
            starttime: 12345,
            kthread: false,
        }
    }

    fn map(list: Vec<ProcIdentity>) -> HashMap<u32, ProcIdentity> {
        list.into_iter().map(|p| (p.pid, p)).collect()
    }

    #[test]
    fn foreign_uid_pid_is_refused() {
        let procs = map(vec![proc(42, 0)]);
        let err = authorize_seed_pids(&[42], 1000, &procs).unwrap_err();
        assert!(
            err.contains("not the invoking user"),
            "expected foreign-uid refusal, got {err}"
        );
        assert!(check_seed_pid(42, 1000, &procs).is_err());
    }

    #[test]
    fn same_uid_pid_is_accepted() {
        let procs = map(vec![proc(42, 1000)]);
        assert_eq!(authorize_seed_pids(&[42], 1000, &procs).unwrap(), vec![42]);
    }

    #[test]
    fn pid_one_is_refused() {
        let procs = map(vec![proc(1, 0)]);
        let err = check_seed_pid(1, 0, &procs).unwrap_err();
        assert!(err.contains("pid 0/1"));
    }

    #[test]
    fn missing_pid_is_refused() {
        let procs = map(vec![]);
        let err = check_seed_pid(99, 1000, &procs).unwrap_err();
        assert!(err.contains("does not exist"));
    }

    #[test]
    fn kernel_thread_is_refused() {
        let mut k = proc(2, 0);
        k.kthread = true;
        k.comm = "kthreadd".into();
        let procs = map(vec![k]);
        let err = check_seed_pid(2, 0, &procs).unwrap_err();
        assert!(err.contains("kernel thread"));
    }

    #[test]
    fn mixed_list_fails_closed_on_foreign() {
        let procs = map(vec![proc(10, 1000), proc(11, 0)]);
        assert!(authorize_seed_pids(&[10, 11], 1000, &procs).is_err());
    }

    #[test]
    fn identity_mismatch_on_starttime_is_reuse() {
        let snap = proc(42, 1000);
        let mut now = snap.clone();
        now.starttime = 99999;
        assert!(!identity_still_caller(&snap, &now, 1000));
        now.starttime = snap.starttime;
        assert!(identity_still_caller(&snap, &now, 1000));
        now.uid = 0;
        assert!(!identity_still_caller(&snap, &now, 1000));
    }

    #[test]
    fn pkexec_uid_wins_over_root_euid() {
        assert_eq!(
            invoking_uid_from_env(Some("1000"), Some("0"), 0).unwrap(),
            1000
        );
    }

    #[test]
    fn sudo_uid_used_without_pkexec() {
        assert_eq!(invoking_uid_from_env(None, Some("1001"), 0).unwrap(), 1001);
    }

    #[test]
    fn root_without_caller_env_fails_closed() {
        assert!(invoking_uid_from_env(None, None, 0).is_err());
        assert!(invoking_uid_from_env(Some(""), Some("  "), 0).is_err());
    }

    #[test]
    fn non_root_euid_is_caller_when_env_missing() {
        assert_eq!(invoking_uid_from_env(None, None, 1000).unwrap(), 1000);
    }

    #[test]
    fn parse_stat_flags_and_starttime() {
        let stat = "42 (Web Content) S 1 1 1 0 -1 4194304 0 0 0 0 0 0 0 0 20 0 1 0 12345 0\n";
        let (flags, starttime) = parse_stat_fields(stat).unwrap();
        assert_eq!(flags, 4194304);
        assert_eq!(starttime, 12345);
        assert!(!is_kernel_thread(flags));
        assert!(is_kernel_thread(PF_KTHREAD));
    }
}
