//! Privileged helper for Snitch. Installed root-owned at
//! `/usr/lib/snitch/snitch-block` and invoked with `pkexec`.
//!
//! Verbs: block-app, unblock-app, block-ips, unblock-ips, teardown, status.

use serde_json::{json, Value};
use snitch_block::caller;
use snitch_block::deps::BlockingCaps;
use snitch_block::forest::{self, ProcIdentity};
use snitch_block::ids::sanitize_app;
use snitch_block::nft_verify;
use snitch_block::owners::{self, OwnerMap};
use snitch_block::restore::{self, RestoreFile};
use std::collections::HashMap;
use std::fs;
use std::io::Write;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

const CGROUP_ROOT: &str = "/sys/fs/cgroup";
const SLICE: &str = "snitch.slice";
const TABLE: &str = "snitch";
const OWNERS_PATH: &str = "/var/lib/snitch/endpoint-owners.json";
const CANONICAL_HELPER: &str = "/usr/lib/snitch/snitch-block";

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        fail(
            2,
            "usage: snitch-block <block-app|unblock-app|block-ips|unblock-ips|teardown|status> ...",
        );
    }
    let result = match args[1].as_str() {
        "block-app" => {
            if args.len() < 3 {
                fail(2, "block-app <app-id> [pid...]");
            }
            block_app(&args[2], &args[3..])
        }
        "unblock-app" => {
            if args.len() < 3 {
                fail(2, "unblock-app <app-id>");
            }
            unblock_app(&args[2])
        }
        "block-ips" => {
            if args.len() < 4 {
                fail(2, "block-ips <app-id> <ip> [ip...]");
            }
            block_ips(&args[2], &args[3..])
        }
        "unblock-ips" => {
            if args.len() < 3 {
                fail(2, "unblock-ips <app-id>");
            }
            unblock_ips(&args[2])
        }
        "teardown" => teardown(),
        "status" => status(),
        other => fail(2, &format!("unknown verb {other}")),
    };
    match result {
        Ok(v) => println!("{v}"),
        Err(e) => {
            if e.trim_start().starts_with('{') {
                println!("{e}");
            } else {
                println!("{}", json!({"ok": false, "error": e, "rollback": false}));
            }
            std::process::exit(1);
        }
    }
}

fn fail_block(code: &str, error: String, rollback: bool) -> Result<Value, String> {
    Err(json!({"ok": false, "error": error, "code": code, "rollback": rollback}).to_string())
}

fn fail(code: i32, msg: &str) -> ! {
    eprintln!("{msg}");
    println!("{}", json!({"ok": false, "error": msg}));
    std::process::exit(code);
}

fn parse_pid(s: &str) -> Result<u32, String> {
    s.parse::<u32>().map_err(|_| format!("bad pid {s}"))
}

fn cgroup_slice() -> PathBuf {
    Path::new(CGROUP_ROOT).join(SLICE)
}

fn cgroup_app(app: &str) -> PathBuf {
    cgroup_slice().join(format!("snitch-{app}"))
}

fn cgroup_match_path(app: &str) -> String {
    format!("{SLICE}/snitch-{app}")
}

fn owners_path() -> PathBuf {
    PathBuf::from(OWNERS_PATH)
}

fn block_app(app_raw: &str, pids: &[String]) -> Result<Value, String> {
    let app = sanitize_app(app_raw)?;
    let caller_uid = match caller::invoking_uid() {
        Ok(u) => u,
        Err(e) => return fail_block("pid-owner", e, false),
    };
    let seeds_raw: Vec<u32> = pids
        .iter()
        .map(|s| parse_pid(s))
        .collect::<Result<Vec<u32>, String>>()?;
    if !Path::new(CGROUP_ROOT).join("cgroup.controllers").is_file() {
        return Err("cgroup v2 not mounted at /sys/fs/cgroup".into());
    }
    let procs = snapshot_proc();
    let seeds = match caller::authorize_seed_pids(&seeds_raw, caller_uid, &procs) {
        Ok(s) => s,
        Err(e) => {
            return fail_block("pid-owner", e, false);
        }
    };
    let forest = forest::collect_forest(&seeds, &procs);
    let live = match caller::authorize_seed_pids(&forest, caller_uid, &procs) {
        Ok(s) => s,
        Err(e) => {
            return fail_block("pid-owner", e, false);
        }
    };
    if live.is_empty() {
        return fail_block(
            "empty-forest",
            "no live processes in the application forest".into(),
            true,
        );
    }

    let mut restore_file = RestoreFile::default();
    for pid in &live {
        let Some(p) = procs.get(pid) else {
            return fail_block(
                "pid-owner",
                format!("pid {pid} has no recorded membership — refusing cgroup block"),
                false,
            );
        };
        let Some(now) = read_identity(*pid) else {
            return fail_block(
                "pid-owner",
                format!("pid {pid} vanished before migrate — refusing cgroup block"),
                false,
            );
        };
        if !caller::identity_still_caller(p, &now, caller_uid) {
            return fail_block(
                "pid-owner",
                format!("pid {pid} is not the invoking user's process (uid/starttime mismatch)"),
                false,
            );
        }
        if restore::is_root_cgroup(&p.cgroup) {
            return fail_block(
                "root-cgroup",
                format!(
                    "pid {pid} is in the root cgroup; cgroup-block refused (use endpoint fallback)"
                ),
                true,
            );
        }
        restore_file.pids.insert(
            pid.to_string(),
            restore::RestorePid {
                cgroup: p.cgroup.clone(),
                uid: p.uid,
                starttime: p.starttime,
            },
        );
    }
    restore::save(&restore::path_for(&app), &restore_file)?;

    ensure_table_and_output_chain()?;
    let slice = cgroup_slice();
    fs::create_dir_all(&slice).map_err(|e| format!("mkdir slice: {e}"))?;
    let _ = fs::write(slice.join("cgroup.subtree_control"), "+pids\n");
    let dest = cgroup_app(&app);
    fs::create_dir_all(&dest).map_err(|e| format!("mkdir app cgroup: {e}"))?;
    let dest_rel = cgroup_match_path(&app);

    let mut moved = Vec::new();
    for pid in &live {
        let Some(snap) = procs.get(pid) else {
            return rollback_block(
                &app,
                &dest_rel,
                format!("pid {pid} dropped from snapshot"),
                "pid-owner",
            );
        };
        let Some(now) = read_identity(*pid) else {
            return rollback_block(
                &app,
                &dest_rel,
                format!("pid {pid} vanished during migrate"),
                "pid-owner",
            );
        };
        if !caller::identity_still_caller(snap, &now, caller_uid) {
            return rollback_block(
                &app,
                &dest_rel,
                format!("pid {pid} uid/starttime changed — refusing migrate"),
                "pid-owner",
            );
        }
        if write_proc(&dest, *pid).is_err() {
            return rollback_block(
                &app,
                &dest_rel,
                format!("migrate {pid} failed"),
                "migrate",
            );
        }
        let cur = read_proc_cgroup(*pid).unwrap_or_default();
        if !restore::membership_matches(&cur, &format!("/{dest_rel}"))
            && !restore::membership_matches(&cur, &dest_rel)
        {
            return rollback_block(
                &app,
                &dest_rel,
                format!("pid {pid} cgroup is {cur}, expected {dest_rel}"),
                "migrate",
            );
        }
        moved.push(*pid);
    }
    if moved.len() != live.len() {
        return rollback_block(
            &app,
            &dest_rel,
            format!("partial migration {}/{} — refusing verified:true", moved.len(), live.len()),
            "migrate",
        );
    }

    if let Err(e) = add_cgroup_drop_rule(&dest_rel) {
        return rollback_block(&app, &dest_rel, e, "nft");
    }
    if !verify_cgroup_rule(&dest_rel) {
        return rollback_block(
            &app,
            &dest_rel,
            "nft rule did not land (nft list check failed)".into(),
            "nft",
        );
    }

    let remotes = collect_remotes(&moved);
    let flush = flush_conntrack(&remotes)?;
    if !flush.ok {
        return rollback_block(
            &app,
            &dest_rel,
            format!("conntrack flush failed ({})", flush.summary()),
            "conntrack",
        );
    }

    Ok(json!({
        "ok": true,
        "mechanism": "cgroup",
        "path": dest_rel,
        "level": restore::cgroup_match_level(&dest_rel),
        "moved": moved,
        "forest": live,
        "flushed": flush.flushed,
        "flushFailed": flush.failed,
        "verified": true,
        "helper": CANONICAL_HELPER
    }))
}

fn rollback_block(app: &str, path: &str, why: String, code: &str) -> Result<Value, String> {
    let _ = delete_rules_containing(path);
    match restore_memberships(app) {
        Ok(_) => fail_block(code, format!("{why} — rolled back"), true),
        Err(e) => fail_block(
            "rollback-failed",
            format!("{why}; restore failed ({e}) — processes may still be in snitch.slice"),
            false,
        ),
    }
}

fn read_proc_cgroup(pid: u32) -> Option<String> {
    let t = fs::read_to_string(format!("/proc/{pid}/cgroup")).ok()?;
    restore::parse_unified_cgroup(&t)
}

fn snapshot_proc() -> HashMap<u32, ProcIdentity> {
    let mut map = HashMap::new();
    let Ok(rd) = fs::read_dir("/proc") else {
        return map;
    };
    for e in rd.flatten() {
        let pid: u32 = match e.file_name().to_str().and_then(|s| s.parse().ok()) {
            Some(p) if p >= 1 => p,
            _ => continue,
        };
        // PID 1 is snapshotted so authorize can refuse it explicitly.
        if let Some(id) = read_identity(pid) {
            map.insert(pid, id);
        }
    }
    map
}

fn read_identity(pid: u32) -> Option<ProcIdentity> {
    let status = fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    let mut ppid = 0u32;
    let mut uid = 0u32;
    for line in status.lines() {
        if let Some(r) = line.strip_prefix("PPid:") {
            ppid = r.split_whitespace().next()?.parse().ok()?;
        }
        if let Some(r) = line.strip_prefix("Uid:") {
            uid = r.split_whitespace().next()?.parse().ok()?;
        }
    }
    let stat = fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let (flags, starttime) = caller::parse_stat_fields(&stat)?;
    let kthread = caller::is_kernel_thread(flags);
    let exe_base = fs::read_link(format!("/proc/{pid}/exe"))
        .ok()
        .and_then(|p| p.file_name().map(|n| n.to_string_lossy().into_owned()))
        .unwrap_or_default();
    let comm = fs::read_to_string(format!("/proc/{pid}/comm"))
        .unwrap_or_default()
        .trim()
        .to_string();
    let cgroup = fs::read_to_string(format!("/proc/{pid}/cgroup"))
        .ok()
        .and_then(|t| restore::parse_unified_cgroup(&t))
        .unwrap_or_default();
    Some(ProcIdentity {
        pid,
        ppid,
        uid,
        exe_base,
        comm,
        cgroup,
        starttime,
        kthread,
    })
}

fn restore_memberships(app: &str) -> Result<Vec<u32>, String> {
    let file = restore::load(&restore::path_for(app));
    let mut restored = Vec::new();
    let mut errors = Vec::new();
    for (pid_s, rec) in &file.pids {
        let pid: u32 = match pid_s.parse() {
            Ok(p) => p,
            Err(_) => continue,
        };
        let orig = &rec.cgroup;
        if !Path::new(&format!("/proc/{pid}")).exists() {
            continue;
        }
        let Some(now) = read_identity(pid) else {
            continue;
        };
        if now.uid != rec.uid || now.starttime != rec.starttime {
            errors.push(format!("{pid}: uid/starttime mismatch — refusing restore (PID reuse)"));
            continue;
        }
        if restore::is_root_cgroup(orig) {
            errors.push(format!("{pid}: refusing to write cgroup root"));
            continue;
        }
        let dest = restore::sys_path(Path::new(CGROUP_ROOT), orig);
        if write_proc(&dest, pid).is_err() {
            errors.push(format!("{pid}: restore to {} failed", dest.display()));
            continue;
        }
        let current = fs::read_to_string(format!("/proc/{pid}/cgroup"))
            .ok()
            .and_then(|t| restore::parse_unified_cgroup(&t))
            .unwrap_or_default();
        if !restore::membership_matches(&current, orig) {
            errors.push(format!("{pid}: still in {current}, wanted {orig}"));
            continue;
        }
        restored.push(pid);
    }
    if !errors.is_empty() {
        return Err(errors.join("; "));
    }
    Ok(restored)
}

fn write_proc(dest: &Path, pid: u32) -> Result<(), String> {
    let mut f = fs::OpenOptions::new()
        .write(true)
        .open(dest.join("cgroup.procs"))
        .map_err(|e| format!("open cgroup.procs: {e}"))?;
    write!(f, "{pid}").map_err(|e| format!("migrate {pid}: {e}"))
}

fn collect_remotes(pids: &[u32]) -> Vec<IpAddr> {
    let mut inodes = std::collections::HashSet::new();
    for pid in pids {
        if let Ok(fd) = fs::read_dir(format!("/proc/{pid}/fd")) {
            for e in fd.flatten() {
                if let Ok(t) = fs::read_link(e.path()) {
                    let s = t.to_string_lossy();
                    if let Some(rest) = s.strip_prefix("socket:[") {
                        if let Some(n) = rest.strip_suffix(']').and_then(|x| x.parse::<u64>().ok()) {
                            inodes.insert(n);
                        }
                    }
                }
            }
        }
    }
    let mut remotes = Vec::new();
    for path in ["/proc/net/tcp", "/proc/net/tcp6", "/proc/net/udp", "/proc/net/udp6"] {
        let Ok(text) = fs::read_to_string(path) else { continue };
        let v6 = path.contains("6");
        for (i, line) in text.lines().enumerate() {
            if i == 0 {
                continue;
            }
            let cols: Vec<&str> = line.split_whitespace().collect();
            if cols.len() < 10 {
                continue;
            }
            let inode: u64 = match cols[9].parse() {
                Ok(n) => n,
                Err(_) => continue,
            };
            if !inodes.contains(&inode) {
                continue;
            }
            if let Some(ip) = parse_remote_ip(cols[2], v6) {
                if !ip.is_unspecified() && !ip.is_loopback() {
                    remotes.push(ip);
                }
            }
        }
    }
    remotes.sort_by_key(|i| i.to_string());
    remotes.dedup();
    remotes
}

fn parse_remote_ip(col: &str, v6: bool) -> Option<IpAddr> {
    let addr = col.rsplit_once(':')?.0;
    if !v6 {
        if addr.len() != 8 {
            return None;
        }
        let n = u32::from_str_radix(addr, 16).ok()?;
        Some(IpAddr::V4(std::net::Ipv4Addr::new(
            (n & 0xff) as u8,
            ((n >> 8) & 0xff) as u8,
            ((n >> 16) & 0xff) as u8,
            ((n >> 24) & 0xff) as u8,
        )))
    } else {
        if addr.len() != 32 {
            return None;
        }
        let mut bytes = [0u8; 16];
        for word in 0..4 {
            let n = u32::from_str_radix(&addr[word * 8..word * 8 + 8], 16).ok()?;
            bytes[word * 4..word * 4 + 4].copy_from_slice(&n.to_le_bytes());
        }
        Some(IpAddr::V6(std::net::Ipv6Addr::from(bytes)))
    }
}

struct FlushReport {
    flushed: Vec<String>,
    failed: Vec<String>,
    ok: bool,
    missing_tool: bool,
}

impl FlushReport {
    fn summary(&self) -> String {
        if self.missing_tool {
            "conntrack not installed".into()
        } else if self.failed.is_empty() {
            format!("{} flushed", self.flushed.len())
        } else {
            format!(
                "{} flushed, {} failed ({})",
                self.flushed.len(),
                self.failed.len(),
                self.failed.join(", ")
            )
        }
    }
}

fn flush_conntrack(remotes: &[IpAddr]) -> Result<FlushReport, String> {
    if remotes.is_empty() {
        return Ok(FlushReport {
            flushed: vec![],
            failed: vec![],
            ok: true,
            missing_tool: false,
        });
    }
    if which("conntrack").is_none() {
        return Ok(FlushReport {
            flushed: vec![],
            failed: remotes.iter().map(|i| i.to_string()).collect(),
            ok: false,
            missing_tool: true,
        });
    }
    let mut flushed = Vec::new();
    let mut failed = Vec::new();
    for ip in remotes {
        match conntrack_delete(ip) {
            Ok(()) => flushed.push(ip.to_string()),
            Err(e) => failed.push(format!("{ip}: {e}")),
        }
    }
    Ok(FlushReport {
        ok: failed.is_empty(),
        flushed,
        failed,
        missing_tool: false,
    })
}

fn which(name: &str) -> Option<PathBuf> {
    let mut dirs: Vec<String> = Vec::new();
    if let Ok(path) = std::env::var("PATH") {
        dirs.extend(
            path.split(':')
                .filter(|s| !s.is_empty())
                .map(|s| s.to_string()),
        );
    }
    for extra in ["/usr/sbin", "/sbin", "/usr/bin", "/bin"] {
        if !dirs.iter().any(|d| d == extra) {
            dirs.push(extra.to_string());
        }
    }
    for dir in dirs {
        let p = Path::new(&dir).join(name);
        if is_executable(&p) {
            return Some(p);
        }
    }
    None
}

fn is_executable(p: &Path) -> bool {
    if !p.is_file() {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        return std::fs::metadata(p)
            .map(|m| m.permissions().mode() & 0o111 != 0)
            .unwrap_or(false);
    }
    #[cfg(not(unix))]
    {
        true
    }
}

fn cgroup_v2_present() -> bool {
    Path::new("/sys/fs/cgroup/cgroup.controllers").is_file()
        || Path::new("/sys/fs/cgroup/unified/cgroup.controllers").is_file()
}

fn probe_blocking_caps() -> BlockingCaps {
    BlockingCaps::from_presence(
        which("nft").is_some(),
        which("conntrack").is_some(),
        cgroup_v2_present(),
    )
}

/// Treat "deleted N" and "0 flow entries have been deleted" as success.
/// Anything else (missing binary already handled, permission, bad syntax) is failure.
fn conntrack_delete(ip: &IpAddr) -> Result<(), String> {
    let mut cmd = Command::new("conntrack");
    match ip {
        IpAddr::V4(_) => {
            cmd.args(["-D", "-d", &ip.to_string()]);
        }
        IpAddr::V6(_) => {
            cmd.args(["-f", "ipv6", "-D", "-d", &ip.to_string()]);
        }
    }
    let out = cmd
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .map_err(|e| format!("conntrack exec: {e}"))?;
    if out.status.success() {
        return Ok(());
    }
    let text = format!(
        "{} {}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
    .to_lowercase();
    if text.contains("0 flow entries") || text.contains("has been deleted") || text.contains("have been deleted")
    {
        return Ok(());
    }
    Err(text.trim().to_string())
}

fn ensure_table_and_output_chain() -> Result<(), String> {
    nft(&["add", "table", "inet", TABLE])?;
    nft(&[
        "add",
        "chain",
        "inet",
        TABLE,
        "out",
        "{ type filter hook output priority 0; policy accept; }",
    ])?;
    Ok(())
}

fn add_cgroup_drop_rule(path: &str) -> Result<(), String> {
    if verify_cgroup_rule(path) {
        return Ok(());
    }
    let level = restore::cgroup_match_level(path).to_string();
    nft(&[
        "add",
        "rule",
        "inet",
        TABLE,
        "out",
        "socket",
        "cgroupv2",
        "level",
        &level,
        path,
        "drop",
    ])
}

fn verify_cgroup_rule(path: &str) -> bool {
    let level = restore::cgroup_match_level(path);
    if let Some(js) = nft_list_table_json() {
        if nft_verify::cgroup_drop_in_json(&js, path, level) {
            return true;
        }
    }
    nft_verify::cgroup_drop_in_text(&nft_list_table(), path, level)
}

fn unblock_app(app_raw: &str) -> Result<Value, String> {
    let app = sanitize_app(app_raw)?;
    let path = cgroup_match_path(&app);
    delete_rules_containing(&path)?;
    if verify_cgroup_rule(&path) {
        return Err("cgroup drop rule still present after delete".into());
    }
    let restored = restore_memberships(&app)?;
    let dest = cgroup_app(&app);
    if dest.exists() {
        fs::remove_dir(&dest).map_err(|e| format!("rmdir {}: {e}", dest.display()))?;
    }
    let _ = fs::remove_file(restore::path_for(&app));
    Ok(json!({
        "ok": true,
        "mechanism": "cgroup",
        "path": path,
        "restored": restored,
        "verified": true
    }))
}

fn delete_rules_containing(needle: &str) -> Result<(), String> {
    let level = restore::cgroup_match_level(needle);
    let out = Command::new("nft")
        .args(["-a", "list", "chain", "inet", TABLE, "out"])
        .output()
        .map_err(|e| format!("nft list: {e}"))?;
    let text = String::from_utf8_lossy(&out.stdout);
    for line in text.lines() {
        if !nft_verify::cgroup_drop_in_text(line, needle, level) {
            continue;
        }
        if let Some(handle) = line.rsplit("handle").nth(0).map(str::trim) {
            if handle.chars().all(|c| c.is_ascii_digit()) {
                nft(&["delete", "rule", "inet", TABLE, "out", "handle", handle])?;
            }
        }
    }
    Ok(())
}

fn ensure_ip_sets_and_rules() -> Result<(), String> {
    ensure_table_and_output_chain()?;
    nft(&["add", "set", "inet", TABLE, "blocked4", "{ type ipv4_addr; }"])?;
    nft(&["add", "set", "inet", TABLE, "blocked6", "{ type ipv6_addr; }"])?;
    let listed = nft_list_table();
    if !listed.contains("ip daddr @blocked4") {
        nft(&["add", "rule", "inet", TABLE, "out", "ip", "daddr", "@blocked4", "drop"])?;
    }
    if !listed.contains("ip6 daddr @blocked6") {
        nft(&["add", "rule", "inet", TABLE, "out", "ip6", "daddr", "@blocked6", "drop"])?;
    }
    let listed = nft_list_table();
    if !listed.contains("ip daddr @blocked4") || !listed.contains("ip6 daddr @blocked6") {
        return Err("host-wide drop rules for blocked4/blocked6 did not land".into());
    }
    Ok(())
}

fn set_name(ip: &IpAddr) -> &'static str {
    match ip {
        IpAddr::V4(_) => "blocked4",
        IpAddr::V6(_) => "blocked6",
    }
}

fn add_element(ip: &IpAddr) -> Result<(), String> {
    nft(&[
        "add",
        "element",
        "inet",
        TABLE,
        set_name(ip),
        &format!("{{ {ip} }}"),
    ])
}

fn delete_element(ip: &IpAddr) -> Result<(), String> {
    nft(&[
        "delete",
        "element",
        "inet",
        TABLE,
        set_name(ip),
        &format!("{{ {ip} }}"),
    ])
}

fn verify_element_present(ip: &IpAddr) -> bool {
    nft_list_set(set_name(ip)).contains(&ip.to_string())
}

fn verify_element_absent(ip: &IpAddr) -> bool {
    !nft_list_set(set_name(ip)).contains(&ip.to_string())
}

fn nft_list_set(name: &str) -> String {
    Command::new("nft")
        .args(["list", "set", "inet", TABLE, name])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
        .unwrap_or_default()
}

fn block_ips(app_raw: &str, ips: &[String]) -> Result<Value, String> {
    let app = sanitize_app(app_raw)?;
    let mut parsed: Vec<IpAddr> = Vec::new();
    for s in ips {
        parsed.push(s.parse::<IpAddr>().map_err(|_| format!("bad ip {s}"))?);
    }
    ensure_ip_sets_and_rules()?;
    let mut added: Vec<String> = Vec::new();
    for ip in &parsed {
        add_element(ip)?;
        if !verify_element_present(ip) {
            for prev in &added {
                if let Ok(prev_ip) = prev.parse::<IpAddr>() {
                    let _ = delete_element(&prev_ip);
                }
            }
            let _ = delete_element(ip);
            return Err(format!("{ip} not present in nft set after add"));
        }
        added.push(ip.to_string());
    }

    let flush = flush_conntrack(&parsed)?;
    if !flush.ok {
        for ip_s in &added {
            if let Ok(ip) = ip_s.parse::<IpAddr>() {
                let _ = delete_element(&ip);
            }
        }
        return Err(format!(
            "conntrack flush failed — nft elements rolled back ({})",
            flush.summary()
        ));
    }

    let mut map = owners::load(&owners_path());
    owners::grant(&mut map, &app, &added);
    owners::save(&owners_path(), &map)?;
    Ok(json!({
        "ok": true,
        "mechanism": "endpoints",
        "hostWide": true,
        "app": app,
        "ips": added,
        "flushed": flush.flushed,
        "flushFailed": flush.failed,
        "verified": true,
        "warning": "endpoints only — affects all apps"
    }))
}

fn unblock_ips(app_raw: &str) -> Result<Value, String> {
    let app = sanitize_app(app_raw)?;
    let mut map = owners::load(&owners_path());
    let (released, retained) = owners::exclusive_release(&mut map, &app);
    if released.is_empty() && retained.is_empty() && !map.contains_key(&app) {
        owners::save(&owners_path(), &map)?;
        return Ok(json!({
            "ok": true,
            "mechanism": "endpoints",
            "app": app,
            "released": released,
            "retained": retained,
            "verified": true
        }));
    }
    let mut missing = Vec::new();
    for ip_s in &released {
        let ip: IpAddr = ip_s.parse().map_err(|_| format!("bad stored ip {ip_s}"))?;
        delete_element(&ip)?;
        if !verify_element_absent(&ip) {
            missing.push(ip_s.clone());
        }
    }
    owners::save(&owners_path(), &map)?;
    if !missing.is_empty() {
        return Err(format!(
            "failed to remove exclusive endpoint(s) from nft set: {}",
            missing.join(", ")
        ));
    }
    Ok(json!({
        "ok": true,
        "mechanism": "endpoints",
        "app": app,
        "released": released,
        "retained": retained,
        "verified": true
    }))
}

fn teardown() -> Result<Value, String> {
    let mut errors: Vec<String> = Vec::new();
    let listed_before = nft_list_table();
    if !listed_before.trim().is_empty() || Path::new("/sys/fs/cgroup").join(SLICE).exists() {
        let nft_out = Command::new("nft")
            .args(["delete", "table", "inet", TABLE])
            .output();
        match nft_out {
            Ok(o) if o.status.success() => {}
            Ok(o) => {
                let err = String::from_utf8_lossy(&o.stderr);
                if !err.contains("No such file") && !err.contains("does not exist") && !listed_before.trim().is_empty()
                {
                    errors.push(format!("nft delete table: {err}"));
                }
            }
            Err(e) => errors.push(format!("nft exec: {e}")),
        }
    }
    let still = nft_list_table();
    if still.contains(&format!("table inet {TABLE}")) || still.contains("blocked4") {
        errors.push("table inet snitch still present after delete".into());
    }

    let restore_dir = Path::new("/var/lib/snitch/cgroup-restore");
    if restore_dir.is_dir() {
        if let Ok(rd) = fs::read_dir(restore_dir) {
            for e in rd.flatten() {
                let stem = e
                    .path()
                    .file_stem()
                    .map(|s| s.to_string_lossy().into_owned())
                    .unwrap_or_default();
                if stem.is_empty() {
                    continue;
                }
                match restore_memberships(&stem) {
                    Ok(_) => {
                        let _ = fs::remove_file(e.path());
                    }
                    Err(err) => errors.push(format!("restore {stem}: {err}")),
                }
            }
        }
    }

    let slice = cgroup_slice();
    if slice.is_dir() {
        if let Ok(rd) = fs::read_dir(&slice) {
            for e in rd.flatten() {
                let p = e.path();
                if let Err(e) = fs::remove_dir(&p) {
                    errors.push(format!("rmdir {}: {e}", p.display()));
                }
            }
        }
        if let Err(e) = fs::remove_dir(&slice) {
            if slice.exists() {
                errors.push(format!("rmdir {}: {e}", slice.display()));
            }
        }
    }
    if slice.exists() {
        errors.push(format!("{} still exists", slice.display()));
    }
    let _ = fs::remove_file(owners_path());

    if !errors.is_empty() {
        return Err(errors.join("; "));
    }
    Ok(json!({"ok": true, "teardown": true, "verified": true}))
}

fn status() -> Result<Value, String> {
    let listed = nft_list_table();
    let has_table = listed.contains("table inet") || listed.contains(&format!("table inet {TABLE}"));
    let map: OwnerMap = owners::load(&owners_path());
    let caps = probe_blocking_caps();
    Ok(json!({
        "ok": true,
        "table": has_table,
        "owners": map,
        "raw": listed,
        "helper": CANONICAL_HELPER,
        "nft": caps.nft,
        "conntrack": caps.conntrack,
        "cgroupv2": caps.cgroupv2,
        "blockingReady": caps.ready(),
        "missing": caps.missing(),
        "packages": caps.packages(),
        "hint": caps.hint()
    }))
}

fn nft(args: &[&str]) -> Result<(), String> {
    let out = Command::new("nft")
        .args(args)
        .output()
        .map_err(|e| format!("nft exec: {e}"))?;
    if out.status.success() {
        return Ok(());
    }
    let err = String::from_utf8_lossy(&out.stderr);
    if err.contains("exist") || err.contains("File exists") || err.contains("No such file") {
        // delete of missing element is success for idempotent unblock
        if args.first().copied() == Some("delete") {
            return Ok(());
        }
        if err.contains("exist") || err.contains("File exists") {
            return Ok(());
        }
    }
    Err(format!("nft {} failed: {err}", args.join(" ")))
}

fn nft_list_table() -> String {
    Command::new("nft")
        .args(["list", "table", "inet", TABLE])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
        .unwrap_or_default()
}

fn nft_list_table_json() -> Option<String> {
    let out = Command::new("nft")
        .args(["-j", "list", "table", "inet", TABLE])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let s = String::from_utf8_lossy(&out.stdout).into_owned();
    if s.trim().is_empty() {
        return None;
    }
    Some(s)
}
