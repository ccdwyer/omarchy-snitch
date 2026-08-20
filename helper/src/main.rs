//! Privileged helper for Snitch. Intended to be installed root-owned and
//! invoked with `pkexec`. Verbs: block-app, unblock-app, block-ips, teardown, status.
//!
//! Blocking uses nftables `socket cgroupv2` (cgroup v2) after migrating the
//! app's process tree into `snitch.slice/snitch-<app>`. Established flows are
//! killed with a conntrack flush. IP-set mode is a separate, explicit verb.

use serde_json::{json, Value};
use std::fs;
use std::io::Write;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

const CGROUP_ROOT: &str = "/sys/fs/cgroup";
const SLICE: &str = "snitch.slice";
const TABLE: &str = "snitch";

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        fail(2, "usage: snitch-block <block-app|unblock-app|block-ips|teardown|status> ...");
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
        "teardown" => teardown(),
        "status" => status(),
        other => fail(2, &format!("unknown verb {other}")),
    };
    match result {
        Ok(v) => {
            println!("{v}");
        }
        Err(e) => {
            println!("{}", json!({"ok": false, "error": e}));
            std::process::exit(1);
        }
    }
}

fn fail(code: i32, msg: &str) -> ! {
    eprintln!("{msg}");
    println!("{}", json!({"ok": false, "error": msg}));
    std::process::exit(code);
}

fn sanitize_app(id: &str) -> Result<String, String> {
    let s: String = id
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.' {
                c.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect();
    let s = s.trim_matches('-').to_string();
    if s.is_empty() || s.len() > 64 {
        return Err("invalid app id".into());
    }
    Ok(s)
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

fn block_app(app_raw: &str, pids: &[String]) -> Result<Value, String> {
    let app = sanitize_app(app_raw)?;
    let pids: Vec<u32> = pids.iter().map(|s| parse_pid(s)).collect::<Result<_, _>>()?;
    if !Path::new(CGROUP_ROOT).join("cgroup.controllers").is_file() {
        return Err("cgroup v2 not mounted at /sys/fs/cgroup".into());
    }
    ensure_table_and_output_chain()?;
    let slice = cgroup_slice();
    fs::create_dir_all(&slice).map_err(|e| format!("mkdir slice: {e}"))?;
    // Best-effort: enable pids on the slice so children can be created.
    let _ = fs::write(slice.join("cgroup.subtree_control"), "+pids\n");
    let dest = cgroup_app(&app);
    fs::create_dir_all(&dest).map_err(|e| format!("mkdir app cgroup: {e}"))?;

    let mut moved = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for pid in pids {
        migrate_tree(pid, &dest, &mut seen, &mut moved);
    }
    if moved.is_empty() {
        return Err("no processes migrated; cannot install a truthful cgroup block".into());
    }

    let path = cgroup_match_path(&app);
    // level 2: snitch.slice / snitch-<app>
    add_cgroup_drop_rule(&path)?;
    if !verify_cgroup_rule(&path) {
        return Err("nft rule did not land (nft list check failed)".into());
    }

    let remotes = collect_remotes(&moved);
    let flushed = flush_conntrack(&remotes);

    Ok(json!({
        "ok": true,
        "mechanism": "cgroup",
        "path": path,
        "moved": moved,
        "flushed": flushed,
        "verified": true
    }))
}

fn migrate_tree(pid: u32, dest: &Path, seen: &mut std::collections::HashSet<u32>, moved: &mut Vec<u32>) {
    if !seen.insert(pid) {
        return;
    }
    if write_proc(dest, pid).is_ok() {
        moved.push(pid);
    }
    for child in children_of(pid) {
        migrate_tree(child, dest, seen, moved);
    }
}

fn write_proc(dest: &Path, pid: u32) -> Result<(), String> {
    let mut f = fs::OpenOptions::new()
        .write(true)
        .open(dest.join("cgroup.procs"))
        .map_err(|e| format!("open cgroup.procs: {e}"))?;
    write!(f, "{pid}").map_err(|e| format!("migrate {pid}: {e}"))
}

fn children_of(pid: u32) -> Vec<u32> {
    let mut kids = Vec::new();
    let task = format!("/proc/{pid}/task");
    let Ok(tasks) = fs::read_dir(&task) else {
        return kids;
    };
    for t in tasks.flatten() {
        let p = t.path().join("children");
        if let Ok(text) = fs::read_to_string(p) {
            for tok in text.split_whitespace() {
                if let Ok(c) = tok.parse::<u32>() {
                    kids.push(c);
                }
            }
        }
    }
    kids
}

fn collect_remotes(pids: &[u32]) -> Vec<IpAddr> {
    // Best-effort: parse /proc/net for inodes owned by these pids.
    // Helper is privileged so it can read other-uid sockets too, but we still
    // only flush remotes we can see.
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
    for path in ["/proc/net/tcp", "/proc/net/tcp6"] {
        let Ok(text) = fs::read_to_string(path) else { continue };
        let v6 = path.ends_with('6');
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

fn flush_conntrack(remotes: &[IpAddr]) -> Vec<String> {
    let mut flushed = Vec::new();
    for ip in remotes {
        let mut cmd = Command::new("conntrack");
        match ip {
            IpAddr::V4(_) => {
                cmd.args(["-D", "-d", &ip.to_string()]);
            }
            IpAddr::V6(_) => {
                cmd.args(["-f", "ipv6", "-D", "-d", &ip.to_string()]);
            }
        }
        let _ = cmd.stdout(Stdio::null()).stderr(Stdio::null()).status();
        flushed.push(ip.to_string());
    }
    flushed
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
    nft(&[
        "add",
        "rule",
        "inet",
        TABLE,
        "out",
        "socket",
        "cgroupv2",
        "level",
        "2",
        path,
        "drop",
    ])
}

fn verify_cgroup_rule(path: &str) -> bool {
    let out = Command::new("nft")
        .args(["list", "table", "inet", TABLE])
        .output();
    match out {
        Ok(o) => {
            let text = String::from_utf8_lossy(&o.stdout);
            o.status.success() && text.contains(path) && text.contains("socket cgroupv2")
        }
        Err(_) => false,
    }
}

fn unblock_app(app_raw: &str) -> Result<Value, String> {
    let app = sanitize_app(app_raw)?;
    let path = cgroup_match_path(&app);
    // Recreate the chain without this path's rule: dump, delete chain, re-add others.
    // Safer and still tiny: delete table rules matching the path via `nft -a list` + `nft delete rule handle`.
    delete_rules_containing(&path)?;
    let dest = cgroup_app(&app);
    // Move leftover procs to the root cgroup so rmdir can succeed.
    if let Ok(text) = fs::read_to_string(dest.join("cgroup.procs")) {
        for tok in text.split_whitespace() {
            if let Ok(pid) = tok.parse::<u32>() {
                let _ = fs::write(Path::new(CGROUP_ROOT).join("cgroup.procs"), pid.to_string());
            }
        }
    }
    let _ = fs::remove_dir(&dest);
    Ok(json!({
        "ok": true,
        "mechanism": "cgroup",
        "path": path,
        "verified": !verify_cgroup_rule(&path)
    }))
}

fn delete_rules_containing(needle: &str) -> Result<(), String> {
    let out = Command::new("nft")
        .args(["-a", "list", "chain", "inet", TABLE, "out"])
        .output()
        .map_err(|e| format!("nft list: {e}"))?;
    let text = String::from_utf8_lossy(&out.stdout);
    for line in text.lines() {
        if line.contains(needle) {
            if let Some(handle) = line.rsplit("handle").nth(0).map(str::trim) {
                if handle.chars().all(|c| c.is_ascii_digit()) {
                    let _ = nft(&["delete", "rule", "inet", TABLE, "out", "handle", handle]);
                }
            }
        }
    }
    Ok(())
}

fn block_ips(app_raw: &str, ips: &[String]) -> Result<Value, String> {
    let app = sanitize_app(app_raw)?;
    let mut parsed: Vec<IpAddr> = Vec::new();
    for s in ips {
        parsed.push(s.parse::<IpAddr>().map_err(|_| format!("bad ip {s}"))?);
    }
    ensure_table_and_output_chain()?;
    nft(&["add", "set", "inet", TABLE, "blocked4", "{ type ipv4_addr; }"])?;
    nft(&["add", "set", "inet", TABLE, "blocked6", "{ type ipv6_addr; }"])?;
    // Idempotent rule add: skip if already present.
    let listed = nft_list_table();
    if !listed.contains("ip daddr @blocked4") {
        nft(&["add", "rule", "inet", TABLE, "out", "ip", "daddr", "@blocked4", "drop"])?;
    }
    if !listed.contains("ip6 daddr @blocked6") {
        nft(&["add", "rule", "inet", TABLE, "out", "ip6", "daddr", "@blocked6", "drop"])?;
    }
    let mut added = Vec::new();
    for ip in &parsed {
        match ip {
            IpAddr::V4(_) => {
                nft(&["add", "element", "inet", TABLE, "blocked4", &format!("{{ {ip} }}")])?;
            }
            IpAddr::V6(_) => {
                nft(&["add", "element", "inet", TABLE, "blocked6", &format!("{{ {ip} }}")])?;
            }
        }
        added.push(ip.to_string());
    }
    let flushed = flush_conntrack(&parsed);
    let verified = nft_list_table().contains("blocked4") || nft_list_table().contains("blocked6");
    if !verified {
        return Err("ip set did not land".into());
    }
    Ok(json!({
        "ok": true,
        "mechanism": "endpoints",
        "hostWide": true,
        "app": app,
        "ips": added,
        "flushed": flushed,
        "verified": true,
        "warning": "endpoints only — affects all apps"
    }))
}

fn teardown() -> Result<Value, String> {
    let _ = Command::new("nft")
        .args(["delete", "table", "inet", TABLE])
        .status();
    // Drain snitch cgroups.
    let slice = cgroup_slice();
    if slice.is_dir() {
        if let Ok(rd) = fs::read_dir(&slice) {
            for e in rd.flatten() {
                let p = e.path();
                if let Ok(text) = fs::read_to_string(p.join("cgroup.procs")) {
                    for tok in text.split_whitespace() {
                        if let Ok(pid) = tok.parse::<u32>() {
                            let _ = fs::write(Path::new(CGROUP_ROOT).join("cgroup.procs"), pid.to_string());
                        }
                    }
                }
                let _ = fs::remove_dir(&p);
            }
        }
        let _ = fs::remove_dir(&slice);
    }
    Ok(json!({"ok": true, "teardown": true}))
}

fn status() -> Result<Value, String> {
    let listed = nft_list_table();
    let has_table = listed.contains("table inet") || listed.contains(&format!("table inet {TABLE}"));
    Ok(json!({
        "ok": true,
        "table": has_table,
        "raw": listed
    }))
}

fn nft(args: &[&str]) -> Result<(), String> {
    // `nft add` of an existing object returns EEXIST (1). Treat that as success
    // so the helper is idempotent.
    let out = Command::new("nft")
        .args(args)
        .output()
        .map_err(|e| format!("nft exec: {e}"))?;
    if out.status.success() {
        return Ok(());
    }
    let err = String::from_utf8_lossy(&out.stderr);
    if err.contains("exist") || err.contains("File exists") {
        return Ok(());
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
