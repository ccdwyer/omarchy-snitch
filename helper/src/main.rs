//! Privileged helper for Snitch. Installed root-owned at
//! `/usr/lib/snitch/snitch-block` and invoked with `pkexec`.
//!
//! Verbs: block-app, unblock-app, block-ips, unblock-ips, teardown, status.

use serde_json::{json, Value};
use snitch_block::ids::sanitize_app;
use snitch_block::owners::{self, OwnerMap};
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
    let pids: Vec<u32> = pids
        .iter()
        .map(|s| parse_pid(s))
        .collect::<Result<Vec<u32>, String>>()?
        .into_iter()
        .filter(|p| *p >= 2)
        .collect();
    if !Path::new(CGROUP_ROOT).join("cgroup.controllers").is_file() {
        return Err("cgroup v2 not mounted at /sys/fs/cgroup".into());
    }
    ensure_table_and_output_chain()?;
    let slice = cgroup_slice();
    fs::create_dir_all(&slice).map_err(|e| format!("mkdir slice: {e}"))?;
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
    add_cgroup_drop_rule(&path)?;
    if !verify_cgroup_rule(&path) {
        return Err("nft rule did not land (nft list check failed)".into());
    }

    let remotes = collect_remotes(&moved);
    let flush = flush_conntrack(&remotes)?;
    let nft_ok = verify_cgroup_rule(&path);
    if !nft_ok {
        return Err("nft rule did not land (nft list check failed)".into());
    }

    Ok(json!({
        "ok": true,
        "mechanism": "cgroup",
        "path": path,
        "moved": moved,
        "flushed": flush.flushed,
        "flushFailed": flush.failed,
        "verified": flush.ok,
        "warning": if flush.ok { Value::Null } else { json!(flush.summary()) },
        "helper": CANONICAL_HELPER
    }))
}

fn migrate_tree(pid: u32, dest: &Path, seen: &mut std::collections::HashSet<u32>, moved: &mut Vec<u32>) {
    if pid < 2 || !seen.insert(pid) {
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
    let path = std::env::var("PATH").unwrap_or_default();
    for dir in path.split(':') {
        let p = Path::new(dir).join(name);
        if p.is_file() {
            return Some(p);
        }
    }
    None
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
    let text = nft_list_table();
    text.contains(path) && text.contains("socket cgroupv2")
}

fn unblock_app(app_raw: &str) -> Result<Value, String> {
    let app = sanitize_app(app_raw)?;
    let path = cgroup_match_path(&app);
    delete_rules_containing(&path)?;
    if verify_cgroup_rule(&path) {
        return Err("cgroup drop rule still present after delete".into());
    }
    let dest = cgroup_app(&app);
    if let Ok(text) = fs::read_to_string(dest.join("cgroup.procs")) {
        for tok in text.split_whitespace() {
            if let Ok(pid) = tok.parse::<u32>() {
                let _ = fs::write(Path::new(CGROUP_ROOT).join("cgroup.procs"), pid.to_string());
            }
        }
    }
    if dest.exists() {
        fs::remove_dir(&dest).map_err(|e| format!("rmdir {}: {e}", dest.display()))?;
    }
    Ok(json!({
        "ok": true,
        "mechanism": "cgroup",
        "path": path,
        "verified": true
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
                    nft(&["delete", "rule", "inet", TABLE, "out", "handle", handle])?;
                }
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
    let mut added = Vec::new();
    for ip in &parsed {
        add_element(ip)?;
        if !verify_element_present(ip) {
            return Err(format!("{ip} not present in nft set after add"));
        }
        added.push(ip.to_string());
    }
    let mut map = owners::load(&owners_path());
    owners::grant(&mut map, &app, &added);
    owners::save(&owners_path(), &map)?;

    let flush = flush_conntrack(&parsed)?;
    Ok(json!({
        "ok": true,
        "mechanism": "endpoints",
        "hostWide": true,
        "app": app,
        "ips": added,
        "flushed": flush.flushed,
        "flushFailed": flush.failed,
        "verified": flush.ok,
        "warning": if flush.ok {
            json!("endpoints only — affects all apps")
        } else {
            json!(format!("endpoints only — affects all apps; conntrack: {}", flush.summary()))
        }
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
    Ok(json!({
        "ok": true,
        "table": has_table,
        "owners": map,
        "raw": listed,
        "helper": CANONICAL_HELPER
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
