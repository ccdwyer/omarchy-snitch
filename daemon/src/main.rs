use snitchd::event::{
    connection_id, now_ms, AppIdentity, Connection, Endpoint, Event,
};
use snitchd::geo::GeoDb;
use snitchd::identity::{
    read_comm, read_exe, read_status_uid, unknown_identity, AppResolver,
};
use snitchd::procfs::{parse_proc_net, ParsedSocket, Protocol};
use snitchd::seen::{network_key, SeenSet};
use std::collections::{HashMap, HashSet};
use std::io::{Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

const VERSION: &str = env!("CARGO_PKG_VERSION");
const COVERAGE: &str = "tcp+connected-udp";
const UDP_TTL_MS: u64 = 30_000;

struct Args {
    socket: PathBuf,
    interval: Duration,
    replay: Option<PathBuf>,
    replay_loop: bool,
    rdns: bool,
    mmdb: Option<PathBuf>,
    data_dir: PathBuf,
    state_dir: PathBuf,
    self_test: bool,
}

fn default_socket() -> PathBuf {
    if let Ok(dir) = std::env::var("XDG_RUNTIME_DIR") {
        if !dir.is_empty() {
            return PathBuf::from(dir).join("snitch.sock");
        }
    }
    PathBuf::from(format!("/tmp/snitch-{}.sock", uid_guess()))
}

fn uid_guess() -> u32 {
    std::env::var("UID")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(0)
}

fn default_state_dir() -> PathBuf {
    if let Ok(dir) = std::env::var("XDG_STATE_HOME") {
        if !dir.is_empty() {
            return PathBuf::from(dir).join("snitch");
        }
    }
    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".into());
    PathBuf::from(home).join(".local/state/snitch")
}

fn parse_args() -> Args {
    let mut socket = default_socket();
    let mut interval = Duration::from_millis(500);
    let mut replay = None;
    let mut replay_loop = false;
    let mut rdns = false;
    let mut mmdb = None;
    let mut data_dir = PathBuf::from("data");
    let mut state_dir = default_state_dir();
    let mut self_test = false;
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--socket" => socket = PathBuf::from(args.next().unwrap_or_default()),
            "--interval-ms" => {
                let ms: u64 = args.next().and_then(|s| s.parse().ok()).unwrap_or(500);
                interval = Duration::from_millis(ms.max(100));
            }
            "--replay" => replay = args.next().map(PathBuf::from),
            "--replay-loop" => replay_loop = true,
            "--rdns" => rdns = true,
            "--mmdb" => mmdb = args.next().map(PathBuf::from),
            "--data-dir" => data_dir = PathBuf::from(args.next().unwrap_or_default()),
            "--state-dir" => state_dir = PathBuf::from(args.next().unwrap_or_default()),
            "--self-test" => self_test = true,
            "-h" | "--help" => {
                print_help();
                std::process::exit(0);
            }
            "--version" => {
                println!("snitchd {VERSION}");
                std::process::exit(0);
            }
            other => {
                eprintln!("unknown argument: {other}");
                print_help();
                std::process::exit(2);
            }
        }
    }
    Args {
        socket,
        interval,
        replay,
        replay_loop,
        rdns,
        mmdb,
        data_dir,
        state_dir,
        self_test,
    }
}

fn print_help() {
    eprintln!(
        "snitchd {VERSION}\n\
         Unprivileged outbound connection monitor.\n\n\
         --socket PATH       unix socket (default $XDG_RUNTIME_DIR/snitch.sock)\n\
         --interval-ms N     sample interval, default 500\n\
         --replay FILE       play canned NDJSON instead of /proc\n\
         --replay-loop       loop the replay file\n\
         --rdns              opt-in reverse DNS (off by default)\n\
         --mmdb PATH         DB-IP Country Lite .mmdb\n\
         --data-dir PATH     world/geo/flag assets\n\
         --state-dir PATH    seen-set JSON (default ~/.local/state/snitch)\n\
         --self-test         parse built-in fixtures and exit"
    );
}

fn main() {
    let args = parse_args();
    if args.self_test {
        match run_self_test() {
            Ok(()) => {
                println!("self-test ok");
                return;
            }
            Err(e) => {
                eprintln!("self-test failed: {e}");
                std::process::exit(1);
            }
        }
    }
    if args.rdns {
        eprintln!("snitchd: reverse-DNS is on (opt-in). This performs outbound lookups.");
    }
    if let Some(path) = &args.replay {
        if let Err(e) = run_replay(path, &args) {
            eprintln!("snitchd replay failed: {e}");
            std::process::exit(1);
        }
        return;
    }
    if let Err(e) = run_live(&args) {
        eprintln!("snitchd: {e}");
        std::process::exit(1);
    }
}

fn run_self_test() -> Result<(), String> {
    let tcp = include_str!("../../tests/fixtures/proc_net_tcp.txt");
    let rows = parse_proc_net(tcp, Protocol::Tcp, false);
    if rows.is_empty() {
        return Err("fixture produced zero tcp rows".into());
    }
    let udp = include_str!("../../tests/fixtures/proc_net_udp.txt");
    let urows = parse_proc_net(udp, Protocol::Udp, false);
    if !urows.iter().any(|s| s.remote_is_unspecified()) {
        return Err("expected an unresolved UDP row in fixture".into());
    }
    Ok(())
}

struct Server {
    listener: UnixListener,
    clients: Vec<Client>,
}

struct Client {
    stream: UnixStream,
}

impl Server {
    fn bind(path: &Path) -> std::io::Result<Self> {
        if path.exists() {
            let _ = std::fs::remove_file(path);
        }
        if let Some(dir) = path.parent() {
            let _ = std::fs::create_dir_all(dir);
        }
        let listener = UnixListener::bind(path)?;
        listener.set_nonblocking(true)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
        }
        Ok(Self {
            listener,
            clients: Vec::new(),
        })
    }

    fn accept_new(&mut self, snapshot: &[Connection]) {
        loop {
            match self.listener.accept() {
                Ok((stream, _)) => {
                    let _ = stream.set_nonblocking(true);
                    let mut c = Client { stream };
                    let hello = Event::Hello {
                        version: VERSION.into(),
                        pid: std::process::id(),
                        coverage: COVERAGE.into(),
                        rdns: false,
                    };
                    if write_line(&mut c.stream, &hello.to_line()).is_err() {
                        continue;
                    }
                    let snap = Event::Snapshot {
                        ts: now_ms(),
                        connections: snapshot.to_vec(),
                    };
                    if write_line(&mut c.stream, &snap.to_line()).is_ok() {
                        self.clients.push(c);
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(_) => break,
            }
        }
    }

    fn broadcast(&mut self, line: &str) {
        self.clients.retain_mut(|c| write_line(&mut c.stream, line).is_ok());
    }

    fn drain_commands(&mut self) -> Vec<String> {
        let mut cmds = Vec::new();
        for c in &mut self.clients {
            let mut buf = [0u8; 512];
            match c.stream.read(&mut buf) {
                Ok(0) => {}
                Ok(n) => {
                    for line in String::from_utf8_lossy(&buf[..n]).lines() {
                        cmds.push(line.trim().to_string());
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(_) => {}
            }
        }
        cmds
    }
}

fn write_line(stream: &mut UnixStream, line: &str) -> std::io::Result<()> {
    stream.write_all(line.as_bytes())?;
    Ok(())
}

fn run_replay(path: &Path, args: &Args) -> Result<(), String> {
    let mut server = Server::bind(&args.socket).map_err(|e| format!("bind {}: {e}", args.socket.display()))?;
    eprintln!("snitchd: replay {} on {}", path.display(), args.socket.display());
    loop {
        let text = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
        let mut snapshot: Vec<Connection> = Vec::new();
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            server.accept_new(&snapshot);
            let _ = server.drain_commands();
            if let Ok(ev) = serde_json::from_str::<Event>(line) {
                if let Event::Connect { conn, .. } = &ev {
                    snapshot.retain(|c| c.id != conn.id);
                    snapshot.push(conn.clone());
                }
                if let Event::Disconnect { id, .. } = &ev {
                    snapshot.retain(|c| c.id != *id);
                }
                if let Event::Snapshot { connections, .. } = &ev {
                    snapshot = connections.clone();
                }
            }
            let mut out = line.to_string();
            out.push('\n');
            server.broadcast(&out);
            std::thread::sleep(Duration::from_millis(80));
        }
        if !args.replay_loop {
            // Keep the socket up so the UI can reconnect and get the last snapshot.
            loop {
                server.accept_new(&snapshot);
                std::thread::sleep(Duration::from_millis(400));
            }
        }
    }
}

struct Live {
    geo: GeoDb,
    seen: SeenSet,
    apps: AppResolver,
    inode_pid: HashMap<u64, u32>,
    live: HashMap<String, Connection>,
    /// (app_id, remote_ip, remote_port) → last seen ms for connected UDP aggregation
    udp_agg: HashMap<(String, String, u16), u64>,
    last_full_scan: Instant,
    last_scan_cost: Duration,
    away_new: Vec<String>,
    last_flush: Instant,
}

fn run_live(args: &Args) -> Result<(), String> {
    let proc_ok = Path::new("/proc/net/tcp").is_file();
    let mut server = Server::bind(&args.socket).map_err(|e| format!("bind {}: {e}", args.socket.display()))?;
    let mut live = Live {
        geo: GeoDb::load(&args.data_dir, args.mmdb.as_deref()),
        seen: SeenSet::load(&args.state_dir),
        apps: AppResolver::new(),
        inode_pid: HashMap::new(),
        live: HashMap::new(),
        udp_agg: HashMap::new(),
        last_full_scan: Instant::now() - Duration::from_secs(60),
        last_scan_cost: Duration::from_millis(0),
        away_new: Vec::new(),
        last_flush: Instant::now(),
    };
    if !proc_ok {
        eprintln!("snitchd: /proc/net/tcp not found — emitting empty snapshots (use --replay on this host)");
    }
    if !live.geo.has_mmdb() {
        eprintln!("snitchd: no MMDB loaded; country/arcs will be empty until data/geoip/dbip-country-lite.mmdb is present");
    }
    eprintln!(
        "snitchd: listening on {} interval={}ms coverage={COVERAGE} rdns={}",
        args.socket.display(),
        args.interval.as_millis(),
        args.rdns
    );

    loop {
        let t0 = Instant::now();
        server.accept_new(&live.snapshot());
        for cmd in server.drain_commands() {
            handle_cmd(&cmd, &mut live, &mut server);
        }
        if proc_ok {
            sample(&mut live, &mut server, args.rdns);
        } else {
            let tick = Event::Tick {
                ts: now_ms(),
                count: 0,
            };
            server.broadcast(&tick.to_line());
        }
        if live.last_flush.elapsed() > Duration::from_secs(5) {
            live.seen.flush();
            live.last_flush = Instant::now();
        }
        let spent = t0.elapsed();
        if args.interval > spent {
            std::thread::sleep(args.interval - spent);
        }
    }
}

fn handle_cmd(cmd: &str, live: &mut Live, server: &mut Server) {
    let v: serde_json::Value = match serde_json::from_str(cmd) {
        Ok(v) => v,
        Err(_) => return,
    };
    let ty = v.get("type").and_then(|x| x.as_str()).unwrap_or("");
    match ty {
        "panel-open" => {
            let keys = live.away_new.clone();
            let ev = Event::Digest {
                ts: now_ms(),
                new_networks: keys.len(),
                keys,
            };
            server.broadcast(&ev.to_line());
            live.away_new.clear();
        }
        "ping" => {
            let ev = Event::Status {
                message: "ok".into(),
            };
            server.broadcast(&ev.to_line());
        }
        _ => {}
    }
}

impl Live {
    fn snapshot(&self) -> Vec<Connection> {
        self.live.values().cloned().collect()
    }
}

fn sample(live: &mut Live, server: &mut Server, _rdns: bool) {
    let socks = read_all_sockets();
    let want_full = live.last_scan_cost < Duration::from_millis(30)
        || live.last_full_scan.elapsed() > Duration::from_secs(5);
    let scan_t0 = Instant::now();
    if want_full {
        live.inode_pid = scan_inodes(None);
        live.last_full_scan = Instant::now();
    } else {
        let known: HashSet<u64> = live.inode_pid.keys().copied().collect();
        let missing: Vec<u64> = socks
            .iter()
            .map(|s| s.inode)
            .filter(|i| !known.contains(i))
            .collect();
        if !missing.is_empty() {
            let extra = scan_inodes(Some(&missing.into_iter().collect()));
            live.inode_pid.extend(extra);
        }
    }
    live.last_scan_cost = scan_t0.elapsed();

    let now = now_ms();
    let mut present: HashSet<String> = HashSet::new();
    let mut udp_seen_keys: HashSet<(String, String, u16)> = HashSet::new();

    for sock in socks {
        if sock.proto == Protocol::Tcp {
            if sock.is_listen() || !sock.is_active_tcp() {
                continue;
            }
        }
        let remote_ip = sock.canonical_remote();
        let local_ip = sock.canonical_local();
        let unresolved = sock.proto == Protocol::Udp && sock.remote_is_unspecified();
        let ident = resolve_app(live, sock.inode, sock.uid);
        if sock.proto == Protocol::Udp && !unresolved {
            let agg_key = (ident.id.clone(), remote_ip.to_string(), sock.remote_port);
            udp_seen_keys.insert(agg_key.clone());
            if let Some(prev) = live.udp_agg.get(&agg_key) {
                if now.saturating_sub(*prev) < UDP_TTL_MS {
                    live.udp_agg.insert(agg_key, now);
                    // Keep the existing logical flow id present.
                    if let Some(existing) = live.live.values().find(|c| {
                        c.app.id == ident.id
                            && c.remote.ip == remote_ip.to_string()
                            && c.remote.port == sock.remote_port
                            && c.proto == "udp"
                    }) {
                        present.insert(existing.id.clone());
                    }
                    continue;
                }
            }
            live.udp_agg.insert(agg_key, now);
        }

        let id = connection_id(sock.proto.as_str(), sock.inode, &remote_ip.to_string(), sock.remote_port);
        present.insert(id.clone());
        if live.live.contains_key(&id) {
            continue;
        }

        let mut country = String::new();
        let mut lat = 0.0;
        let mut lon = 0.0;
        let mut net_key = String::new();
        let mut new_net = false;
        if !unresolved && !remote_ip.is_loopback() {
            net_key = network_key(remote_ip);
            let is_dns = sock.remote_port == 53;
            let first = live.seen.observe(&net_key, now);
            new_net = first && !is_dns;
            if new_net && !live.away_new.contains(&net_key) {
                live.away_new.push(net_key.clone());
            }
            if let Some(hit) = live.geo.lookup(remote_ip) {
                country = hit.country;
                lat = hit.lat;
                lon = hit.lon;
            }
        }

        let conn = Connection {
            id: id.clone(),
            proto: sock.proto.as_str().into(),
            inode: sock.inode,
            app: ident,
            local: Endpoint {
                ip: local_ip.to_string(),
                port: sock.local_port,
            },
            remote: Endpoint {
                ip: remote_ip.to_string(),
                port: sock.remote_port,
            },
            state: sock.state_name().into(),
            country,
            lat,
            lon,
            unresolved,
            new_network: new_net,
            network_key: net_key,
        };
        live.live.insert(id, conn.clone());
        let ev = Event::Connect { ts: now, conn };
        server.broadcast(&ev.to_line());
    }

    // Drop UDP aggregations that aged out and whose sockets vanished.
    live.udp_agg.retain(|k, last| udp_seen_keys.contains(k) || now.saturating_sub(*last) < UDP_TTL_MS);

    let gone: Vec<String> = live
        .live
        .keys()
        .filter(|k| !present.contains(*k))
        .cloned()
        .collect();
    for id in gone {
        // UDP logical flows linger until TTL.
        if let Some(c) = live.live.get(&id) {
            if c.proto == "udp" && !c.unresolved {
                let key = (c.app.id.clone(), c.remote.ip.clone(), c.remote.port);
                if let Some(last) = live.udp_agg.get(&key) {
                    if now.saturating_sub(*last) < UDP_TTL_MS {
                        continue;
                    }
                }
            }
        }
        live.live.remove(&id);
        let ev = Event::Disconnect { ts: now, id };
        server.broadcast(&ev.to_line());
    }

    let tick = Event::Tick {
        ts: now,
        count: live.live.len(),
    };
    server.broadcast(&tick.to_line());
}

fn resolve_app(live: &mut Live, inode: u64, uid: u32) -> AppIdentity {
    let pid = live.inode_pid.get(&inode).copied().unwrap_or(0);
    if pid == 0 {
        if uid != live.apps.our_uid() && uid != 0 {
            return snitchd::identity::system_identity(0);
        }
        return unknown_identity(0);
    }
    let exe = read_exe(pid);
    let comm = read_comm(pid);
    let real_uid = read_status_uid(pid).unwrap_or(uid);
    live.apps.resolve(pid, real_uid, &exe, &comm)
}

fn read_all_sockets() -> Vec<ParsedSocket> {
    let mut out = Vec::new();
    for (path, proto, v6) in [
        ("/proc/net/tcp", Protocol::Tcp, false),
        ("/proc/net/tcp6", Protocol::Tcp, true),
        ("/proc/net/udp", Protocol::Udp, false),
        ("/proc/net/udp6", Protocol::Udp, true),
    ] {
        if let Ok(text) = std::fs::read_to_string(path) {
            out.extend(parse_proc_net(&text, proto, v6));
        }
    }
    out
}

/// Walk `/proc/<pid>/fd` looking for `socket:[inode]`. When `only` is set,
/// stop a pid early once remaining targets are gone (delta scan).
fn scan_inodes(only: Option<&HashSet<u64>>) -> HashMap<u64, u32> {
    let mut map = HashMap::new();
    let proc = match std::fs::read_dir("/proc") {
        Ok(d) => d,
        Err(_) => return map,
    };
    let mut remaining: Option<HashSet<u64>> = only.cloned();
    for ent in proc.flatten() {
        if remaining.as_ref().is_some_and(|s| s.is_empty()) {
            break;
        }
        let name = ent.file_name();
        let pid: u32 = match name.to_str().and_then(|s| s.parse().ok()) {
            Some(p) => p,
            None => continue,
        };
        let fd_dir = match std::fs::read_dir(format!("/proc/{pid}/fd")) {
            Ok(d) => d,
            Err(_) => continue,
        };
        for fd in fd_dir.flatten() {
            let target = match std::fs::read_link(fd.path()) {
                Ok(t) => t,
                Err(_) => continue,
            };
            let s = target.to_string_lossy();
            if let Some(inode) = parse_socket_link(&s) {
                if let Some(rem) = remaining.as_mut() {
                    if rem.remove(&inode) {
                        map.insert(inode, pid);
                    }
                } else {
                    map.insert(inode, pid);
                }
            }
        }
    }
    map
}

fn parse_socket_link(s: &str) -> Option<u64> {
    let rest = s.strip_prefix("socket:[")?.strip_suffix(']')?;
    rest.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn socket_link_parse() {
        assert_eq!(parse_socket_link("socket:[54321]"), Some(54321));
        assert_eq!(parse_socket_link("/dev/pts/0"), None);
    }
}
