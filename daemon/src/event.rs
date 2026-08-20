use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Endpoint {
    pub ip: String,
    pub port: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AppIdentity {
    pub id: String,
    pub name: String,
    pub icon: String,
    pub desktop: String,
    pub pid: u32,
    /// True when the process is another uid and we only know it as "system".
    #[serde(default)]
    pub system: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Connection {
    pub id: String,
    pub proto: String,
    pub inode: u64,
    pub app: AppIdentity,
    pub local: Endpoint,
    pub remote: Endpoint,
    pub state: String,
    /// ISO 3166-1 alpha-2, empty when unknown or unresolved UDP.
    #[serde(default)]
    pub country: String,
    #[serde(default)]
    pub lat: f64,
    #[serde(default)]
    pub lon: f64,
    /// UDP with a null remote — listed, never drawn as an arc.
    #[serde(default)]
    pub unresolved: bool,
    #[serde(default, rename = "newNetwork")]
    pub new_network: bool,
    #[serde(default, rename = "networkKey")]
    pub network_key: String,
    /// PTR name; only filled when reverse-DNS is opted in.
    #[serde(default)]
    pub hostname: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum Event {
    #[serde(rename = "hello")]
    Hello {
        version: String,
        pid: u32,
        coverage: String,
        rdns: bool,
    },
    #[serde(rename = "snapshot")]
    Snapshot {
        ts: u64,
        connections: Vec<Connection>,
    },
    #[serde(rename = "connect")]
    Connect { ts: u64, #[serde(flatten)] conn: Connection },
    #[serde(rename = "disconnect")]
    Disconnect { ts: u64, id: String },
    #[serde(rename = "tick")]
    Tick { ts: u64, count: usize },
    #[serde(rename = "digest")]
    Digest {
        ts: u64,
        #[serde(rename = "newNetworks")]
        new_networks: usize,
        keys: Vec<String>,
    },
    #[serde(rename = "status")]
    Status { message: String },
}

impl Event {
    pub fn to_line(&self) -> String {
        let mut line = serde_json::to_string(self).unwrap_or_else(|_| "{\"type\":\"status\",\"message\":\"encode-error\"}".into());
        line.push('\n');
        line
    }
}

pub fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

pub fn connection_id(proto: &str, inode: u64, remote_ip: &str, remote_port: u16) -> String {
    format!("{proto}:{inode}:{remote_ip}:{remote_port}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replay_fixture_parses() {
        let text = include_str!("../../tests/fixtures/replay.ndjson");
        let mut n = 0;
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let ev: Event = serde_json::from_str(line).unwrap_or_else(|e| panic!("bad replay line {line}: {e}"));
            n += 1;
            let _ = ev;
        }
        assert!(n >= 10);
    }

    #[test]
    fn hello_roundtrip_line() {
        let ev = Event::Hello {
            version: "1.0.0".into(),
            pid: 7,
            coverage: "tcp+connected-udp".into(),
            rdns: false,
        };
        let line = ev.to_line();
        assert!(line.ends_with('\n'));
        let parsed: Event = serde_json::from_str(line.trim()).unwrap();
        match parsed {
            Event::Hello { version, rdns, .. } => {
                assert_eq!(version, "1.0.0");
                assert!(!rdns);
            }
            _ => panic!("wrong variant"),
        }
    }
}
