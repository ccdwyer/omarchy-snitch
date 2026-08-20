//! Parsers for `/proc/net/{tcp,tcp6,udp,udp6}`.
//!
//! Address encoding matches the Linux kernel's seq_file output: IPv4 is the
//! little-endian hex of `s_addr`; IPv6 is four little-endian 32-bit words.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    Tcp,
    Udp,
}

impl Protocol {
    pub fn as_str(self) -> &'static str {
        match self {
            Protocol::Tcp => "tcp",
            Protocol::Udp => "udp",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedSocket {
    pub proto: Protocol,
    pub local: IpAddr,
    pub local_port: u16,
    pub remote: IpAddr,
    pub remote_port: u16,
    pub state: u8,
    pub uid: u32,
    pub inode: u64,
}

impl ParsedSocket {
    pub fn state_name(&self) -> &'static str {
        tcp_state_name(self.state)
    }

    pub fn remote_is_unspecified(&self) -> bool {
        match self.remote {
            IpAddr::V4(v) => v.is_unspecified(),
            IpAddr::V6(v) => v.is_unspecified(),
        }
    }

    /// TCP sockets we treat as live conversations (not listen / time-wait / close).
    pub fn is_active_tcp(&self) -> bool {
        self.proto == Protocol::Tcp && matches!(self.state, 0x01 | 0x02 | 0x03 | 0x04 | 0x05 | 0x08 | 0x09 | 0x0B)
    }

    pub fn is_listen(&self) -> bool {
        self.proto == Protocol::Tcp && self.state == 0x0A
    }

    /// Mapped IPv6 (::ffff:a.b.c.d) is rewritten to the inner v4 address.
    pub fn canonical_remote(&self) -> IpAddr {
        match self.remote {
            IpAddr::V6(v) => v.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(IpAddr::V6(v)),
            other => other,
        }
    }

    pub fn canonical_local(&self) -> IpAddr {
        match self.local {
            IpAddr::V6(v) => v.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(IpAddr::V6(v)),
            other => other,
        }
    }
}

pub fn tcp_state_name(state: u8) -> &'static str {
    match state {
        0x01 => "ESTABLISHED",
        0x02 => "SYN_SENT",
        0x03 => "SYN_RECV",
        0x04 => "FIN_WAIT1",
        0x05 => "FIN_WAIT2",
        0x06 => "TIME_WAIT",
        0x07 => "CLOSE",
        0x08 => "CLOSE_WAIT",
        0x09 => "LAST_ACK",
        0x0A => "LISTEN",
        0x0B => "CLOSING",
        _ => "UNKNOWN",
    }
}

pub fn parse_proc_net(text: &str, proto: Protocol, ipv6: bool) -> Vec<ParsedSocket> {
    let mut out = Vec::new();
    for (i, line) in text.lines().enumerate() {
        if i == 0 {
            continue;
        }
        if let Some(sock) = parse_proc_net_line(line, proto, ipv6) {
            out.push(sock);
        }
    }
    out
}

pub fn parse_proc_net_line(line: &str, proto: Protocol, ipv6: bool) -> Option<ParsedSocket> {
    let line = line.trim();
    if line.is_empty() {
        return None;
    }
    let cols: Vec<&str> = line.split_whitespace().collect();
    // sl, local, rem, st, tx:rx, tr:when, retrnsmt, uid, timeout, inode
    if cols.len() < 10 {
        return None;
    }
    // After split_whitespace, "0:" is cols[0], local is cols[1], rem cols[2], st cols[3], uid cols[7], inode cols[9]
    let (local_col, rem_col, st_col, uid_col, inode_col) = if cols[0].contains(':') && cols[0].len() < 8 {
        // "0:" already split as its own token
        (cols[1], cols[2], cols[3], cols[7], cols[9])
    } else {
        (cols[1], cols[2], cols[3], cols[7], cols[9])
    };

    let (local, local_port) = parse_addr_port(local_col, ipv6)?;
    let (remote, remote_port) = parse_addr_port(rem_col, ipv6)?;
    let state = u8::from_str_radix(st_col, 16).ok()?;
    let uid: u32 = uid_col.parse().ok()?;
    let inode: u64 = inode_col.parse().ok()?;
    Some(ParsedSocket {
        proto,
        local,
        local_port,
        remote,
        remote_port,
        state,
        uid,
        inode,
    })
}

pub fn parse_addr_port(col: &str, ipv6: bool) -> Option<(IpAddr, u16)> {
    let (addr_hex, port_hex) = col.rsplit_once(':')?;
    let port = u16::from_str_radix(port_hex, 16).ok()?;
    let addr = if ipv6 {
        IpAddr::V6(parse_ipv6_hex(addr_hex)?)
    } else {
        IpAddr::V4(parse_ipv4_hex(addr_hex)?)
    };
    Some((addr, port))
}

pub fn parse_ipv4_hex(hex: &str) -> Option<Ipv4Addr> {
    if hex.len() != 8 {
        return None;
    }
    let n = u32::from_str_radix(hex, 16).ok()?;
    // Kernel prints __le32 as %08X, so on little-endian hosts the low byte is
    // the first octet. That matches every Linux we care about.
    Some(Ipv4Addr::new(
        (n & 0xff) as u8,
        ((n >> 8) & 0xff) as u8,
        ((n >> 16) & 0xff) as u8,
        ((n >> 24) & 0xff) as u8,
    ))
}

pub fn parse_ipv6_hex(hex: &str) -> Option<Ipv6Addr> {
    if hex.len() != 32 {
        return None;
    }
    let mut bytes = [0u8; 16];
    for word in 0..4 {
        let slice = &hex[word * 8..word * 8 + 8];
        let n = u32::from_str_radix(slice, 16).ok()?;
        let be = n.to_le_bytes(); // undo the kernel's little-endian word dump
        bytes[word * 4..word * 4 + 4].copy_from_slice(&be);
    }
    Some(Ipv6Addr::from(bytes))
}

pub fn encode_ipv4_hex(ip: Ipv4Addr) -> String {
    let o = ip.octets();
    let n = u32::from_le_bytes(o);
    format!("{n:08X}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn ipv4_loopback() {
        // 127.0.0.1 → 0100007F
        let ip = parse_ipv4_hex("0100007F").unwrap();
        assert_eq!(ip, Ipv4Addr::new(127, 0, 0, 1));
        assert_eq!(encode_ipv4_hex(ip), "0100007F");
    }

    #[test]
    fn ipv4_googleish() {
        // 142.250.190.14 → octets 8E FA BE 0E → LE dump 0EBEFA8E
        let ip = parse_ipv4_hex("0EBEFA8E").unwrap();
        assert_eq!(ip, Ipv4Addr::new(142, 250, 190, 14));
    }

    #[test]
    fn ipv4_unspecified() {
        assert_eq!(parse_ipv4_hex("00000000").unwrap(), Ipv4Addr::UNSPECIFIED);
    }

    #[test]
    fn ipv6_loopback() {
        let ip = parse_ipv6_hex("00000000000000000000000001000000").unwrap();
        assert_eq!(ip, Ipv6Addr::LOCALHOST);
    }

    #[test]
    fn ipv6_mapped_v4() {
        // ::ffff:127.0.0.1  words: 0, 0, ffff0000, 0100007f in kernel dump
        let ip = parse_ipv6_hex("0000000000000000FFFF00000100007F").unwrap();
        assert_eq!(ip.to_ipv4_mapped(), Some(Ipv4Addr::new(127, 0, 0, 1)));
    }

    #[test]
    fn parse_established_tcp() {
        let line = "   1: 0A01010A:C21C 0EBEFA8E:01BB 01 00000000:00000000 00:00000000 00000000  1000        0 54321 1 0000000000000000 20 0 0 10 -1";
        let sock = parse_proc_net_line(line, Protocol::Tcp, false).unwrap();
        assert_eq!(sock.local, IpAddr::V4(Ipv4Addr::new(10, 1, 1, 10)));
        assert_eq!(sock.local_port, 0xC21C);
        assert_eq!(sock.remote, IpAddr::V4(Ipv4Addr::new(142, 250, 190, 14)));
        assert_eq!(sock.remote_port, 443);
        assert_eq!(sock.state, 1);
        assert_eq!(sock.uid, 1000);
        assert_eq!(sock.inode, 54321);
        assert!(sock.is_active_tcp());
    }

    #[test]
    fn parse_listen_excluded_from_active() {
        let line = "   0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12345 1 0000000000000000 100 0 0 10 0";
        let sock = parse_proc_net_line(line, Protocol::Tcp, false).unwrap();
        assert!(sock.is_listen());
        assert!(!sock.is_active_tcp());
        assert!(sock.remote_is_unspecified());
    }

    #[test]
    fn parse_time_wait() {
        let line = "   2: 0A01010A:C21D 0EBEFA8E:01BB 06 00000000:00000000 00:00000000 00000000  1000        0 999 1 0000000000000000 20 0 0 10 -1";
        let sock = parse_proc_net_line(line, Protocol::Tcp, false).unwrap();
        assert_eq!(sock.state_name(), "TIME_WAIT");
        assert!(!sock.is_active_tcp());
    }

    #[test]
    fn parse_udp_null_remote() {
        let line = "   0: 00000000:0035 00000000:0000 07 00000000:00000000 00:00000000 00000000  1000        0 777 2 0000000000000000 0";
        let sock = parse_proc_net_line(line, Protocol::Udp, false).unwrap();
        assert_eq!(sock.proto, Protocol::Udp);
        assert_eq!(sock.local_port, 53);
        assert!(sock.remote_is_unspecified());
        assert_eq!(sock.state_name(), "CLOSE");
    }

    #[test]
    fn parse_connected_udp() {
        let line = "   1: 0A01010A:C350 08080808:0035 01 00000000:00000000 00:00000000 00000000  1000        0 888 2 0000000000000000 0";
        let sock = parse_proc_net_line(line, Protocol::Udp, false).unwrap();
        assert_eq!(sock.remote, IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)));
        assert_eq!(sock.remote_port, 53);
        assert!(!sock.remote_is_unspecified());
    }

    #[test]
    fn parse_table_skips_header() {
        let text = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n   0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1 1 0000000000000000 100 0 0 10 0\n";
        let rows = parse_proc_net(text, Protocol::Tcp, false);
        assert_eq!(rows.len(), 1);
    }

    #[test]
    fn ipv6_tcp_line() {
        let line = "   0: 00000000000000000000000001000000:1F90 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 42 1 0000000000000000 100 0 0 10 0";
        let sock = parse_proc_net_line(line, Protocol::Tcp, true).unwrap();
        assert_eq!(sock.local, IpAddr::V6(Ipv6Addr::LOCALHOST));
        assert_eq!(sock.local_port, 8080);
        assert!(sock.remote_is_unspecified());
    }
}
