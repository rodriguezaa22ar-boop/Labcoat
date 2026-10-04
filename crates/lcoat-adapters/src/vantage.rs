//! Where a tool run happened: the hostname and the source address the
//! machine would use to reach the target. Recorded on `adapter.started` and
//! on the evidence record (format 1.1), so a scan of a host from itself and
//! a scan from another machine are distinguishable in the trail.

use std::net::{IpAddr, SocketAddr, ToSocketAddrs, UdpSocket};

/// The local hostname, from `/etc/hostname` or `/proc/sys/kernel/hostname`
/// (Linux) or the `HOSTNAME` variable; `unknown` when none is readable.
pub fn hostname() -> String {
    for path in ["/proc/sys/kernel/hostname", "/etc/hostname"] {
        if let Ok(text) = std::fs::read_to_string(path) {
            let name = text.trim();
            if !name.is_empty() {
                return sanitize(name);
            }
        }
    }
    if let Ok(name) = std::env::var("HOSTNAME")
        && !name.trim().is_empty()
    {
        return sanitize(name.trim());
    }
    // macOS: `hostname` is the one portable way without libc bindings.
    if let Ok(out) = std::process::Command::new("/bin/hostname").output()
        && out.status.success()
    {
        let name = String::from_utf8_lossy(&out.stdout).trim().to_owned();
        if !name.is_empty() {
            return sanitize(&name);
        }
    }
    "unknown".to_owned()
}

/// Keep the token ledger-safe: no whitespace, no `=`, bounded length.
fn sanitize(s: &str) -> String {
    s.chars()
        .filter(|c| !c.is_whitespace() && *c != '=')
        .take(253)
        .collect()
}

/// The source address the kernel would route to `target` from, found by
/// connecting an unbound UDP socket (no packet is sent). `unknown` when the
/// target does not resolve or has no route.
pub fn source_address(target: &str) -> String {
    let dest: Option<SocketAddr> = match target.parse::<IpAddr>() {
        Ok(ip) => Some(SocketAddr::new(ip, 9)),
        Err(_) => (target, 9)
            .to_socket_addrs()
            .ok()
            .and_then(|mut it| it.next()),
    };
    let Some(dest) = dest else {
        return "unknown".to_owned();
    };
    let bind = if dest.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    };
    let Ok(sock) = UdpSocket::bind(bind) else {
        return "unknown".to_owned();
    };
    if sock.connect(dest).is_err() {
        return "unknown".to_owned();
    }
    sock.local_addr()
        .map(|a| a.ip().to_string())
        .unwrap_or_else(|_| "unknown".to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn values_are_ledger_safe() {
        let h = hostname();
        assert!(!h.is_empty() && !h.contains(' ') && !h.contains('='));
        let a = source_address("127.0.0.1");
        assert!(a == "127.0.0.1" || a == "unknown", "{a}");
        assert_eq!(source_address("not a host name!"), "unknown");
        assert_eq!(sanitize("a b=c"), "abc");
    }
}
