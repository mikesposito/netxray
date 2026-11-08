//! Attributes connections to processes by polling `lsof` (built into macOS)
//! every 2 seconds and matching the flow's source endpoint to a socket owner.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::process::Command;
use std::sync::Arc;
use std::time::Duration;

use crate::flow::Shared;

type SockKey = (String, u16); // local ip, local port

fn parse_lsof(out: &[u8]) -> HashMap<SockKey, (u32, String)> {
    let mut map = HashMap::new();
    let mut pid: Option<u32> = None;
    let mut comm = String::new();
    for line in out.split(|&b| b == b'\n') {
        if line.is_empty() {
            continue;
        }
        let (field, value) = line.split_first().unwrap();
        match field {
            b'p' => {
                pid = std::str::from_utf8(value).ok().and_then(|s| s.parse().ok());
                comm.clear();
            }
            b'c' => comm = String::from_utf8_lossy(value).into_owned(),
            b'n' => {
                let name = String::from_utf8_lossy(value);
                // "192.168.1.5:52814->93.184.216.34:443 (ESTABLISHED)"
                let Some((local, _)) = name.split_once("->") else { continue };
                let Some((ip, port)) = local.rsplit_once(':') else { continue };
                let Ok(port) = port.parse::<u16>() else { continue };
                let ip = ip.trim_start_matches('[').trim_end_matches(']').to_string();
                if let Some(pid) = pid {
                    map.insert((ip, port), (pid, comm.clone()));
                }
            }
            _ => {}
        }
    }
    map
}

fn key_of(addr: &SocketAddr) -> SockKey {
    (addr.ip().to_string(), addr.port())
}

pub fn spawn(shared: Arc<Shared>) {
    std::thread::spawn(move || loop {
        std::thread::sleep(Duration::from_secs(2));
        let Ok(out) = Command::new("/usr/sbin/lsof")
            .args(["-nP", "-iTCP", "-F", "pcn"])
            .output()
        else {
            continue;
        };
        let map = parse_lsof(&out.stdout);
        let flows = shared.flows.lock().unwrap();
        for f in flows.iter() {
            if f.inner.lock().unwrap().pid.is_some() {
                continue;
            }
            if let Some((pid, comm)) = map.get(&key_of(&f.src)) {
                f.set_pid(*pid, comm.clone());
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_lsof_fields() {
        let src = b"p111\nccurl\nf4\nn192.168.0.2:5000->1.2.3.4:443 (ESTABLISHED)\n\
                    p222\nclsof\nf3\nn[fe80::1]:999->[fe80::2]:443 (ESTABLISHED)\n\
                    p333\nclaunchd\nf2\nn*:53692\n";
        let map = parse_lsof(src);
        assert_eq!(map.get(&("192.168.0.2".to_string(), 5000)), Some(&(111, "curl".to_string())));
        assert_eq!(map.get(&("fe80::1".to_string(), 999)), Some(&(222, "lsof".to_string())));
        assert!(!map.contains_key(&("*".to_string(), 53692)));
    }
}
