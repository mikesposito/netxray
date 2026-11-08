//! pf (macOS packet filter) integration: loads a transparent-proxy ruleset,
//! recovers the original destination of redirected connections via
//! DIOCNATLOOK, and restores the system ruleset on exit.
//!
//! Struct layout and ioctl number follow sshuttle's proven Darwin
//! implementation (pf_state_xport is a 4-byte union on macOS, so
//! pfioc_natlook is 84 bytes and DIOCNATLOOK is 0xc0544417).

use std::fs;
use std::io::{self, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};

const DIOCNATLOOK: libc::c_ulong = 0xc054_4417;
const PF_OUT: u8 = 2; // PF_INOUT=0, PF_IN=1, PF_OUT=2 (OpenBSD/Darwin pf)

#[repr(C, align(4))]
#[derive(Clone, Copy)]
struct NatLook {
  saddr: [u8; 16],
  daddr: [u8; 16],
  rsaddr: [u8; 16],
  rdaddr: [u8; 16],
  sxport: u32,
  dxport: u32,
  rsxport: u32,
  rdxport: u32,
  af: u8,
  proto: u8,
  proto_variant: u8,
  direction: u8,
}

const _: () = assert!(std::mem::size_of::<NatLook>() == 84);

pub struct Pf {
  fd: i32,
  enabled_by_us: bool,
  restored: AtomicBool,
}

fn pfctl(args: &[&str], stdin: Option<&str>) -> io::Result<String> {
  let mut cmd = Command::new("/sbin/pfctl");
  cmd.args(args).stdout(Stdio::piped()).stderr(Stdio::piped());
  if stdin.is_some() {
    cmd.stdin(Stdio::piped());
  }
  let mut child = cmd.spawn()?;
  if let Some(text) = stdin {
    child.stdin.take().unwrap().write_all(text.as_bytes())?;
  }
  let out = child.wait_with_output()?;
  if !out.status.success() {
    return Err(io::Error::other(format!(
      "pfctl {}: {}",
      args.join(" "),
      String::from_utf8_lossy(&out.stderr).trim()
    )));
  }
  Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// pf requires rule order: options, normalization, translation, filtering.
/// Our rdr (translation) is inserted before the first filtering rule; our
/// pass/block (filtering) rules are appended at the end.
fn rules(orig: &str, listen_port: u16) -> String {
  let rdr = format!(
        "# netxray: redirect all outbound non-loopback TCP to the proxy\n\
         rdr pass on lo0 inet proto tcp from ! 127.0.0.0/8 to ! 127.0.0.0/8 -> 127.0.0.1 port {listen_port}"
    );
  let filters = "\n\
        # --- netxray filters ---\n\
        # the proxy's own relays bind 20000:20999 and bypass the redirect (breaks the loop)\n\
        pass out quick inet proto tcp from any port 20000:20999 to any\n\
        pass out quick route-to lo0 inet proto tcp from ! 127.0.0.0/8 to ! 127.0.0.0/8\n\
        # QUIC (UDP 443) is blocked so browsers fall back to TCP, which we intercept\n\
        block return-icmp out quick inet proto udp to any port 443\n\
        # shortcut: IPv6 interception is not implemented; reset v6 TCP (clients fall back to v4) and block v6 QUIC\n\
        block return-rst out quick inet6 proto tcp to ! ::1\n\
        block return-icmp6 out quick inet6 proto udp to any port 443\n";

  let mut out = String::new();
  let mut inserted = false;
  for line in orig.lines() {
    let t = line.trim_start();
    let is_filter = t.starts_with("pass ") || t.starts_with("block ") || t.starts_with("anchor ");
    if !inserted && is_filter {
      out.push_str(&rdr);
      out.push('\n');
      inserted = true;
    }
    out.push_str(line);
    out.push('\n');
  }
  if !inserted {
    out.push_str(&rdr);
    out.push('\n');
  }
  out.push_str(filters);
  out
}

impl Pf {
  pub fn setup(listen_port: u16) -> io::Result<Pf> {
    if unsafe { libc::geteuid() } != 0 {
      return Err(io::Error::other(
        "must run as root: try `sudo ./netxray`",
      ));
    }
    let orig = fs::read_to_string("/etc/pf.conf")
      .map_err(|e| io::Error::other(format!("reading /etc/pf.conf: {e}")))?;
    // 'set skip on lo' would neutralize our lo0 redirection; strip it while we run.
    let kept: String = orig
      .lines()
      .filter(|l| !l.trim_start().starts_with("set skip on lo"))
      .collect::<Vec<_>>()
      .join("\n");
    pfctl(&["-f", "-"], Some(&rules(&kept, listen_port)))?;

    let info = pfctl(&["-s", "info"], None)?;
    let enabled_by_us = info.contains("Status: Disabled");
    if enabled_by_us {
      pfctl(&["-E"], None)?;
    }

    let fd = unsafe { libc::open(c"/dev/pf".as_ptr().cast(), libc::O_RDWR) };
    if fd < 0 {
      return Err(io::Error::last_os_error());
    }
    Ok(Pf {
      fd,
      enabled_by_us,
      restored: AtomicBool::new(false),
    })
  }

  /// Look up the original destination for a redirected connection, given
  /// the peer address of the accepted socket and the proxy listen port.
  pub fn nat_lookup(&self, src: SocketAddr, listen_port: u16) -> Option<SocketAddr> {
    let IpAddr::V4(ip) = src.ip() else {
      return None;
    };
    for direction in [PF_OUT, 1] {
      let mut nl: NatLook = unsafe { std::mem::zeroed() };
      nl.saddr[..4].copy_from_slice(&ip.octets());
      nl.daddr[..4].copy_from_slice(&[127, 0, 0, 1]);
      nl.sxport = src.port().to_be() as u32;
      nl.dxport = listen_port.to_be() as u32;
      nl.af = libc::AF_INET as u8;
      nl.proto = libc::IPPROTO_TCP as u8;
      nl.proto_variant = 0;
      nl.direction = direction;
      let r = unsafe {
        libc::ioctl(
          self.fd,
          DIOCNATLOOK,
          &mut nl as *mut NatLook as *mut libc::c_void,
        )
      };
      if r == 0 {
        let dst = Ipv4Addr::new(nl.rdaddr[0], nl.rdaddr[1], nl.rdaddr[2], nl.rdaddr[3]);
        let port = u16::from_be(nl.rdxport as u16);
        if port != 0 {
          return Some(SocketAddr::new(IpAddr::V4(dst), port));
        }
      }
    }
    None
  }

  /// Reload the original /etc/pf.conf and disable pf if we enabled it.
  pub fn restore(&self) {
    if self.restored.swap(true, Ordering::SeqCst) {
      return;
    }
    if let Err(e) = pfctl(&["-f", "/etc/pf.conf"], None) {
      eprintln!("warning: failed to restore /etc/pf.conf: {e}");
      eprintln!("restore manually with: sudo pfctl -f /etc/pf.conf");
    }
    if self.enabled_by_us {
      let _ = pfctl(&["-d"], None);
    }
  }
}

impl Drop for Pf {
  fn drop(&mut self) {
    self.restore();
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn natlook_layout() {
    assert_eq!(std::mem::size_of::<NatLook>(), 84);
    assert_eq!(
      DIOCNATLOOK as u64,
      0xc0_00_00_00u64 | (84 << 16) | ((b'D' as u64) << 8) | 23
    );
  }

  // The stock macOS pf.conf: anchors first (translation points), then a
  // filtering anchor. Our rdr must slot in between.
  const STOCK_PF_CONF: &str = "#\nscrub-anchor \"com.apple/*\"\nnat-anchor \"com.apple/*\"\nrdr-anchor \"com.apple/*\"\ndummynet-anchor \"com.apple/*\"\nanchor \"com.apple/*\"\nload anchor \"com.apple\" from \"/etc/pf.anchors/com.apple\"\n";

  #[test]
  fn generated_ruleset_parses_with_pfctl() {
    let combined = rules(STOCK_PF_CONF, 9191);
    let rdr_pos = combined.find("rdr pass on lo0").unwrap();
    let anchor_pos = combined.find("\nanchor \"").unwrap();
    assert!(rdr_pos < anchor_pos, "rdr must precede filtering rules");

    // pfctl -nf parses without loading; works without root on macOS.
    let out = std::process::Command::new("/sbin/pfctl")
      .args(["-nf", "/dev/stdin"])
      .stdin(Stdio::piped())
      .stdout(Stdio::null())
      .stderr(Stdio::piped())
      .spawn()
      .and_then(|mut c| {
        use std::io::Write;
        c.stdin.take().unwrap().write_all(combined.as_bytes())?;
        c.wait_with_output()
      });
    match out {
      Ok(o) => assert!(
        o.status.success(),
        "pfctl rejected ruleset: {}",
        String::from_utf8_lossy(&o.stderr)
      ),
      Err(_) => {} // pfctl not present (non-macOS CI): placement assert above still ran
    }
  }
}
