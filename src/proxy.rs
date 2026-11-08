use std::io::{self, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::os::fd::{AsRawFd, FromRawFd};
use std::sync::atomic::{AtomicU16, AtomicU64, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use crate::flow::{Dir, Flow, Shared};
use crate::pf::Pf;
use crate::proto;

pub const LISTEN_PORT: u16 = 9191;

const RELAY_PORT_BASE: u16 = 20000;
const RELAY_PORT_COUNT: u16 = 1000;
// shortcut: relay ports stay below the ephemeral range (49152+), so no
// regular application socket can ever land in the pf bypass rule
static NEXT_RELAY: AtomicU16 = AtomicU16::new(0);

pub fn spawn(shared: Arc<Shared>, listener: TcpListener, pf: Arc<Pf>) {
    thread::spawn(move || {
        for conn in listener.incoming() {
            match conn {
                Ok(c) => {
                    let (s2, p2) = (shared.clone(), pf.clone());
                    thread::spawn(move || handle(s2, p2, c));
                }
                Err(_) => return,
            }
        }
    });
}

fn handle(shared: Arc<Shared>, pf: Arc<Pf>, mut client: TcpStream) {
    let Ok(src) = client.peer_addr() else { return };
    let dst = pf.nat_lookup(src, LISTEN_PORT);
    let flow = shared.push_flow(src, dst);
    let Some(dst) = dst else {
        flow.set_status("err: pf nat lookup failed");
        return;
    };

    let (buf, host) = match sniff(&mut client) {
        Ok(v) => v,
        Err(e) => {
            flow.set_status(format!("err: {e}"));
            return;
        }
    };
    flow.set_host(host.as_deref());
    if proto::classify(&buf) == proto::Kind::Http {
        flow.set_http(proto::http_method(&buf), &buf);
    }

    if let Some(pattern) = shared.blocklist.matches(host.as_deref(), Some(dst)) {
        flow.set_status(format!("blocked: {pattern}"));
        rst_close(&mut client);
        return;
    }

    let mut srv = match relay_connect(dst) {
        Ok(s) => s,
        Err(e) => {
            flow.set_status(format!("err: {e}"));
            rst_close(&mut client);
            return;
        }
    };

    // Relay: log everything through, counting bytes both ways.
    let _ = client.set_read_timeout(None);
    if let Err(e) = srv.write_all(&buf) {
        flow.set_status(format!("err: {e}"));
        return;
    }
    flow.up.fetch_add(buf.len() as u64, Ordering::Relaxed);

    let mut c_read = match client.try_clone() {
        Ok(s) => s,
        Err(e) => {
            flow.set_status(format!("err: {e}"));
            return;
        }
    };
    let mut s_read = match srv.try_clone() {
        Ok(s) => s,
        Err(e) => {
            flow.set_status(format!("err: {e}"));
            return;
        }
    };

    let up_res = thread::scope(|sc| {
        let down = sc.spawn(|| pump(&mut s_read, &mut client, &flow.down, &flow, Dir::Resp));
        let up = pump(&mut c_read, &mut srv, &flow.up, &flow, Dir::Req);
        let down = down.join().map_err(|_| io::Error::other("pump panicked")).and_then(|r| r);
        (up, down)
    });

    let code = flow.inner.lock().unwrap().http_status;
    let status = match up_res {
        (Ok(_), Ok(_)) => code.map(|c| format!("closed {c}")).unwrap_or("closed".to_string()),
        (Err(e), _) | (_, Err(e)) => format!("err: {e}"),
    };
    if flow.inner.lock().unwrap().status.starts_with("active") {
        flow.set_status(status);
    }
}

/// Read the first client bytes and try to extract the hostname (TLS SNI or
/// HTTP Host) without breaking server-first protocols: if nothing arrives
/// within 300ms we give up on sniffing and relay blind.
fn sniff(client: &mut TcpStream) -> io::Result<(Vec<u8>, Option<String>)> {
    client.set_read_timeout(Some(Duration::from_millis(300)))?;
    let mut buf = Vec::with_capacity(8192);
    let deadline = Instant::now() + Duration::from_millis(1500);
    loop {
        let mut chunk = [0u8; 4096];
        match client.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => {
                buf.extend_from_slice(&chunk[..n]);
                match proto::classify(&buf) {
                    proto::Kind::Tls => {
                        if let Some(h) = proto::tls_sni(&buf) {
                            return Ok((buf, Some(h)));
                        }
                        if !proto::tls_incomplete(&buf) {
                            return Ok((buf, None)); // complete record, no SNI
                        }
                    }
                    proto::Kind::Http => {
                        if let Some(h) = proto::http_host(&buf) {
                            return Ok((buf, Some(h)));
                        }
                    }
                    proto::Kind::Other => return Ok((buf, None)),
                }
                if buf.len() >= 16384 || Instant::now() >= deadline {
                    return Ok((buf, None));
                }
            }
            Err(e)
                if e.kind() == io::ErrorKind::WouldBlock
                    || e.kind() == io::ErrorKind::TimedOut =>
            {
                break; // nothing more coming promptly; relay what we have
            }
            Err(e) => return Err(e),
        }
    }
    let host = proto::tls_sni(&buf)
        .or_else(|| proto::http_host(&buf));
    Ok((buf, host))
}

fn pump(from: &mut TcpStream, to: &mut TcpStream, counter: &AtomicU64, flow: &Flow, dir: Dir) -> io::Result<u64> {
    let mut buf = [0u8; 16 * 1024];
    let mut total = 0u64;
    loop {
        match from.read(&mut buf) {
            Ok(0) => return Ok(total),
            Ok(n) => {
                to.write_all(&buf[..n])?;
                counter.fetch_add(n as u64, Ordering::Relaxed);
                flow.capture(dir, &buf[..n]);
                total += n as u64;
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => {
                let _ = to.shutdown(Shutdown::Both); // unblock the sibling pump
                return Err(e);
            }
        }
    }
}

/// Connect to the original destination from a source port inside the pf
/// bypass range (20000:20999) so the connection is not redirected back to us.
fn relay_connect(dst: SocketAddr) -> io::Result<TcpStream> {
    let std::net::SocketAddr::V4(d) = dst else {
        return Err(io::Error::other("non-IPv4 destination"));
    };
    let last = io::Error::other("no free relay ports");
    for _ in 0..RELAY_PORT_COUNT {
        let port = RELAY_PORT_BASE + (NEXT_RELAY.fetch_add(1, Ordering::Relaxed) % RELAY_PORT_COUNT);
        let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let one: libc::c_int = 1;
        unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_REUSEADDR,
                &one as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            );
        }
        let bind_addr = libc::sockaddr_in {
            sin_len: std::mem::size_of::<libc::sockaddr_in>() as u8,
            sin_family: libc::AF_INET as u8,
            sin_port: port.to_be(),
            sin_addr: libc::in_addr { s_addr: 0 },
            sin_zero: [0; 8],
        };
        let r = unsafe {
            libc::bind(
                fd,
                &bind_addr as *const _ as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
            )
        };
        if r != 0 {
            unsafe { libc::close(fd) };
            continue; // port taken, try the next
        }
        let dst_addr = libc::sockaddr_in {
            sin_len: std::mem::size_of::<libc::sockaddr_in>() as u8,
            sin_family: libc::AF_INET as u8,
            sin_port: d.port().to_be(),
            sin_addr: libc::in_addr { s_addr: u32::from_ne_bytes(d.ip().octets()) },
            sin_zero: [0; 8],
        };
        let r = unsafe {
            libc::connect(
                fd,
                &dst_addr as *const _ as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
            )
        };
        if r == 0 {
            return Ok(unsafe { TcpStream::from_raw_fd(fd) });
        }
        let e = io::Error::last_os_error();
        unsafe { libc::close(fd) };
        match e.kind() {
            io::ErrorKind::AddrInUse | io::ErrorKind::PermissionDenied => continue,
            _ => return Err(e),
        }
    }
    Err(last)
}

/// Close with SO_LINGER=0 so the client sees an immediate TCP RST
/// (blocked connections should fail fast, not linger on FIN).
fn rst_close(s: &mut TcpStream) {
    unsafe {
        let ling = libc::linger { l_onoff: 1, l_linger: 0 };
        libc::setsockopt(
            s.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_LINGER,
            &ling as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::linger>() as libc::socklen_t,
        );
    }
    let _ = s.shutdown(Shutdown::Both);
}
