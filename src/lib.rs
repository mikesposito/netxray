//! interceptor — a transparent TCP proxy + TUI network logger for macOS.
//!
//! Intercepts every program's outbound TCP connections via pf, relays them
//! unchanged, shows a live log (process, hostname, bytes) and can block
//! hosts by glob pattern.

pub mod block;
pub mod flow;
pub mod pf;
pub mod pid;
pub mod proto;
pub mod proxy;
pub mod tui;

use std::net::TcpListener;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::Arc;

use flow::Shared;
use pf::Pf;
use proxy::LISTEN_PORT;

/// Boot the proxy and run the TUI until the user quits. Returns the exit code.
pub fn run(blocklist_path: String) -> i32 {
  if unsafe { libc::geteuid() } != 0 {
    eprintln!("interceptor must run as root to manage pf — try: sudo ./interceptor");
    return 1;
  }

  let shared = Arc::new(Shared::new(blocklist_path));

  // Bind before pf rules go live so no connection is lost in the gap.
  let listener = match TcpListener::bind(("127.0.0.1", LISTEN_PORT)) {
    Ok(l) => l,
    Err(e) => {
      eprintln!("cannot bind 127.0.0.1:{LISTEN_PORT}: {e}");
      return 1;
    }
  };

  let pf = match Pf::setup(LISTEN_PORT) {
    Ok(p) => Arc::new(p),
    Err(e) => {
      eprintln!("pf setup failed: {e}");
      return 1;
    }
  };
  eprintln!("intercepting on 127.0.0.1:{LISTEN_PORT} — press q in the TUI to quit");

  proxy::spawn(shared.clone(), listener, pf.clone());
  pid::spawn(shared.clone());

  // Terminal raw mode: panic in the TUI must not leave the ruleset behind.
  let res = catch_unwind(AssertUnwindSafe(|| tui::run(&shared)));
  pf.restore();
  match res {
    Ok(Ok(())) => 0,
    Ok(Err(e)) => {
      eprintln!("tui error: {e}");
      1
    }
    Err(_) => 1,
  }
}
