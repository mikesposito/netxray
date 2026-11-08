mod block;
mod flow;
mod pf;
mod pid;
mod proto;
mod proxy;
mod tui;

use std::net::TcpListener;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::Arc;

use flow::Shared;
use pf::Pf;
use proxy::LISTEN_PORT;

fn main() {
    let blocklist_path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "blocklist.txt".to_string());

    if unsafe { libc::geteuid() } != 0 {
        eprintln!("interceptor must run as root to manage pf — try: sudo ./interceptor");
        std::process::exit(1);
    }

    let shared = Arc::new(Shared::new(blocklist_path));

    // Bind before pf rules go live so no connection is lost in the gap.
    let listener = match TcpListener::bind(("127.0.0.1", LISTEN_PORT)) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("cannot bind 127.0.0.1:{LISTEN_PORT}: {e}");
            std::process::exit(1);
        }
    };

    let pf = match Pf::setup(LISTEN_PORT) {
        Ok(p) => Arc::new(p),
        Err(e) => {
            eprintln!("pf setup failed: {e}");
            std::process::exit(1);
        }
    };
    eprintln!("intercepting on 127.0.0.1:{LISTEN_PORT} — press q in the TUI to quit");

    proxy::spawn(shared.clone(), listener, pf.clone());
    pid::spawn(shared.clone());

    // Terminal raw mode: panic in the TUI must not leave the ruleset behind.
    let res = catch_unwind(AssertUnwindSafe(|| tui::run(&shared)));
    pf.restore();
    std::process::exit(match res {
        Ok(Ok(())) => 0,
        Ok(Err(e)) => {
            eprintln!("tui error: {e}");
            1
        }
        Err(_) => 1,
    });
}
