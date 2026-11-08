use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::AtomicU64;
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

use crate::block::Blocklist;

const MAX_FLOWS: usize = 5000;

/// Per-direction bytes kept for the detail view (plain HTTP only).
pub const CAPTURE_CAP: usize = 64 * 1024;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Dir {
    Req,
    Resp,
}

pub struct Inner {
    pub host: Option<String>,
    pub pid: Option<u32>,
    pub comm: Option<String>,
    pub status: String,
    pub method: Option<String>,
    pub http_status: Option<u16>,
    pub req_buf: Vec<u8>,
    pub resp_buf: Vec<u8>,
    pub is_http: bool,
}

pub struct Flow {
    pub start: SystemTime,
    pub src: SocketAddr,
    pub dst: Option<SocketAddr>,
    pub up: AtomicU64,
    pub down: AtomicU64,
    pub inner: Mutex<Inner>,
}

impl Flow {
    pub fn set_host(&self, host: Option<&str>) {
        self.inner.lock().unwrap().host = host.map(str::to_string);
    }

    pub fn set_status(&self, status: impl Into<String>) {
        self.inner.lock().unwrap().status = status.into();
    }

    pub fn set_pid(&self, pid: u32, comm: String) {
        let mut i = self.inner.lock().unwrap();
        i.pid = Some(pid);
        i.comm = Some(comm);
    }

    /// Mark this flow as plain HTTP and record the first request bytes
    /// (enables detail-view capture for this connection).
    pub fn set_http(&self, method: Option<&str>, req: &[u8]) {
        let mut i = self.inner.lock().unwrap();
        i.is_http = true;
        i.method = method.map(str::to_string);
        i.req_buf = req[..req.len().min(CAPTURE_CAP)].to_vec();
    }

    /// Buffers streamed bytes for the detail view (HTTP only) and parses
    /// the response status code from the first response bytes.
    pub fn capture(&self, dir: Dir, bytes: &[u8]) {
        let mut i = self.inner.lock().unwrap();
        if !i.is_http {
            return;
        }
        let buf = match dir {
            Dir::Req => &mut i.req_buf,
            Dir::Resp => &mut i.resp_buf,
        };
        if buf.len() < CAPTURE_CAP {
            let take = (CAPTURE_CAP - buf.len()).min(bytes.len());
            buf.extend_from_slice(&bytes[..take]);
        }
        if dir == Dir::Resp && i.http_status.is_none() {
            i.http_status = crate::proto::http_status(&i.resp_buf);
        }
    }
}

pub struct Shared {
    pub flows: Mutex<Vec<Arc<Flow>>>,
    pub blocklist: Blocklist,
}

impl Shared {
    pub fn new(blocklist_path: impl Into<PathBuf>) -> Self {
        Shared {
            flows: Mutex::new(Vec::new()),
            blocklist: Blocklist::new(blocklist_path),
        }
    }

    pub fn push_flow(&self, src: SocketAddr, dst: Option<SocketAddr>) -> Arc<Flow> {
        let flow = Arc::new(Flow {
            start: SystemTime::now(),
            src,
            dst,
            up: AtomicU64::new(0),
            down: AtomicU64::new(0),
            inner: Mutex::new(Inner {
                host: None,
                pid: None,
                comm: None,
                status: "active".to_string(),
                method: None,
                http_status: None,
                req_buf: Vec::new(),
                resp_buf: Vec::new(),
                is_http: false,
            }),
        });
        let mut v = self.flows.lock().unwrap();
        if v.len() >= MAX_FLOWS {
            v.drain(0..1000); // keep the tool's memory bounded on long runs
        }
        v.push(flow.clone());
        flow
    }
}
