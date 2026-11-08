//! Sniffs the host name out of the first bytes of a connection:
//! TLS SNI from the ClientHello, or the `Host:` header of a plain HTTP request.

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Kind {
    Tls,
    Http,
    Other,
}

pub fn classify(b: &[u8]) -> Kind {
    if b.len() >= 3 && b[0] == 0x16 && b[1] == 0x03 {
        return Kind::Tls;
    }
    // HTTP request methods are short uppercase tokens followed by a space.
    if b.len() >= 4 && b[0].is_ascii_uppercase() && b[..b.len().min(8)].contains(&b' ') {
        return Kind::Http;
    }
    Kind::Other
}

/// True when a TLS record header is present but the body isn't fully buffered yet.
pub fn tls_incomplete(b: &[u8]) -> bool {
    b.len() >= 5
        && b[0] == 0x16
        && (u16::from_be_bytes([b[3], b[4]]) as usize) + 5 > b.len()
}

/// Extract the SNI hostname from a complete TLS ClientHello record, if present.
pub fn tls_sni(b: &[u8]) -> Option<String> {
    if b.len() < 5 || b[0] != 0x16 {
        return None;
    }
    let rec = u16::from_be_bytes([b[3], b[4]]) as usize;
    if rec < 4 || 5 + rec > b.len() {
        return None;
    }
    let b = &b[5..5 + rec];
    if b[0] != 0x01 {
        // not a ClientHello
        return None;
    }
    let mut i = 4; // handshake type (1) + 24-bit length (3)
    if i + 2 + 32 > b.len() {
        return None;
    }
    i += 2 + 32; // client version + random
    if i + 1 > b.len() {
        return None;
    }
    i += 1 + b[i] as usize; // session id
    if i + 2 > b.len() {
        return None;
    }
    i += 2 + u16::from_be_bytes([b[i], b[i + 1]]) as usize; // cipher suites
    if i + 1 > b.len() {
        return None;
    }
    i += 1 + b[i] as usize; // compression methods
    if i + 2 > b.len() {
        return None;
    }
    let ext_len = u16::from_be_bytes([b[i], b[i + 1]]) as usize;
    i += 2;
    let end = (i + ext_len).min(b.len());
    while i + 4 <= end {
        let etype = u16::from_be_bytes([b[i], b[i + 1]]);
        let elen = u16::from_be_bytes([b[i + 2], b[i + 3]]) as usize;
        let dstart = i + 4;
        if dstart + elen <= b.len() && etype == 0 {
            let d = &b[dstart..dstart + elen];
            // server_name extension: list_len(2) name_type(1)=0 len(2) name
            if d.len() >= 5 && d[2] == 0 {
                let nlen = u16::from_be_bytes([d[3], d[4]]) as usize;
                if d.len() >= 5 + nlen && nlen > 0 {
                    let name = String::from_utf8_lossy(&d[5..5 + nlen]).trim().to_string();
                    if name.is_empty() {
                        return None;
                    }
                    return Some(name);
                }
            }
        }
        i = dstart + elen;
    }
    None
}

/// The HTTP request method ("GET", "POST", ...) — first token of the request line.
pub fn http_method(b: &[u8]) -> Option<&str> {
    let end = b.iter().position(|&c| c == b' ')?;
    let m = b.get(..end)?;
    if m.is_empty() || m.len() > 10 || !m.iter().all(|c| c.is_ascii_uppercase()) {
        return None;
    }
    std::str::from_utf8(m).ok()
}

/// Status code from an HTTP response's first line, e.g. "HTTP/1.1 404 ...".
pub fn http_status(b: &[u8]) -> Option<u16> {
    if !b.starts_with(b"HTTP/") {
        return None;
    }
    let rest = &b[5..];
    let sp = rest.iter().position(|&c| c == b' ')?;
    let code = rest.get(sp + 1..sp + 4)?;
    if code.iter().all(|c| c.is_ascii_digit()) {
        std::str::from_utf8(code)
            .ok()
            .and_then(|s| s.parse().ok())
            .filter(|c| (100..600).contains(c))
    } else {
        None
    }
}

/// Extract the `Host:` header from buffered HTTP request bytes (case-insensitive).
pub fn http_host(b: &[u8]) -> Option<String> {
    if b.len() < 16 {
        return None;
    }
    let hay = b.to_ascii_lowercase();
    let needle = b"\nhost:";
    let pos = hay.windows(needle.len()).position(|w| w == needle)?;
    let rest = &b[pos + needle.len()..];
    let end = rest
        .iter()
        .position(|&c| c == b'\r' || c == b'\n')
        .unwrap_or(rest.len());
    let h = String::from_utf8_lossy(&rest[..end]).trim().to_string();
    if h.is_empty() {
        None
    } else {
        Some(h)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn client_hello(sni: &str) -> Vec<u8> {
        let name = sni.as_bytes();
        let mut sn = vec![0u8]; // name_type host_name
        sn.extend_from_slice(&(name.len() as u16).to_be_bytes());
        sn.extend_from_slice(name);
        let mut body = (sn.len() as u16).to_be_bytes().to_vec(); // server_name_list length
        body.extend(sn);
        let mut ext = 0u16.to_be_bytes().to_vec(); // extension type 0
        ext.extend_from_slice(&(body.len() as u16).to_be_bytes());
        ext.extend(body);

        let mut hs = vec![0x03, 0x03]; // client version TLS 1.2
        hs.extend(std::iter::repeat(0x42).take(32)); // random
        hs.push(0); // session id (empty)
        hs.extend([0x00, 0x02, 0x13, 0x01]); // 1 cipher suite
        hs.extend([0x01, 0x00]); // 1 null compression
        hs.extend_from_slice(&(ext.len() as u16).to_be_bytes());
        hs.extend(ext);

        let mut h = vec![0x01]; // handshake type ClientHello
        h.extend(&hs.len().to_be_bytes()[1..4]); // 24-bit length
        h.extend(hs);

        let mut rec = vec![0x16, 0x03, 0x01]; // record: handshake, TLS 1.0
        rec.extend_from_slice(&(h.len() as u16).to_be_bytes());
        rec.extend(h);
        rec
    }

    #[test]
    fn sni_roundtrip() {
        let hello = client_hello("example.com");
        assert_eq!(classify(&hello), Kind::Tls);
        assert_eq!(tls_sni(&hello), Some("example.com".to_string()));
        assert!(!tls_incomplete(&hello));
    }

    #[test]
    fn sni_partial_record() {
        let hello = client_hello("example.com");
        let cut = &hello[..hello.len() - 3];
        assert!(tls_incomplete(cut));
        assert_eq!(tls_sni(cut), None);
    }

    #[test]
    fn sni_garbage() {
        assert_eq!(tls_sni(&[0x16, 0x03, 0x01, 0x00, 0x02, 0xff, 0xff]), None);
        assert_eq!(tls_sni(b"GET / HTTP/1.1\r\n"), None);
    }

    #[test]
    fn http_parsing() {
        let req = b"GET /index.html HTTP/1.1\r\nHost: Example.COM\r\nUser-Agent: x\r\n\r\n";
        assert_eq!(classify(req), Kind::Http);
        assert_eq!(http_host(req), Some("Example.COM".to_string()));

        let partial = b"GET / HTTP/1.1\r\nHost: exa";
        assert_eq!(http_host(partial), Some("exa".to_string()));
        assert_eq!(classify(b"\x01\x02\x03\x04binary"), Kind::Other);
    }

    #[test]
    fn method_and_status_parsing() {
        assert_eq!(http_method(b"POST /api/x HTTP/1.1\r\n"), Some("POST"));
        assert_eq!(http_method(b"CONNECT"), None); // no space
        assert_eq!(http_method(b"get /x HTTP/1.1"), None); // lowercase = not a method
        assert_eq!(http_method(b"/path HTTP/1.1"), None);

        assert_eq!(http_status(b"HTTP/1.1 200 OK\r\n"), Some(200));
        assert_eq!(http_status(b"HTTP/1.0 404 Not Found"), Some(404));
        assert_eq!(http_status(b"HTTP/1.1 999 x"), None);
        assert_eq!(http_status(b"HTTP/1.1 4"), None);
        assert_eq!(http_status(b"garbage"), None);
    }
}
