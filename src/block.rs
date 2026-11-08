use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::RwLock;
use std::time::SystemTime;

/// Shell-style glob: '*' = any run, '?' = any single char, case-insensitive.
/// Iterative two-pointer matcher with backtracking on '*'.
pub fn glob_match(pattern: &str, text: &str) -> bool {
  let p: Vec<char> = pattern.to_lowercase().chars().collect();
  let t: Vec<char> = text.to_lowercase().chars().collect();
  let (mut pi, mut ti) = (0usize, 0usize);
  let (mut star, mut mark) = (None::<usize>, 0usize);
  while ti < t.len() {
    if pi < p.len() && (p[pi] == '?' || p[pi] == t[ti]) {
      pi += 1;
      ti += 1;
    } else if pi < p.len() && p[pi] == '*' {
      star = Some(pi);
      mark = ti;
      pi += 1;
    } else if let Some(s) = star {
      pi = s + 1;
      mark += 1;
      ti = mark;
    } else {
      return false;
    }
  }
  while pi < p.len() && p[pi] == '*' {
    pi += 1;
  }
  pi == p.len()
}

struct State {
  patterns: Vec<String>,
  mtime: Option<SystemTime>,
}

/// One pattern per line; '#' comments allowed. Reloaded automatically when
/// the file's mtime changes, so the file can be edited while the tool runs.
pub struct Blocklist {
  path: PathBuf,
  state: RwLock<State>,
}

impl Blocklist {
  pub fn new(path: impl Into<PathBuf>) -> Self {
    let bl = Blocklist {
      path: path.into(),
      state: RwLock::new(State {
        patterns: Vec::new(),
        mtime: None,
      }),
    };
    bl.reload(true);
    bl
  }

  pub fn path(&self) -> &str {
    self.path.to_str().unwrap_or("?")
  }

  pub fn len(&self) -> usize {
    self.state.read().unwrap().patterns.len()
  }

  pub fn is_empty(&self) -> bool {
    self.len() == 0
  }

  fn reload(&self, force: bool) {
    let mtime = fs::metadata(&self.path).and_then(|m| m.modified()).ok();
    let mut st = self.state.write().unwrap();
    if !force && st.mtime == mtime {
      return; // unchanged since last load
    }
    st.mtime = mtime;
    st.patterns = fs::read_to_string(&self.path)
      .unwrap_or_default()
      .lines()
      .map(|l| l.trim().to_string())
      .filter(|l| !l.is_empty() && !l.starts_with('#'))
      .collect();
  }

  pub fn matches(&self, host: Option<&str>, dst: Option<SocketAddr>) -> Option<String> {
    self.reload(false);
    let st = self.state.read().unwrap();
    for p in &st.patterns {
      if host.is_some_and(|h| glob_match(p, h))
        || dst.is_some_and(|d| glob_match(p, &d.ip().to_string()))
      {
        return Some(p.clone());
      }
    }
    None
  }

  /// Append one pattern (used by the TUI 'b' key) and reload.
  pub fn add(&self, pattern: &str) -> io::Result<usize> {
    let mut f = OpenOptions::new()
      .create(true)
      .append(true)
      .open(&self.path)?;
    writeln!(f, "{pattern}")?;
    drop(f);
    self.reload(true);
    Ok(self.len())
  }

  /// Current patterns in file order (reloaded first so the view is fresh).
  pub fn patterns(&self) -> Vec<String> {
    self.reload(false);
    self.state.read().unwrap().patterns.clone()
  }

  /// Delete one pattern by index.
  /// shortcut: rewrites the whole file, so comments/blank lines are dropped; fine while patterns are the file's only real content
  pub fn remove(&self, index: usize) -> io::Result<()> {
    let mut pats = self.patterns();
    if index >= pats.len() {
      return Err(io::Error::other("no such pattern"));
    }
    let removed = pats.remove(index);
    fs::write(
      &self.path,
      if pats.is_empty() {
        String::new()
      } else {
        pats.join("\n") + "\n"
      },
    )?;
    self.reload(true);
    let _ = removed;
    Ok(())
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn glob_basics() {
    assert!(glob_match("example.com", "example.com"));
    assert!(glob_match("EXAMPLE.com", "example.COM"));
    assert!(!glob_match("example.com", "www.example.com"));
    assert!(glob_match("*.example.com", "a.b.example.com"));
    assert!(!glob_match("*.example.com", "example.com"));
    assert!(glob_match("*google*", "awwwgooglexxx"));
    assert!(!glob_match("*google*", "bing.com"));
    assert!(glob_match("f?o", "foo"));
    assert!(!glob_match("f?o", "fooo"));
    assert!(glob_match("*", "anything"));
    assert!(glob_match("", ""));
    assert!(!glob_match("", "x"));
  }

  #[test]
  fn blocklist_file_roundtrip() {
    let path = std::env::temp_dir().join(format!("interceptor-bl-test-{}", std::process::id()));
    let _ = fs::remove_file(&path);
    fs::write(&path, "# comment\n*.example.com\n").unwrap();

    let bl = Blocklist::new(&path);
    assert_eq!(bl.len(), 1);
    assert_eq!(
      bl.matches(Some("www.example.com"), None),
      Some("*.example.com".to_string())
    );
    assert_eq!(bl.matches(Some("example.org"), None), None);

    let dst: SocketAddr = "93.184.216.34:443".parse().unwrap();
    bl.add("93.184.216.34").unwrap();
    assert_eq!(
      bl.matches(None, Some(dst)),
      Some("93.184.216.34".to_string())
    );
    assert_eq!(bl.len(), 2);

    bl.remove(0).unwrap();
    assert_eq!(bl.len(), 1);
    assert_eq!(bl.matches(Some("www.example.com"), None), None);
    assert_eq!(bl.matches(Some("blocked.example.com"), None), None);
    bl.remove(0).unwrap();
    assert_eq!(bl.patterns(), Vec::<String>::new());
    let _ = fs::remove_file(&path);
  }
}
