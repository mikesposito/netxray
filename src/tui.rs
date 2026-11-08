use std::io;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use ratatui::layout::{Constraint, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::Clear;
use ratatui::widgets::{List, ListItem, Paragraph, Row, Table, Wrap};
use ratatui::Frame;

use crate::flow::{Flow, Shared};

struct Detail {
  flow: Arc<Flow>,
  scroll: usize,
}

struct Help {
  filter: String,
  saved: String,
  editing: bool,
}

const HELP: &[(&str, &str)] = &[
  ("/", "filter flows (live, like nvim incsearch)"),
  ("b", "block the selected flow's hostname"),
  ("B", "open the blocklist editor"),
  ("d / x", "in blocklist: remove the selected pattern"),
  ("Enter", "inspect a flow: headers and bodies"),
  ("j / k / arrows", "scroll / move selection"),
  ("g / G", "top / tail"),
  ("?", "this help"),
  ("/ (here)", "search between shortcuts"),
  ("q / Ctrl-C", "quit (restores the pf ruleset)"),
];

struct App {
  filter: String,
  saved_filter: String,
  editing: bool,
  offset: usize,
  selected: usize,
  follow: bool,
  view_h: usize,
  message: Option<(String, Instant)>,
  detail: Option<Detail>,
  bl_view: Option<usize>, // blocklist editor: selected pattern index
  help: Option<Help>,     // '?' modal
}

impl App {
  fn new() -> Self {
    App {
      filter: String::new(),
      saved_filter: String::new(),
      editing: false,
      offset: 0,
      selected: 0,
      follow: true,
      view_h: 1,
      message: None,
      detail: None,
      bl_view: None,
      help: None,
    }
  }

  fn flash(&mut self, msg: impl Into<String>) {
    self.message = Some((msg.into(), Instant::now()));
  }
}

struct RowData {
  flow: Arc<Flow>,
  cells: [String; 9],
  code: Option<u16>,
}

/// Build display rows for all flows matching the current filter (nvim-style
/// live incsearch: the edit buffer filters as you type).
fn visible(shared: &Shared, filter: &str) -> Vec<RowData> {
  let needle = filter.to_lowercase();
  let flows = shared.flows.lock().unwrap();
  flows
    .iter()
    .filter_map(|f| {
      let i = f.inner.lock().unwrap();
      let code = i.http_status;
      let status = match (code, i.status.as_str()) {
        (Some(c), "active") => format!("active {c}"),
        _ => i.status.clone(),
      };
      let cells = [
        fmt_time(f.start),
        i.pid.map(|p| p.to_string()).unwrap_or_else(|| "-".into()),
        i.comm.clone().unwrap_or_default(),
        i.host.clone().unwrap_or_else(|| "-".into()),
        f.dst.map(|d| d.to_string()).unwrap_or_else(|| "?".into()),
        i.method.clone().unwrap_or_else(|| "-".into()),
        human(f.up.load(std::sync::atomic::Ordering::Relaxed)),
        human(f.down.load(std::sync::atomic::Ordering::Relaxed)),
        status,
      ];
      let joined = cells
        .iter()
        .map(|c| c.to_lowercase())
        .collect::<Vec<_>>()
        .join(" ");
      if needle.is_empty() || joined.contains(&needle) {
        Some(RowData {
          flow: f.clone(),
          cells,
          code,
        })
      } else {
        None
      }
    })
    .collect()
}

pub fn run(shared: &Arc<Shared>) -> io::Result<()> {
  let mut terminal = ratatui::init();
  let mut app = App::new();
  let res = event_loop(&mut terminal, shared, &mut app);
  ratatui::restore();
  res
}

fn event_loop(
  terminal: &mut ratatui::DefaultTerminal,
  shared: &Arc<Shared>,
  app: &mut App,
) -> io::Result<()> {
  use ratatui::crossterm::event::{self, Event, KeyEventKind};

  loop {
    terminal.draw(|f| ui(f, shared, app))?;
    if !event::poll(Duration::from_millis(200))? {
      continue;
    }
    match event::read()? {
      Event::Key(k) if k.kind == KeyEventKind::Press && handle_key(shared, app, k) => {
        return Ok(());
      }
      _ => {}
    }
  }
}

/// Returns true when the app should quit.
fn handle_key(shared: &Arc<Shared>, app: &mut App, k: ratatui::crossterm::event::KeyEvent) -> bool {
  use ratatui::crossterm::event::{KeyCode, KeyModifiers};

  if app.bl_view.is_some() {
    let mut sel = app.bl_view.unwrap();
    let mut closed = false;
    let pats = shared.blocklist.patterns();
    match k.code {
      KeyCode::Esc | KeyCode::Char('q') | KeyCode::Enter => closed = true,
      KeyCode::Char('j') | KeyCode::Down if !pats.is_empty() => {
        sel = (sel + 1).min(pats.len() - 1);
      }
      KeyCode::Char('k') | KeyCode::Up => sel = sel.saturating_sub(1),
      KeyCode::Char('g') => sel = 0,
      KeyCode::Char('G') => sel = pats.len().saturating_sub(1),
      KeyCode::Char('d') | KeyCode::Char('x') => {
        if let Some(p) = pats.get(sel).cloned() {
          match shared.blocklist.remove(sel) {
            Ok(()) => {
              app.flash(format!("removed: {p}"));
              if sel >= shared.blocklist.len() {
                sel = shared.blocklist.len().saturating_sub(1);
              }
            }
            Err(e) => app.flash(format!("remove failed: {e}")),
          }
        }
      }
      _ => {}
    }
    app.bl_view = if closed { None } else { Some(sel) };
    return false;
  }

  if let Some(d) = &mut app.detail {
    let max = usize::MAX / 4; // clamped precisely in ui() on the next frame
    match k.code {
      KeyCode::Esc | KeyCode::Enter | KeyCode::Char('q') => app.detail = None,
      KeyCode::Char('j') | KeyCode::Down => d.scroll += 1,
      KeyCode::Char('k') | KeyCode::Up => d.scroll = d.scroll.saturating_sub(1),
      KeyCode::PageDown => d.scroll = d.scroll.saturating_add(app.view_h).min(max),
      KeyCode::PageUp => d.scroll = d.scroll.saturating_sub(app.view_h),
      KeyCode::Char('g') => d.scroll = 0,
      KeyCode::Char('G') => d.scroll = max,
      _ => {}
    }
    return false;
  }

  if app.help.is_some() {
    let h = app.help.as_mut().unwrap();
    let mut close = false;
    if h.editing {
      match k.code {
        KeyCode::Char(c) => h.filter.push(c),
        KeyCode::Backspace => {
          h.filter.pop();
        }
        KeyCode::Enter => {
          h.saved = h.filter.clone();
          h.editing = false;
        }
        KeyCode::Esc => {
          h.filter = h.saved.clone();
          h.editing = false;
        }
        _ => {}
      }
    } else {
      match k.code {
        KeyCode::Char('?') | KeyCode::Char('q') | KeyCode::Esc => close = true,
        KeyCode::Char('/') => {
          h.saved = h.filter.clone();
          h.editing = true;
        }
        _ => {}
      }
    }
    if close {
      app.help = None;
    }
    return false;
  }

  if app.editing {
    match k.code {
      KeyCode::Char(c) => app.filter.push(c),
      KeyCode::Backspace => {
        app.filter.pop();
      }
      KeyCode::Enter => {
        app.saved_filter = app.filter.clone();
        app.editing = false;
      }
      KeyCode::Esc => {
        app.filter = app.saved_filter.clone(); // abort, keep previous filter
        app.editing = false;
      }
      _ => {}
    }
    return false;
  }

  match k.code {
    KeyCode::Char('q') => return true,
    KeyCode::Char('c') if k.modifiers.contains(KeyModifiers::CONTROL) => return true,
    KeyCode::Enter => {
      let rows = visible(shared, &app.filter);
      if let Some(rd) = rows.get(app.selected) {
        app.detail = Some(Detail {
          flow: rd.flow.clone(),
          scroll: 0,
        });
      }
    }
    KeyCode::Char('/') => {
      app.saved_filter = app.filter.clone();
      app.editing = true;
    }
    KeyCode::Char('?') => {
      app.help = Some(Help {
        filter: String::new(),
        saved: String::new(),
        editing: false,
      });
    }
    KeyCode::Char('b') => block_selected(shared, app),
    KeyCode::Char('B') => app.bl_view = Some(0),
    KeyCode::Char('j') | KeyCode::Down => move_sel(app, shared, 1),
    KeyCode::Char('k') | KeyCode::Up => move_sel(app, shared, -1),
    KeyCode::Char('g') => {
      app.follow = false;
      app.selected = 0;
    }
    KeyCode::Char('G') => {
      app.follow = true;
    }
    KeyCode::PageUp => move_sel(app, shared, -(app.view_h as isize)),
    KeyCode::PageDown => move_sel(app, shared, app.view_h as isize),
    _ => {}
  }
  false
}

fn move_sel(app: &mut App, shared: &Arc<Shared>, delta: isize) {
  let len = visible(shared, &app.filter).len();
  if len == 0 {
    return;
  }
  let new = app.selected as isize + delta;
  app.selected = new.clamp(0, len as isize - 1) as usize;
  app.follow = app.selected + 1 == len;
}

/// 'b' on the selected flow: block its hostname (or destination IP if no
/// host was sniffed) by appending a pattern to the blocklist file.
fn block_selected(shared: &Arc<Shared>, app: &mut App) {
  let rows = visible(shared, &app.filter);
  let Some(rd) = rows.get(app.selected) else {
    return;
  };
  let inner = rd.flow.inner.lock().unwrap();
  let pattern = inner
    .host
    .clone()
    .filter(|h| !h.is_empty())
    .unwrap_or_else(|| rd.flow.dst.map(|d| d.ip().to_string()).unwrap_or_default());
  drop(inner);
  if pattern.is_empty() {
    app.flash("nothing to block");
    return;
  }
  match shared.blocklist.add(&pattern) {
    Ok(_) => app.flash(format!("blocked: {pattern}")),
    Err(e) => app.flash(format!("blocklist error: {e}")),
  }
}

fn ui(f: &mut Frame, shared: &Arc<Shared>, app: &mut App) {
  let area = f.area();
  let chunks = ratatui::layout::Layout::vertical([
    Constraint::Min(1),
    Constraint::Length(1),
    Constraint::Length(1),
  ])
  .split(area);
  let (table_area, status_area, input_area) = (chunks[0], chunks[1], chunks[2]);

  if let Some(sel) = app.bl_view.as_mut() {
    let pats = shared.blocklist.patterns();
    if *sel >= pats.len() {
      *sel = pats.len().saturating_sub(1);
    }
    let title = format!(
      " blocklist: {} — d:remove  j/k:move  Esc:close ",
      shared.blocklist.path()
    );
    let items: Vec<ListItem> = if pats.is_empty() {
      vec![ListItem::new(Span::styled(
        "(empty — press b on a flow, or edit the file directly)",
        Style::default().fg(Color::DarkGray),
      ))]
    } else {
      pats
        .iter()
        .enumerate()
        .map(|(i, p)| {
          let mut style = Style::default().fg(Color::Yellow);
          if i == *sel {
            style = style.add_modifier(Modifier::REVERSED);
          }
          ListItem::new(Span::styled(p.clone(), style))
        })
        .collect()
    };
    f.render_widget(
      List::new(items).block(ratatui::widgets::Block::bordered().title(title)),
      area,
    );
    return;
  }

  if let Some(d) = &mut app.detail {
    let w = area.width as usize;
    let lines = detail_lines(&d.flow);
    let total: usize = lines
      .iter()
      .map(|l| {
        l.iter()
          .map(|s| s.content.chars().count())
          .sum::<usize>()
          .div_ceil(w)
      })
      .sum();
    d.scroll = d.scroll.min(total.saturating_sub(1));
    f.render_widget(
      Paragraph::new(lines)
        .wrap(Wrap { trim: false })
        .scroll((d.scroll as u16, 0)),
      table_area,
    );
    let hint = Line::from(Span::styled(
            "detail · Esc:close · j/k/PgUp/PgDn:scroll · g/G:top/bottom · bodies are only captured for plain HTTP",
            Style::default().fg(Color::DarkGray),
        ));
    f.render_widget(Paragraph::new(hint), input_area);
    return;
  }

  let data = visible(shared, &app.filter);
  let h = (table_area.height as usize).saturating_sub(1).max(1);
  app.view_h = h;
  if data.is_empty() {
    app.selected = 0;
    app.offset = 0;
  } else {
    if app.selected >= data.len() {
      app.selected = data.len() - 1;
    }
    if app.follow {
      app.selected = data.len() - 1;
      app.offset = data.len().saturating_sub(h);
    }
    if app.selected < app.offset {
      app.offset = app.selected;
    }
    if app.selected >= app.offset + h {
      app.offset = app.selected + 1 - h;
    }
    app.offset = app.offset.min(data.len() - 1);
  }

  let header = Row::new([
    "time",
    "pid",
    "process",
    "host / url",
    "dst",
    "method",
    "up",
    "down",
    "status",
  ]);
  let rows = data[app.offset..(app.offset + h).min(data.len())]
    .iter()
    .enumerate()
    .map(|(i, rd)| {
      let sel = app.offset + i == app.selected;
      let mut style = Style::default().fg(status_color(&rd.cells[8], rd.code));
      if sel {
        style = style.add_modifier(Modifier::REVERSED);
      }
      Row::new(rd.cells.iter().map(|c| c.as_str()).collect::<Vec<_>>()).style(style)
    });
  let table = Table::new(
    rows,
    [
      Constraint::Length(10),
      Constraint::Length(6),
      Constraint::Length(13),
      Constraint::Min(12),
      Constraint::Length(21),
      Constraint::Length(7),
      Constraint::Length(9),
      Constraint::Length(9),
      Constraint::Length(12),
    ],
  )
  .header(header);
  f.render_widget(table, table_area);

  // status line
  let total = shared.flows.lock().unwrap().len();
  let shown = data.len();
  let mut spans = vec![
    Span::styled(
      format!("{total} flows · {shown} shown · "),
      Style::default(),
    ),
    Span::styled(
      format!(
        "blocklist: {} ({} patterns) · ",
        shared.blocklist.path(),
        shared.blocklist.len()
      ),
      Style::default(),
    ),
    Span::styled(
      "/:filter  b:block  B:blocklist  ?:help  q:quit",
      Style::default().fg(Color::DarkGray),
    ),
  ];
  if let Some((msg, at)) = &app.message {
    if at.elapsed() < Duration::from_secs(3) {
      spans.insert(
        0,
        Span::styled(format!("{msg}  "), Style::default().fg(Color::Yellow)),
      );
    } else {
      app.message = None;
    }
  }
  let status = Line::from(spans);
  f.render_widget(Paragraph::new(status), status_area);

  // input line ('/' prompt, like vim search)
  let input = if app.editing {
    Line::from(vec![
      Span::styled("/", Style::default().fg(Color::Cyan)),
      Span::raw(app.filter.clone()),
      Span::styled("▏", Style::default().fg(Color::Cyan)),
    ])
  } else if !app.filter.is_empty() {
    Line::from(vec![
      Span::styled("/", Style::default().fg(Color::DarkGray)),
      Span::raw(app.filter.clone()),
    ])
  } else {
    Line::from("")
  };
  f.render_widget(Paragraph::new(input), input_area);

  if let Some(h) = &app.help {
    render_help(f, area, h);
  }
}

fn centered_rect(pct_x: u16, pct_y: u16, r: Rect) -> Rect {
  let v = ratatui::layout::Layout::vertical([
    Constraint::Percentage((100 - pct_y) / 2),
    Constraint::Percentage(pct_y),
    Constraint::Percentage((100 - pct_y) / 2),
  ])
  .split(r);
  ratatui::layout::Layout::horizontal([
    Constraint::Percentage((100 - pct_x) / 2),
    Constraint::Percentage(pct_x),
    Constraint::Percentage((100 - pct_x) / 2),
  ])
  .split(v[1])[1]
}

fn render_help(f: &mut Frame, area: Rect, h: &Help) {
  let popup = centered_rect(70, 60, area);
  let needle = h.filter.to_lowercase();
  let mut lines: Vec<Line> = Vec::new();
  for (key, desc) in HELP {
    let hay = format!("{key} {desc}").to_lowercase();
    if needle.is_empty() || hay.contains(&needle) {
      lines.push(Line::from(vec![
        Span::styled(format!("{key:<14}"), Style::default().fg(Color::Cyan)),
        Span::raw(*desc),
      ]));
    }
  }
  if lines.is_empty() {
    lines.push(Line::from(Span::styled(
      "(no matching shortcut)",
      Style::default().fg(Color::DarkGray),
    )));
  }
  let title = if h.editing {
    format!(" shortcuts — /{}▏ ", h.filter)
  } else if h.filter.is_empty() {
    " shortcuts — /:search · Esc:close ".to_string()
  } else {
    format!(" shortcuts — /{} · Esc:close ", h.filter)
  };
  f.render_widget(Clear, popup);
  f.render_widget(
    Paragraph::new(lines).block(ratatui::widgets::Block::bordered().title(title)),
    popup,
  );
}

fn status_color(status: &str, code: Option<u16>) -> Color {
  if code.is_some_and(|c| c >= 400) || status.starts_with("blocked") || status.starts_with("err") {
    Color::Red
  } else if status == "active" {
    Color::Cyan
  } else {
    Color::DarkGray
  }
}

fn sanitize(b: &[u8]) -> String {
  String::from_utf8_lossy(b)
    .chars()
    .map(|c| {
      if c.is_control() && c != '\n' && c != '\t' && c != '\r' {
        '.'
      } else {
        c
      }
    })
    .collect()
}

// ── detail view ──

fn dim_style() -> Style {
  Style::default().fg(Color::DarkGray)
}

fn divider(title: &str) -> Line<'static> {
  Line::from(Span::styled(
    format!("── {title} ──"),
    Style::default()
      .fg(Color::Magenta)
      .add_modifier(Modifier::BOLD),
  ))
}

fn code_color(c: u16) -> Color {
  match c {
    200..=299 => Color::Green,
    300..=399 => Color::Yellow,
    _ => Color::Red,
  }
}

fn first_line(l: &str, response: bool) -> Line<'static> {
  if response {
    if let Some(rest) = l.strip_prefix("HTTP/") {
      if let Some(sp) = rest.find(' ') {
        let tail = &rest[sp + 1..];
        if tail.len() >= 3 && tail[..3].chars().all(|c| c.is_ascii_digit()) {
          let code: u16 = tail[..3].parse().unwrap();
          return Line::from(vec![
            Span::styled(format!("HTTP/{} ", &rest[..sp]), dim_style()),
            Span::styled(
              tail[..3].to_string(),
              Style::default()
                .fg(code_color(code))
                .add_modifier(Modifier::BOLD),
            ),
            Span::raw(tail[3..].to_string()),
          ]);
        }
      }
    }
  } else if let Some(sp) = l.find(' ') {
    return Line::from(vec![
      Span::styled(
        l[..sp].to_string(),
        Style::default()
          .fg(Color::Cyan)
          .add_modifier(Modifier::BOLD),
      ),
      Span::raw(l[sp..].to_string()),
    ]);
  }
  Line::raw(l.to_string())
}

fn key_value_line(l: &str) -> Line<'static> {
  match l.find(':') {
    Some(c) => Line::from(vec![
      Span::styled(l[..=c].to_string(), Style::default().fg(Color::Cyan)),
      Span::raw(l[c + 1..].to_string()),
    ]),
    None => Line::raw(l.to_string()),
  }
}

fn capture_section(title: &str, buf: &[u8], response: bool) -> Vec<Line<'static>> {
  let mut out = vec![divider(title)];
  if buf.is_empty() {
    out.push(Line::from(Span::styled("(nothing captured)", dim_style())));
    return out;
  }
  let s = sanitize(buf);
  let (head, body) = match s.find("\r\n\r\n").or_else(|| s.find("\n\n")) {
    Some(p) => (&s[..p], s[p..].trim_start_matches(['\r', '\n']).to_string()),
    None => (s.as_str(), String::new()),
  };
  for (idx, l) in head.lines().enumerate() {
    out.push(if idx == 0 {
      first_line(l, response)
    } else {
      key_value_line(l)
    });
  }
  if !body.is_empty() {
    out.push(Line::raw(""));
    out.extend(body.lines().map(|l| Line::from(l.to_string())));
  }
  if buf.len() >= crate::flow::CAPTURE_CAP {
    out.push(Line::from(Span::styled(
      "[truncated at 64 KiB]",
      dim_style().add_modifier(Modifier::ITALIC),
    )));
  }
  out
}

fn detail_lines(flow: &Flow) -> Vec<Line<'static>> {
  let i = flow.inner.lock().unwrap();
  let mut status = i.status.clone();
  if let Some(c) = i.http_status {
    status.push_str(&format!(" ({c})"));
  }
  let mut out = vec![
    Line::from(vec![
      Span::styled("src     ", dim_style()),
      Span::raw(flow.src.to_string()),
      Span::styled("  →  ", dim_style()),
      Span::raw(
        flow
          .dst
          .map(|d| d.to_string())
          .unwrap_or_else(|| "?".into()),
      ),
    ]),
    Line::from(vec![
      Span::styled("process ", dim_style()),
      Span::raw(i.comm.clone().unwrap_or_else(|| "-".into())),
      Span::styled(
        format!(
          "  pid {}",
          i.pid.map(|p| p.to_string()).unwrap_or_else(|| "-".into())
        ),
        dim_style(),
      ),
    ]),
    Line::from(vec![
      Span::styled("host    ", dim_style()),
      Span::raw(i.host.clone().unwrap_or_else(|| "-".into())),
    ]),
    Line::from(vec![
      Span::styled("status  ", dim_style()),
      Span::styled(
        status,
        Style::default().fg(status_color(&i.status, i.http_status)),
      ),
    ]),
    Line::from(vec![
      Span::styled("bytes   ", dim_style()),
      Span::styled("up ", dim_style()),
      Span::raw(human(flow.up.load(std::sync::atomic::Ordering::Relaxed))),
      Span::styled("  down ", dim_style()),
      Span::raw(human(flow.down.load(std::sync::atomic::Ordering::Relaxed))),
    ]),
  ];
  if i.is_http {
    out.push(Line::raw(""));
    out.extend(capture_section("request", &i.req_buf, false));
    out.push(Line::raw(""));
    out.extend(capture_section("response", &i.resp_buf, true));
  } else {
    out.push(Line::raw(""));
    out.push(Line::from(Span::styled(
      "payload not captured: only plain HTTP headers/bodies are visible.",
      Style::default().fg(Color::Yellow),
    )));
    out.push(Line::from(Span::styled(
            "TLS is encrypted end-to-end (nothing after the ClientHello can be read), and binary protocols are streamed through without buffering.",
            dim_style(),
        )));
  }
  out
}

fn fmt_time(t: SystemTime) -> String {
  let secs = t
    .duration_since(UNIX_EPOCH)
    .map(|d| d.as_secs() as i64)
    .unwrap_or(0);
  let mut tm: libc::tm = unsafe { std::mem::zeroed() };
  unsafe { libc::localtime_r(&secs, &mut tm) };
  format!("{:02}:{:02}:{:02}", tm.tm_hour, tm.tm_min, tm.tm_sec)
}

fn human(n: u64) -> String {
  if n < 1024 {
    format!("{n}B")
  } else if n < 1024 * 1024 {
    format!("{:.1}K", n as f64 / 1024.0)
  } else if n < 1024 * 1024 * 1024 {
    format!("{:.1}M", n as f64 / (1024.0 * 1024.0))
  } else {
    format!("{:.1}G", n as f64 / (1024.0 * 1024.0 * 1024.0))
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn request_section_colors_method_and_keys() {
    let req = b"POST /api HTTP/1.1\r\nHost: x.test\r\nContent-Type: text/plain\r\n\r\nhello=world";
    let out = capture_section("request", req, false);
    // divider + 3 head lines + blank + body
    assert_eq!(out.len(), 6);
    assert_eq!(out[1].spans[0].content, "POST");
    assert_eq!(out[1].spans[0].style.fg, Some(Color::Cyan));
    assert_eq!(out[2].spans[0].content, "Host:");
    assert_eq!(out[2].spans[0].style.fg, Some(Color::Cyan));
    assert_eq!(out[4].spans, vec![]); // blank separator line
    assert_eq!(out[5].spans[0].content, "hello=world");
  }

  #[test]
  fn response_section_colors_status_code() {
    let resp = b"HTTP/1.1 404 Not Found\r\nServer: x\r\n\r\nnope";
    let out = capture_section("response", resp, true);
    assert_eq!(out[1].spans[0].content, "HTTP/1.1 ");
    assert_eq!(out[1].spans[0].style.fg, Some(Color::DarkGray));
    assert_eq!(out[1].spans[1].content, "404");
    assert_eq!(out[1].spans[1].style.fg, Some(Color::Red));
    assert_eq!(out[4].spans[0].content, "nope");
  }

  #[test]
  fn status_code_colors_by_class() {
    assert_eq!(code_color(200), Color::Green);
    assert_eq!(code_color(204), Color::Green);
    assert_eq!(code_color(301), Color::Yellow);
    assert_eq!(code_color(404), Color::Red);
    assert_eq!(code_color(500), Color::Red);
  }

  #[test]
  fn empty_capture_and_truncation_markers() {
    let empty = capture_section("request", &[], false);
    assert_eq!(empty[1].spans[0].content, "(nothing captured)");
    assert_eq!(empty[1].spans[0].style.fg, Some(Color::DarkGray));

    let big = vec![b'x'; crate::flow::CAPTURE_CAP];
    let out = capture_section("request", &big, false);
    let last = out.last().unwrap();
    assert_eq!(last.spans[0].content, "[truncated at 64 KiB]");
  }
}
