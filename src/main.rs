use std::env;

fn main() {
  let blocklist_path = env::args()
    .nth(1)
    .unwrap_or_else(|| "blocklist.txt".to_string());
  std::process::exit(netxray::run(blocklist_path));
}
