//! wgproxyrs CLI scaffold.
//!
//! Parses the intended command-line surface and then stops honestly:
//! the tunnel is not implemented yet (see ROADMAP.md, Phase 1).

use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::ExitCode;

use wgproxyrs::config::Settings;

const USAGE: &str = "\
wgproxyrs — userspace WireGuard client exposed as a SOCKS5/HTTP proxy

Usage: wgproxyrs [OPTIONS]

Options:
  -c, --config <PATH>   Stock WireGuard .conf file
      --bind <ADDR>     Proxy bind address [default: 127.0.0.1:1080]
  -h, --help            Print this help
  -v, --version         Print version
";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();

    let mut config_path: Option<PathBuf> = None;
    let mut bind: Option<SocketAddr> = None;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "-h" | "--help" => {
                print!("{USAGE}");
                return ExitCode::SUCCESS;
            }
            "-v" | "--version" => {
                println!("wgproxyrs {}", env!("CARGO_PKG_VERSION"));
                return ExitCode::SUCCESS;
            }
            "-c" | "--config" => {
                i += 1;
                match args.get(i) {
                    Some(path) => config_path = Some(PathBuf::from(path)),
                    None => {
                        eprintln!("error: --config needs a path\n\n{USAGE}");
                        return ExitCode::FAILURE;
                    }
                }
            }
            "--bind" => {
                i += 1;
                match args.get(i).and_then(|v| v.parse::<SocketAddr>().ok()) {
                    Some(addr) => bind = Some(addr),
                    None => {
                        eprintln!("error: --bind needs an IP:port address\n\n{USAGE}");
                        return ExitCode::FAILURE;
                    }
                }
            }
            other => {
                eprintln!("error: unknown argument '{other}'\n\n{USAGE}");
                return ExitCode::FAILURE;
            }
        }
        i += 1;
    }

    let Some(config_path) = config_path else {
        eprintln!("error: --config <PATH> is required\n\n{USAGE}");
        return ExitCode::FAILURE;
    };

    let mut settings = Settings::new(config_path);
    if let Some(addr) = bind {
        settings.bind = addr;
    }

    // Fail-closed starts here: with no tunnel implementation yet, the only
    // correct behaviour is to refuse rather than pretend to proxy.
    eprintln!(
        "wgproxyrs {}: scaffold build — tunnel not implemented yet, refusing to start.\n\
         config: {}\nbind: {}\nSee ROADMAP.md (Phase 1) for what lands next.",
        env!("CARGO_PKG_VERSION"),
        settings.config_path.display(),
        settings.bind,
    );
    ExitCode::FAILURE
}
