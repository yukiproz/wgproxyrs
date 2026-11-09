//! wgproxyrs CLI.
//!
//! ```text
//! wgproxyrs --config <path> [--bind 127.0.0.1:1080] [--http-bind <addr>]
//! wgproxyrs --config <path> --check     # validate config, no network
//! wgproxyrs genkey                      # fresh WireGuard keypair
//! ```

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs};
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use wgproxyrs::config::{Config, Settings};
use wgproxyrs::keys::generate_keypair;
use wgproxyrs::stack::{EngineConfig, spawn_engine};
use wgproxyrs::tunnel::{UdpTransport, WgTunnel};

const USAGE: &str = "\
wgproxyrs — userspace WireGuard client exposed as a SOCKS5/HTTP proxy

Usage:
  wgproxyrs --config <PATH> [OPTIONS]
  wgproxyrs genkey

Options:
  -c, --config <PATH>   Stock WireGuard .conf file
      --bind <ADDR>     SOCKS5 bind address [default: 127.0.0.1:1080]
      --http-bind <ADDR>  Also serve HTTP CONNECT on this address
      --check           Validate the config and exit (no network use)
  -h, --help            Print this help
  -v, --version         Print version
";

#[tokio::main]
async fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();

    if args.first().map(String::as_str) == Some("genkey") {
        let kp = generate_keypair();
        println!("PrivateKey = {}", kp.private_key_b64);
        println!("PublicKey = {}", kp.public_key_b64);
        return ExitCode::SUCCESS;
    }

    let mut config_path: Option<PathBuf> = None;
    let mut bind: Option<SocketAddr> = None;
    let mut http_bind: Option<SocketAddr> = None;
    let mut check = false;

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
            "--check" => check = true,
            "-c" | "--config" => {
                i += 1;
                match args.get(i) {
                    Some(path) => config_path = Some(PathBuf::from(path)),
                    None => return usage_error("--config needs a path"),
                }
            }
            "--bind" => {
                i += 1;
                match args.get(i).and_then(|v| v.parse::<SocketAddr>().ok()) {
                    Some(addr) => bind = Some(addr),
                    None => return usage_error("--bind needs an IP:port address"),
                }
            }
            "--http-bind" => {
                i += 1;
                match args.get(i).and_then(|v| v.parse::<SocketAddr>().ok()) {
                    Some(addr) => http_bind = Some(addr),
                    None => return usage_error("--http-bind needs an IP:port address"),
                }
            }
            other => return usage_error(&format!("unknown argument '{other}'")),
        }
        i += 1;
    }

    let Some(config_path) = config_path else {
        return usage_error("--config <PATH> is required");
    };
    let mut settings = Settings::new(config_path);
    if let Some(addr) = bind {
        settings.bind = addr;
    }
    settings.http_bind = http_bind;

    let config = match Config::load(&settings.config_path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("wgproxyrs: {e}");
            return ExitCode::FAILURE;
        }
    };

    if check {
        // --check: parse + summarise. Never prints key material, never
        // touches the network (endpoint resolution included).
        println!("config OK: {}", settings.config_path.display());
        for addr in &config.interface.addresses {
            println!("  address: {addr}");
        }
        for (i, dns) in config.interface.dns.iter().enumerate() {
            println!("  dns[{}]: {dns}", i + 1);
        }
        if let Some(port) = config.interface.listen_port {
            println!("  listen_port: {port}");
        }
        for (i, peer) in config.peers.iter().enumerate() {
            println!("  peer[{}]: endpoint {}", i + 1, peer.endpoint);
            for allowed in &peer.allowed_ips {
                println!("  peer[{}]: allowed_ip {allowed}", i + 1);
            }
        }
        return ExitCode::SUCCESS;
    }

    match run(settings, config).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(msg) => {
            eprintln!("wgproxyrs: {msg}");
            ExitCode::FAILURE
        }
    }
}

fn usage_error(msg: &str) -> ExitCode {
    eprintln!("error: {msg}\n\n{USAGE}");
    ExitCode::FAILURE
}

async fn run(settings: Settings, config: Config) -> Result<(), String> {
    // v0.1 drives a single peer (the first). Multi-peer = multiple tunnels
    // with AllowedIPs routing; the config parser already accepts them.
    let peer = config
        .peers
        .first()
        .ok_or("config has no [Peer] section")?
        .clone();

    // The one legitimate outside lookup (DESIGN.md §4.2): resolve the
    // WireGuard endpoint itself, once, at startup.
    let endpoint: SocketAddr = peer
        .endpoint
        .to_socket_addrs()
        .map_err(|e| format!("cannot resolve endpoint {}: {e}", peer.endpoint))?
        .next()
        .ok_or_else(|| format!("endpoint {} resolved to nothing", peer.endpoint))?;

    let udp_bind = match endpoint {
        SocketAddr::V4(_) => SocketAddr::new(
            IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            config.interface.listen_port.unwrap_or(0),
        ),
        SocketAddr::V6(_) => SocketAddr::new(
            IpAddr::V6(Ipv6Addr::UNSPECIFIED),
            config.interface.listen_port.unwrap_or(0),
        ),
    };
    let transport = UdpTransport::new(udp_bind, endpoint)
        .map_err(|e| format!("cannot bind UDP {udp_bind}: {e}"))?;

    let tunnel = WgTunnel::new(
        config.interface.private_key,
        peer.public_key,
        peer.preshared_key,
        peer.persistent_keepalive,
        Box::new(transport),
    );

    let mut allowed_ips = Vec::new();
    for p in &config.peers {
        allowed_ips.extend(p.allowed_ips.iter().copied());
    }
    let (engine, engine_thread) = spawn_engine(
        tunnel,
        EngineConfig {
            addresses: config.interface.addresses.clone(),
            dns_servers: config.interface.dns.clone(),
            allowed_ips,
        },
    );

    let socks_listener = tokio::net::TcpListener::bind(settings.bind)
        .await
        .map_err(|e| format!("cannot bind SOCKS5 {}: {e}", settings.bind))?;
    let socks_engine = engine.clone();
    let socks_task = tokio::spawn(async move {
        let _ = wgproxyrs::proxy::run_socks5_listener(socks_listener, socks_engine).await;
    });

    let mut http_task = None;
    if let Some(http_bind) = settings.http_bind {
        let http_listener = tokio::net::TcpListener::bind(http_bind)
            .await
            .map_err(|e| format!("cannot bind HTTP {http_bind}: {e}"))?;
        let http_engine = engine.clone();
        http_task = Some(tokio::spawn(async move {
            let _ = wgproxyrs::proxy::run_http_listener(http_listener, http_engine).await;
        }));
    }

    // Ready line: honest about tunnel state from the first second.
    let status = engine.status();
    println!(
        "wgproxyrs {} ready: socks5://{}{} peer={} tunnel={}",
        env!("CARGO_PKG_VERSION"),
        settings.bind,
        settings
            .http_bind
            .map(|a| format!(" http://{a}"))
            .unwrap_or_default(),
        endpoint,
        if status.up { "up" } else { "down" },
    );

    // Log tunnel state transitions (the readiness signal, human edition).
    let status_engine = engine.clone();
    let status_task = tokio::spawn(async move {
        let mut was_up = status_engine.status().up;
        loop {
            tokio::time::sleep(Duration::from_millis(500)).await;
            let s = status_engine.status();
            if s.up != was_up {
                was_up = s.up;
                match s.handshake_age {
                    Some(age) if s.up => {
                        println!("tunnel up (handshake age {}s)", age.as_secs())
                    }
                    _ => println!("tunnel down"),
                }
            }
        }
    });

    wait_for_shutdown().await;
    println!("wgproxyrs: shutting down");
    engine.stop();
    socks_task.abort();
    if let Some(task) = http_task {
        task.abort();
    }
    status_task.abort();
    let _ = engine_thread.join();
    Ok(())
}

async fn wait_for_shutdown() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        let mut term = signal(SignalKind::terminate()).expect("install SIGTERM handler");
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = term.recv() => {}
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}
