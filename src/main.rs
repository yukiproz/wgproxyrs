//! wgproxyrs CLI.
//!
//! ```text
//! wgproxyrs --config <path> [--bind 127.0.0.1:1080] [--http-bind <addr>]
//!           [--info-bind <addr>] [--tcp-tunnel <listen>=<target>]...
//!           [--proxy-user <u> --proxy-pass <p>]
//!           [--daemon] [--pidfile <path>] [--log-file <path>] [--silent]
//! wgproxyrs --config <path> --check     # validate config, no network
//! wgproxyrs status --info <addr>        # tunnel up? exit 0 iff up
//! wgproxyrs genkey                      # fresh WireGuard keypair
//! ```

use std::io::{Read as _, Write as _};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

use wgproxyrs::config::{Config, Settings, TcpTunnel};
use wgproxyrs::info::{run_info_listener, status_is_up};
use wgproxyrs::keys::generate_keypair;
use wgproxyrs::proxy::{
    ProxyAuth, ProxyCtx, Target, run_http_listener, run_socks5_listener, run_tcp_tunnel_listener,
};
use wgproxyrs::stack::{EngineConfig, PeerTunnel, spawn_engine};
use wgproxyrs::tunnel::{Transport, UdpTransport, WgTunnel, shared_udp_transports};

const USAGE: &str = "\
wgproxyrs — userspace WireGuard client exposed as a SOCKS5/HTTP proxy

Usage:
  wgproxyrs --config <PATH> [OPTIONS]
  wgproxyrs status --info <ADDR>
  wgproxyrs genkey

Options:
  -c, --config <PATH>   Stock WireGuard .conf file
      --bind <ADDR>     SOCKS5 bind address [default: 127.0.0.1:1080]
      --http-bind <ADDR>  Also serve HTTP CONNECT on this address
      --info-bind <ADDR>  Also serve tunnel health as HTTP JSON there
      --tcp-tunnel <L>=<T>  Forward local listen <L> through the tunnel
                            to target <T> (host:port); repeatable
      --proxy-user <USER>   Require proxy authentication (with --proxy-pass)
      --proxy-pass <PASS>   SOCKS5: RFC 1929; HTTP: Basic Proxy-Authorization
      --daemon          Detach into the background (unix)
      --pidfile <PATH>  Daemon pidfile [default: ./<config-stem>.pid]
      --log-file <PATH> Daemon stdout/stderr redirect target
      --silent          Suppress informational logging
      --check           Validate the config and exit (no network use)
  -h, --help            Print this help
  -v, --version         Print version
";

/// Daemon-related flags, consumed before the async runtime exists
/// (fork() is only safe while the process is single-threaded).
#[derive(Debug, Default)]
struct DaemonOpts {
    daemon: bool,
    pidfile: Option<PathBuf>,
    log_file: Option<PathBuf>,
    silent: bool,
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();

    if args.first().map(String::as_str) == Some("genkey") {
        let kp = generate_keypair();
        println!("PrivateKey = {}", kp.private_key_b64);
        println!("PublicKey = {}", kp.public_key_b64);
        return ExitCode::SUCCESS;
    }
    if args.first().map(String::as_str) == Some("status") {
        return status_command(&args[1..]);
    }

    let mut config_path: Option<PathBuf> = None;
    let mut settings_extra = SettingsExtra::default();
    let mut daemon = DaemonOpts::default();
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
            "--daemon" => daemon.daemon = true,
            "--silent" => daemon.silent = true,
            "-c" | "--config" => {
                i += 1;
                match args.get(i) {
                    Some(path) => config_path = Some(PathBuf::from(path)),
                    None => return usage_error("--config needs a path"),
                }
            }
            "--pidfile" => {
                i += 1;
                match args.get(i) {
                    Some(path) => daemon.pidfile = Some(PathBuf::from(path)),
                    None => return usage_error("--pidfile needs a path"),
                }
            }
            "--log-file" => {
                i += 1;
                match args.get(i) {
                    Some(path) => daemon.log_file = Some(PathBuf::from(path)),
                    None => return usage_error("--log-file needs a path"),
                }
            }
            "--bind" => {
                i += 1;
                match args.get(i).and_then(|v| v.parse::<SocketAddr>().ok()) {
                    Some(addr) => settings_extra.bind = Some(addr),
                    None => return usage_error("--bind needs an IP:port address"),
                }
            }
            "--http-bind" => {
                i += 1;
                match args.get(i).and_then(|v| v.parse::<SocketAddr>().ok()) {
                    Some(addr) => settings_extra.http_bind = Some(addr),
                    None => return usage_error("--http-bind needs an IP:port address"),
                }
            }
            "--info-bind" => {
                i += 1;
                match args.get(i).and_then(|v| v.parse::<SocketAddr>().ok()) {
                    Some(addr) => settings_extra.info_bind = Some(addr),
                    None => return usage_error("--info-bind needs an IP:port address"),
                }
            }
            "--tcp-tunnel" => {
                i += 1;
                let Some(spec) = args.get(i) else {
                    return usage_error("--tcp-tunnel needs <listen>=<target>");
                };
                let Some((listen, target)) = spec.split_once('=') else {
                    return usage_error("--tcp-tunnel expects <listen>=<target>");
                };
                let Ok(listen) = listen.parse::<SocketAddr>() else {
                    return usage_error("--tcp-tunnel listen must be an IP:port address");
                };
                if target.is_empty() {
                    return usage_error("--tcp-tunnel target is empty");
                }
                settings_extra.tcp_tunnels.push(TcpTunnel {
                    listen,
                    target: target.to_string(),
                });
            }
            "--proxy-user" => {
                i += 1;
                match args.get(i) {
                    Some(v) => settings_extra.proxy_user = Some(v.clone()),
                    None => return usage_error("--proxy-user needs a value"),
                }
            }
            "--proxy-pass" => {
                i += 1;
                match args.get(i) {
                    Some(v) => settings_extra.proxy_pass = Some(v.clone()),
                    None => return usage_error("--proxy-pass needs a value"),
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
    if let Some(addr) = settings_extra.bind {
        settings.bind = addr;
    }
    settings.http_bind = settings_extra.http_bind;
    settings.info_bind = settings_extra.info_bind;
    settings.tcp_tunnels = settings_extra.tcp_tunnels;
    settings.proxy_user = settings_extra.proxy_user;
    settings.proxy_pass = settings_extra.proxy_pass;
    if let Err(e) = settings.validate() {
        return usage_error(&e);
    }

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

    // Daemonize BEFORE building the runtime: fork() is only safe while
    // the process is single-threaded.
    let pidfile = if daemon.daemon {
        let pidfile = daemon
            .pidfile
            .clone()
            .unwrap_or_else(|| default_pidfile(&settings.config_path));
        if let Err(e) = daemonize(daemon.log_file.as_deref(), &pidfile) {
            eprintln!("wgproxyrs: cannot daemonize: {e}");
            return ExitCode::FAILURE;
        }
        Some(pidfile)
    } else {
        None
    };

    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("wgproxyrs: cannot start async runtime: {e}");
            return ExitCode::FAILURE;
        }
    };
    let result = runtime.block_on(run(settings, config, daemon.silent));
    if let Some(pidfile) = &pidfile {
        let _ = std::fs::remove_file(pidfile);
    }
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(msg) => {
            eprintln!("wgproxyrs: {msg}");
            ExitCode::FAILURE
        }
    }
}

/// CLI values that land in [`Settings`], collected during parsing.
#[derive(Debug, Default)]
struct SettingsExtra {
    bind: Option<SocketAddr>,
    http_bind: Option<SocketAddr>,
    info_bind: Option<SocketAddr>,
    tcp_tunnels: Vec<TcpTunnel>,
    proxy_user: Option<String>,
    proxy_pass: Option<String>,
}

fn usage_error(msg: &str) -> ExitCode {
    eprintln!("error: {msg}\n\n{USAGE}");
    ExitCode::FAILURE
}

/// `wgproxyrs status --info <addr>` — a launcher's one-liner: print the
/// info endpoint's JSON and exit 0 iff it reports the tunnel up, 1 when
/// it reports down, 2 when the endpoint cannot be reached.
fn status_command(args: &[String]) -> ExitCode {
    let mut info_addr: Option<String> = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--info" => {
                i += 1;
                match args.get(i) {
                    Some(v) => info_addr = Some(v.clone()),
                    None => {
                        eprintln!("error: --info needs an address");
                        return ExitCode::from(2);
                    }
                }
            }
            other => {
                eprintln!("error: unknown status argument '{other}'");
                return ExitCode::from(2);
            }
        }
        i += 1;
    }
    let Some(addr) = info_addr else {
        eprintln!("usage: wgproxyrs status --info <addr>");
        return ExitCode::from(2);
    };
    match fetch_info(&addr) {
        Ok(body) => {
            println!("{body}");
            if status_is_up(&body) {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(1)
            }
        }
        Err(e) => {
            eprintln!("error: cannot reach info endpoint at {addr}: {e}");
            ExitCode::from(2)
        }
    }
}

/// Minimal blocking HTTP GET of the info endpoint (the status command
/// runs outside the async runtime on purpose).
fn fetch_info(addr: &str) -> std::io::Result<String> {
    let target: SocketAddr = addr
        .parse()
        .ok()
        .or_else(|| addr.to_socket_addrs().ok().and_then(|mut i| i.next()))
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidInput, "bad address"))?;
    let mut stream = TcpStream::connect_timeout(&target, Duration::from_secs(5))?;
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    stream.write_all(b"GET / HTTP/1.1\r\nHost: wgproxyrs\r\nConnection: close\r\n\r\n")?;
    let mut raw = String::new();
    stream.read_to_string(&mut raw)?;
    let body = raw
        .split_once("\r\n\r\n")
        .map(|(_, b)| b.trim().to_string())
        .ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, "malformed HTTP response")
        })?;
    Ok(body)
}

fn default_pidfile(config_path: &Path) -> PathBuf {
    let stem = config_path
        .file_stem()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| "wgproxyrs".to_string());
    PathBuf::from(format!("./{stem}.pid"))
}

fn warn_wide_bind(what: &str, addr: SocketAddr, auth_configured: bool) {
    if !addr.ip().is_loopback() {
        if auth_configured {
            eprintln!("warning: {what} is bound to non-loopback address {addr} (proxy auth is ON)");
        } else {
            eprintln!(
                "WARNING: {what} is bound to non-loopback address {addr} WITHOUT proxy \
                 authentication — anyone who can reach this port can use your tunnel. \
                 Set --proxy-user/--proxy-pass or bind to loopback."
            );
        }
    }
}

/// Small logging gate for informational lines (`--silent`).
struct Log {
    silent: bool,
}
impl Log {
    fn info(&self, msg: String) {
        if !self.silent {
            println!("{msg}");
        }
    }
}

async fn run(settings: Settings, config: Config, silent: bool) -> Result<(), String> {
    let log = Log { silent };
    if config.peers.is_empty() {
        return Err("config has no [Peer] section".into());
    }

    // The one legitimate outside lookup (DESIGN.md §4.2): resolve the
    // WireGuard endpoints themselves, once, at startup.
    let mut endpoints: Vec<SocketAddr> = Vec::with_capacity(config.peers.len());
    for peer in &config.peers {
        let endpoint: SocketAddr = peer
            .endpoint
            .to_socket_addrs()
            .map_err(|e| format!("cannot resolve endpoint {}: {e}", peer.endpoint))?
            .next()
            .ok_or_else(|| format!("endpoint {} resolved to nothing", peer.endpoint))?;
        endpoints.push(endpoint);
    }

    // One tunnel per peer. A single peer keeps the dedicated
    // UdpTransport (the kernel-interop proven path); multiple peers
    // share one UDP socket with per-source dispatch, mirroring
    // WireGuard's one-listen-port-per-interface model.
    let listen_port = config.interface.listen_port.unwrap_or(0);
    let transports: Vec<Box<dyn Transport>> = if endpoints.len() == 1 {
        let udp_bind = match endpoints[0] {
            SocketAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), listen_port),
            SocketAddr::V6(_) => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), listen_port),
        };
        let transport = UdpTransport::new(udp_bind, endpoints[0])
            .map_err(|e| format!("cannot bind UDP {udp_bind}: {e}"))?;
        vec![Box::new(transport) as Box<dyn Transport>]
    } else {
        let udp_bind = SocketAddr::new(
            if endpoints.iter().all(|e| e.is_ipv6()) {
                IpAddr::V6(Ipv6Addr::UNSPECIFIED)
            } else {
                IpAddr::V4(Ipv4Addr::UNSPECIFIED)
            },
            listen_port,
        );
        shared_udp_transports(udp_bind, &endpoints)
            .map_err(|e| format!("cannot bind shared UDP {udp_bind}: {e}"))?
            .into_iter()
            .map(|t| Box::new(t) as Box<dyn Transport>)
            .collect()
    };

    let peer_tunnels: Vec<PeerTunnel> = config
        .peers
        .iter()
        .zip(transports)
        .map(|(peer, transport)| PeerTunnel {
            tunnel: WgTunnel::new(
                config.interface.private_key,
                peer.public_key,
                peer.preshared_key,
                peer.persistent_keepalive,
                transport,
            ),
            allowed_ips: peer.allowed_ips.clone(),
            endpoint: peer.endpoint.clone(),
        })
        .collect();

    let (engine, engine_thread) = spawn_engine(
        peer_tunnels,
        EngineConfig {
            addresses: config.interface.addresses.clone(),
            dns_servers: config.interface.dns.clone(),
        },
    );

    let auth = match (&settings.proxy_user, &settings.proxy_pass) {
        (Some(user), Some(pass)) => Some(ProxyAuth {
            user: user.clone(),
            pass: pass.clone(),
        }),
        _ => None,
    };
    let ctx = ProxyCtx::new(engine.clone()).with_auth(auth.clone());

    let socks_listener = tokio::net::TcpListener::bind(settings.bind)
        .await
        .map_err(|e| format!("cannot bind SOCKS5 {}: {e}", settings.bind))?;
    warn_wide_bind("SOCKS5 proxy", settings.bind, auth.is_some());
    let socks_engine = ctx.clone();
    let socks_task = tokio::spawn(async move {
        let _ = run_socks5_listener(socks_listener, socks_engine).await;
    });

    let mut http_task = None;
    if let Some(http_bind) = settings.http_bind {
        let http_listener = tokio::net::TcpListener::bind(http_bind)
            .await
            .map_err(|e| format!("cannot bind HTTP {http_bind}: {e}"))?;
        warn_wide_bind("HTTP proxy", http_bind, auth.is_some());
        let http_ctx = ctx.clone();
        http_task = Some(tokio::spawn(async move {
            let _ = run_http_listener(http_listener, http_ctx).await;
        }));
    }

    let mut info_task = None;
    if let Some(info_bind) = settings.info_bind {
        let info_listener = tokio::net::TcpListener::bind(info_bind)
            .await
            .map_err(|e| format!("cannot bind info {info_bind}: {e}"))?;
        if !info_bind.ip().is_loopback() {
            eprintln!(
                "WARNING: info endpoint is bound to non-loopback address {info_bind} — \
                 it has no authentication and reveals tunnel state to anyone who can \
                 reach it."
            );
        }
        let info_engine = engine.clone();
        info_task = Some(tokio::spawn(async move {
            let _ = run_info_listener(info_listener, info_engine).await;
        }));
    }

    let mut tunnel_tasks = Vec::new();
    for tunnel in &settings.tcp_tunnels {
        let Some(target) = Target::parse(&tunnel.target) else {
            eprintln!(
                "wgproxyrs: warning: skipping TCP tunnel with unparsable target: {}",
                tunnel.target
            );
            continue;
        };
        let listener = tokio::net::TcpListener::bind(tunnel.listen)
            .await
            .map_err(|e| format!("cannot bind TCP tunnel {}: {e}", tunnel.listen))?;
        if !tunnel.listen.ip().is_loopback() {
            eprintln!(
                "WARNING: TCP tunnel is bound to non-loopback address {} — it has no \
                 authentication and forwards into your tunnel.",
                tunnel.listen
            );
        }
        let tunnel_ctx = ctx.clone();
        tunnel_tasks.push(tokio::spawn(async move {
            let _ = run_tcp_tunnel_listener(listener, target, tunnel_ctx).await;
        }));
    }

    // Ready line: honest about tunnel state from the first second.
    let status = engine.status();
    let mut extras = String::new();
    if let Some(a) = settings.http_bind {
        extras.push_str(&format!(" http://{a}"));
    }
    if let Some(a) = settings.info_bind {
        extras.push_str(&format!(" info://{a}"));
    }
    for tunnel in &settings.tcp_tunnels {
        extras.push_str(&format!(" tcp:{}->{}", tunnel.listen, tunnel.target));
    }
    if auth.is_some() {
        extras.push_str(" auth=on");
    }
    log.info(format!(
        "wgproxyrs {} ready: socks5://{}{} peers={} tunnel={}",
        env!("CARGO_PKG_VERSION"),
        settings.bind,
        extras,
        endpoints
            .iter()
            .map(|e| e.to_string())
            .collect::<Vec<_>>()
            .join(","),
        if status.up { "up" } else { "down" },
    ));

    // Log tunnel state transitions (the readiness signal, human edition).
    let status_engine = engine.clone();
    let status_silent = silent;
    let status_task = tokio::spawn(async move {
        let slog = Log {
            silent: status_silent,
        };
        let mut was_up = status_engine.status().up;
        loop {
            tokio::time::sleep(Duration::from_millis(500)).await;
            let s = status_engine.status();
            if s.up != was_up {
                was_up = s.up;
                match s.handshake_age {
                    Some(age) if s.up => {
                        let peers_up = s.peers.iter().filter(|p| p.up).count();
                        slog.info(format!(
                            "tunnel up ({}/{} peers, handshake age {}s)",
                            peers_up,
                            s.peers.len(),
                            age.as_secs()
                        ));
                    }
                    _ => slog.info("tunnel down".into()),
                }
            }
        }
    });

    wait_for_shutdown().await;
    log.info("wgproxyrs: shutting down".into());
    engine.stop();
    socks_task.abort();
    if let Some(task) = http_task {
        task.abort();
    }
    if let Some(task) = info_task {
        task.abort();
    }
    for task in tunnel_tasks {
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

// ---------------------------------------------------------------------------
// Daemon mode (unix): fork + setsid + redirect stdio + pidfile, with a
// readiness pipe so the parent only reports success once the child is
// actually detached and the pidfile exists.
// ---------------------------------------------------------------------------

#[cfg(unix)]
fn daemonize(log_file: Option<&Path>, pidfile: &Path) -> Result<(), String> {
    use std::os::unix::io::RawFd;

    let mut fds: [RawFd; 2] = [-1, -1];
    if unsafe { libc::pipe(fds.as_mut_ptr()) } != 0 {
        return Err(format!("pipe: {}", std::io::Error::last_os_error()));
    }
    let (read_fd, write_fd) = (fds[0], fds[1]);

    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return Err(format!("fork: {}", std::io::Error::last_os_error()));
    }
    if pid > 0 {
        // Parent: wait for the child's readiness byte, then exit so the
        // shell gets its prompt back. '1' = detached OK; anything else
        // (or EOF) = the bytes after the first are the error message.
        unsafe { libc::close(write_fd) };
        let mut msg = Vec::new();
        let mut buf = [0u8; 256];
        loop {
            let n =
                unsafe { libc::read(read_fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
            if n <= 0 {
                break;
            }
            msg.extend_from_slice(&buf[..n as usize]);
        }
        unsafe { libc::close(read_fd) };
        if msg.first() == Some(&b'1') {
            std::process::exit(0);
        }
        let text = if msg.len() > 1 {
            String::from_utf8_lossy(&msg[1..]).into_owned()
        } else {
            String::new()
        };
        return Err(if text.is_empty() {
            "child failed during daemon setup".into()
        } else {
            text
        });
    }

    // Child: report setup results back through the pipe.
    let report = |ok: bool, text: &str| {
        let mut payload = vec![if ok { b'1' } else { b'0' }];
        payload.extend_from_slice(text.as_bytes());
        unsafe {
            let _ = libc::write(
                write_fd,
                payload.as_ptr() as *const libc::c_void,
                payload.len(),
            );
            libc::close(write_fd);
            libc::close(read_fd);
        }
    };
    let fail = |text: String| {
        report(false, &text);
        std::process::exit(1);
    };

    if unsafe { libc::setsid() } < 0 {
        fail(format!("setsid: {}", std::io::Error::last_os_error()));
    }

    // Redirect stdio: stdin from /dev/null; stdout/stderr to the log
    // file (append) or /dev/null when no log file was requested.
    let devnull = unsafe { libc::open(c"/dev/null".as_ptr(), libc::O_RDWR) };
    if devnull < 0 {
        fail(format!(
            "open /dev/null: {}",
            std::io::Error::last_os_error()
        ));
    }
    let out_fd = match log_file {
        Some(path) => {
            let cpath = match std::ffi::CString::new(path.as_os_str().to_string_lossy().as_bytes())
            {
                Ok(p) => p,
                Err(_) => fail("log file path contains a NUL byte".into()),
            };
            let fd = unsafe {
                libc::open(
                    cpath.as_ptr(),
                    libc::O_WRONLY | libc::O_CREAT | libc::O_APPEND,
                    0o644,
                )
            };
            if fd < 0 {
                fail(format!(
                    "open log file {}: {}",
                    path.display(),
                    std::io::Error::last_os_error()
                ));
            }
            fd
        }
        None => devnull,
    };
    unsafe {
        libc::dup2(devnull, 0);
        libc::dup2(out_fd, 1);
        libc::dup2(out_fd, 2);
        if out_fd > 2 {
            libc::close(out_fd);
        }
        if devnull > 2 && devnull != out_fd {
            libc::close(devnull);
        }
    }

    // The pidfile holds the DAEMON's pid (this process, post-fork).
    let my_pid = std::process::id();
    if let Err(e) = std::fs::write(pidfile, format!("{my_pid}\n")) {
        fail(format!("write pidfile {}: {e}", pidfile.display()));
    }
    report(true, "");
    Ok(())
}

#[cfg(not(unix))]
fn daemonize(_log_file: Option<&Path>, _pidfile: &Path) -> Result<(), String> {
    Err("--daemon is only supported on unix".into())
}
