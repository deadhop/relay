//! deadhop relay: a small Nostr relay that carries only deadhop's ContextVM
//! traffic (requests to, and replies from, the keys its operator whitelists),
//! or, in public mode, ContextVM traffic for any key.

pub mod config;
pub mod event;
pub mod filter;
pub mod http;
pub mod hub;
pub mod limits;
pub mod networks;
pub mod server;
pub mod session;
pub mod state;
pub mod stats;
pub mod store;
pub mod web;

#[cfg(test)]
mod tests;

use config::{npub, Config};

pub const USAGE: &str = "deadhop-relay: a Nostr relay for deadhop's ContextVM traffic

usage:
  deadhop-relay [serve]   run the relay
  deadhop-relay check     read the configuration, print what it says, and exit
  deadhop-relay version   print the version

Configuration comes from DEADHOP_RELAY_* environment variables. A whitelist is
required: DEADHOP_RELAY_WHITELIST=invoices=npub1...,admin=npub1...
unless the relay is public (DEADHOP_RELAY_PUBLIC=on): ContextVM traffic for any key.
Also on Tor, I2P or FIPS: DEADHOP_RELAY_TOR_LISTEN and DEADHOP_RELAY_TOR_URLS (and I2P_, FIPS_).
Docs: https://deadhop.run/relay/docs/";

/// What `check` prints: the settings that matter, one per line.
pub fn summary(c: &Config) -> String {
    let mut s = format!("listen        {}\n", c.listen.map_or("off".into(), |a| a.to_string()));
    for a in &c.adapters {
        s += &format!(
            "{:<14}{} for {} (at most {} connections)\n",
            a.network.id(),
            a.listen,
            a.urls.join(", "),
            a.max_connections
        );
    }
    s += &format!(
        "operator page {}\n",
        c.stats_listen.map_or("off".into(), |a| a.to_string())
    );
    s += &format!(
        "mode          {}\n",
        if c.public {
            "public: ContextVM traffic for any key"
        } else {
            "whitelist only"
        }
    );
    for (k, label) in c.whitelist.entries() {
        s += &format!("whitelist     {label}: {}\n", npub(k));
    }
    let l = &c.limits;
    s += &format!(
        "limits        {} connections (+{} reserved), {} per address, {} public events/min per address, pow {}\n",
        l.max_connections, l.reserved_connections, l.connections_per_ip, l.public_events_per_min, l.min_pow
    );
    s
}

/// Wait for Ctrl-C or SIGTERM.
pub async fn signalled() {
    let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()).expect("signal handler");
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {}
        _ = term.recv() => {}
    }
}

/// Run the relay until signalled.
pub async fn serve(cfg: Config) -> u8 {
    let r = match server::start(cfg).await {
        Ok(r) => r,
        Err(e) => {
            eprintln!("deadhop-relay: cannot listen: {e}");
            return 1;
        }
    };
    let keys = r.shared.cfg.whitelist.len();
    let mode = if r.shared.cfg.public {
        "any key (public)"
    } else {
        "whitelisted keys only"
    };
    eprintln!(
        "deadhop-relay {}: listening on {} for {mode}, {keys} whitelisted",
        web::VERSION,
        r.addr
    );
    for (n, a) in r.listeners.iter().filter(|(n, _)| *n != networks::Network::Clearnet) {
        let urls = r.shared.cfg.adapter(*n).map(|x| x.urls.join(", ")).unwrap_or_default();
        eprintln!("deadhop-relay: {} on {a} for {urls}", n.label());
    }
    if let Some(a) = r.stats_addr {
        eprintln!("deadhop-relay: operator page on http://{a}/");
    }
    signalled().await;
    eprintln!("deadhop-relay: shutting down");
    r.stop().await;
    0
}

/// The command line. Returns the exit code.
pub fn cli(args: &[String], get: &dyn Fn(&str) -> Option<String>) -> u8 {
    let cmd = args.get(1).map_or("serve", String::as_str);
    match cmd {
        "version" | "--version" | "-V" => {
            println!("deadhop-relay {}", web::VERSION);
            0
        }
        "help" | "--help" | "-h" => {
            println!("{USAGE}");
            0
        }
        "serve" | "check" => {
            let cfg = match Config::from_env(get, &|p| std::fs::read_to_string(p)) {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("deadhop-relay: {e}");
                    return 2;
                }
            };
            if cmd == "check" {
                print!("{}", summary(&cfg));
                return 0;
            }
            let rt = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .expect("a tokio runtime");
            rt.block_on(serve(cfg))
        }
        other => {
            eprintln!("deadhop-relay: unknown command '{other}'\n\n{USAGE}");
            2
        }
    }
}
