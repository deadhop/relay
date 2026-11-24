//! The binary itself: exit codes, and a clean stop on SIGTERM and SIGINT.

use std::io::{BufRead, BufReader};
use std::process::{Command, Stdio};

const KEY: &str = "5c1e8f4ab2d3e60c7a9b1f2e3d4c5b6a79881726354a5b6c7d8e9fa0b1c2d3e4";

fn relay() -> Command {
    let mut c = Command::new(env!("CARGO_BIN_EXE_deadhop-relay"));
    // Not env_clear(): coverage runs pass LLVM_PROFILE_FILE through the environment.
    for (k, _) in std::env::vars().filter(|(k, _)| k.starts_with("DEADHOP_RELAY_")) {
        c.env_remove(k);
    }
    c.env("DEADHOP_RELAY_LISTEN", "127.0.0.1:0")
        .env("DEADHOP_RELAY_STATS_LISTEN", "127.0.0.1:0");
    c
}

#[test]
fn refuses_to_start_without_a_whitelist() {
    let out = relay().output().unwrap();
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).contains("does not start without one"));
}

#[test]
fn version_help_and_unknown_commands() {
    let out = relay().arg("version").output().unwrap();
    assert!(String::from_utf8_lossy(&out.stdout).starts_with("deadhop-relay "));
    assert!(String::from_utf8_lossy(&relay().arg("help").output().unwrap().stdout).contains("usage:"));
    assert_eq!(relay().arg("nope").output().unwrap().status.code(), Some(2));
}

#[test]
fn reads_the_whitelist_from_a_file() {
    let dir = std::env::temp_dir().join(format!("deadhop-relay-test-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let file = dir.join("whitelist");
    std::fs::write(&file, format!("# operators\ninvoices={KEY}\n")).unwrap();
    let out = relay()
        .arg("check")
        .env("DEADHOP_RELAY_WHITELIST_FILE", &file)
        .output()
        .unwrap();
    assert!(String::from_utf8_lossy(&out.stdout).contains("whitelist     invoices: npub1"));
}

#[test]
fn check_prints_the_configuration() {
    let out = relay()
        .arg("check")
        .env("DEADHOP_RELAY_WHITELIST", format!("admin={KEY}"))
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    assert!(stdout.contains("whitelist     admin: npub1") && stdout.contains("mode          whitelist only"));
}

#[test]
fn check_prints_public_mode() {
    let out = relay().arg("check").env("DEADHOP_RELAY_PUBLIC", "on").output().unwrap();
    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    assert!(
        stdout.contains("mode          public: ContextVM traffic for any key"),
        "{stdout}"
    );
    assert!(!stdout.contains("whitelist "), "{stdout}");
}

fn stops_on(signal: &str, env: (&str, &str)) {
    let mut child = relay().env(env.0, env.1).stderr(Stdio::piped()).spawn().unwrap();
    let mut lines = BufReader::new(child.stderr.take().unwrap()).lines();
    let first = lines.next().unwrap().unwrap();
    assert!(first.contains("listening on 127.0.0.1:"), "{first}");
    let mode = if env.0 == "DEADHOP_RELAY_PUBLIC" {
        "for any key (public), 0 whitelisted"
    } else {
        "for whitelisted keys only, 1 whitelisted"
    };
    assert!(first.contains(mode), "{first}");
    assert!(lines.next().unwrap().unwrap().contains("operator page"));
    assert!(Command::new("kill")
        .args([signal, &child.id().to_string()])
        .status()
        .unwrap()
        .success());
    assert!(lines.next().unwrap().unwrap().contains("shutting down"));
    assert_eq!(child.wait().unwrap().code(), Some(0));
}

#[test]
fn stops_on_sigterm() {
    stops_on("-TERM", ("DEADHOP_RELAY_WHITELIST", KEY));
}

#[test]
fn stops_on_sigint() {
    stops_on("-INT", ("DEADHOP_RELAY_PUBLIC", "on"));
}

#[test]
fn a_busy_port_exits_with_1() {
    let busy = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = busy.local_addr().unwrap().to_string();
    let out = relay()
        .env("DEADHOP_RELAY_WHITELIST", KEY)
        .env("DEADHOP_RELAY_LISTEN", addr)
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&out.stderr).contains("cannot listen"));
}
