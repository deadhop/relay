//! deadhop-relay: all logic is in the library.

fn main() -> std::process::ExitCode {
    let args: Vec<String> = std::env::args().collect();
    std::process::ExitCode::from(deadhop_relay::cli(&args, &|k| std::env::var(k).ok()))
}
