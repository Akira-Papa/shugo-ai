use clap::Parser;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
fn main() {
    let args = shugo_core::cli::Cli::parse();
    let json = args.json;
    let cancelled = Arc::new(AtomicBool::new(false));
    let flag = cancelled.clone();
    if ctrlc::set_handler(move || {
        flag.store(true, Ordering::SeqCst);
    })
    .is_err()
    {
        eprintln!("Unable to install interrupt handler");
        std::process::exit(1);
    }
    if let Err(error) = shugo_core::cli::execute(args, cancelled) {
        if json {
            eprintln!("{}", serde_json::json!({"error":error}));
        } else {
            eprintln!("shugo: {error}");
        }
        std::process::exit(1);
    }
}
