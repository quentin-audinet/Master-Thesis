use aya::programs::KProbe;
use aya::{include_bytes_aligned, Bpf};
use aya_log::BpfLogger;
use log::{info, warn, debug};
use tokio::signal;

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    env_logger::init();

    #[cfg(not(debug_assertions))]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/kprobe-hook"
    ))?;
    if let Err(e) = BpfLogger::init(&mut bpf) {
        // This can happen if you remove all log statements from your eBPF program.
        warn!("failed to initialize eBPF logger: {}", e);
    }
    let program: &mut KProbe = bpf.program_mut("kprobe_hook").unwrap().try_into()?;
    program.load()?;
    program.attach("tcp_connect", 0)?;

    info!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;
    info!("Exiting...");

    Ok(())
}
