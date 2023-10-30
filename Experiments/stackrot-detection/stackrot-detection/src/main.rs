use aya::programs::KProbe;
use aya::maps::HashMap;
use aya::{include_bytes_aligned, Bpf};
use aya_log::BpfLogger;
use log::{info, warn, debug};
use tokio::signal;

use stackrot_detection_common::Programs;

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    env_logger::init();

    // Bump the memlock rlimit. This is needed for older kernels that don't use the
    // new memcg based accounting, see https://lwn.net/Articles/837122/
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {}", ret);
    }

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    #[cfg(debug_assertions)]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/debug/stackrot-detection"
    ))?;
    #[cfg(not(debug_assertions))]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/stackrot-detection"
    ))?;
    if let Err(e) = BpfLogger::init(&mut bpf) {
        // This can happen if you remove all log statements from your eBPF program.
        warn!("failed to initialize eBPF logger: {}", e);
    }
    let program_synchronize_rcu: &mut KProbe = bpf.program_mut("stackrot_detection_synchronize_rcu").unwrap().try_into()?;
    program_synchronize_rcu.load()?;
    program_synchronize_rcu.attach("synchronize_rcu", 0)?;

    let program_ext4_mkdir: &mut KProbe = bpf.program_mut("stackrot_detection_ext4_mkdir").unwrap().try_into()?;
    program_ext4_mkdir.load()?;
    program_ext4_mkdir.attach("ext4_mkdir", 0)?;

    let program_kfunction: &mut KProbe = bpf.program_mut("stackrot_detection_kfunction").unwrap().try_into()?;
    program_kfunction.load()?;
    program_kfunction.attach("filemap_map_pmd", 0)?;

    let mut marked_programs: HashMap<_, u16, Programs> = HashMap::try_from(bpf.map_mut("MARKED_PROGRAMS").unwrap())?;

    info!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;
    info!("Exiting...");

    Ok(())
}
