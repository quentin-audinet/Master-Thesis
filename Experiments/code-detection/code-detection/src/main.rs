use aya::programs::{KProbe, self};
use aya::{include_bytes_aligned, Bpf};
use aya_log::BpfLogger;
use code_detection_common::{Node, LinkedList};
use log::{info, warn, debug};
use tokio::signal;

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
        "../../target/bpfel-unknown-none/debug/code-detection"
    ))?;
    #[cfg(not(debug_assertions))]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/code-detection"
    ))?;
    if let Err(e) = BpfLogger::init(&mut bpf) {
        // This can happen if you remove all log statements from your eBPF program.
        warn!("failed to initialize eBPF logger: {}", e);
    }

    let function_list = ["tcp_connect", "tcp_v4_rcv"];

    for f in function_list {
        let mut bpf_fun = "code_detection_".to_owned();
        bpf_fun.push_str(f);
        let program: &mut KProbe = bpf.program_mut(&bpf_fun).unwrap().try_into()?;
        program.load()?;
        program.attach(&f, 0)?;
    }
 
    let l1 = LinkedList::new(Node::new(5));

    info!("********************** l1: {}", l1.get_current_data());

    info!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;
    info!("Exiting...");

    Ok(())
}
