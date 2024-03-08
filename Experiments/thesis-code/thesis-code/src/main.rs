use aya::maps::RingBuf;
use aya::programs::KProbe;
use aya::{include_bytes_aligned, Bpf};
use aya_log::BpfLogger;
use log::{info, warn, debug};
use thesis_code_common::RingData;
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
        "../../target/bpfel-unknown-none/debug/thesis-code"
    ))?;
    #[cfg(not(debug_assertions))]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/thesis-code"
    ))?;
    if let Err(e) = BpfLogger::init(&mut bpf) {
        // This can happen if you remove all log statements from your eBPF program.
        warn!("failed to initialize eBPF logger: {}", e);
    }

    /*  TODO
        - Load conditions in a shared Graph between ULand and KLand 
        - Create the KProbes for each kernel function to hook
        - Map : Process -> Graph status
    */

    
    let program: &mut KProbe = bpf.program_mut("thesis_code").unwrap().try_into()?;
    program.load()?;
    program.attach("tcp_connect", 0)?;
    let mut ring_buf = RingBuf::try_from(bpf.map_mut("ARRAY").unwrap()).unwrap();


    /*  TODO
        - Wait from signal from kernel
        KL ==> { PID, KFUNC, ARGS } ==> UL
        OnSignalReceived:
            1. Get Process from PID
            2. Check if PID is registered, if not add an entry
            3. Check if some current condition rely on KFUNC
            4. Check if the condition is satisfied using ARGS
            5. Update Graph status and check if a vulnerability has been triggered

    */

    // When this thread is finished, the program should terminate
    // Ensure that every infinite loop finish when wait_for_ctrl_c terminates
    let wait_for_ctrl_c = tokio::spawn(async {
        info!("Waiting for Ctrl-C...");
        signal::ctrl_c().await.unwrap();
        info!("Exiting...");
    });

    loop {
        match (ring_buf).next() {
            Some(data) => {
                let ptr = data.as_ptr() as *const RingData;
                let ring = unsafe { *ptr };
                info!("Received data {:?} from {}", ring.args, ring.pid);
            },
            None => {}
        };
        if wait_for_ctrl_c.is_finished() {
            break;
        }
    };
    Ok(())

}
