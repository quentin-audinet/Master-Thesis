use aya::maps::{Array, HashMap, RingBuf};
use aya::programs::KProbe;
use aya::{include_bytes_aligned, Bpf};
use aya_log::BpfLogger;
use log::{info, warn, debug};
use thesis_code_common::{ConditionStates::{self, *}, NodeCondition, RingData};
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
    
    // Declare all hooks here
    let program: &mut KProbe = bpf.program_mut("thesis_code").unwrap().try_into()?;
    program.load()?;
    program.attach("tcp_connect", 0)?;

    // Create the ring buffer
    let mut ring_buf = RingBuf::try_from(bpf.take_map("ARRAY").unwrap())?;

    // Create the Graph of Conditions.
    let mut condition_graph: Array<_, NodeCondition> = Array::try_from(bpf.take_map("CONDITION_GRAPH").unwrap())?;

    // TODO, fill the Graph
    condition_graph.set(0, &NodeCondition { value: 10}, 0)?;    // fake set
    condition_graph.set(3, &NodeCondition { value: 20}, 0)?;    // fake set


    // Create the porcess map
    let mut process_map: HashMap<_, u32, [ConditionStates; 16]> = HashMap::try_from(bpf.map_mut("PROCESS_CONDITIONS").unwrap())?;
    process_map.insert(1234, [WAITING,UNREACHABLE,UNREACHABLE,WAITING,UNREACHABLE,UNREACHABLE,UNREACHABLE,UNREACHABLE,UNREACHABLE,UNREACHABLE,UNREACHABLE,UNREACHABLE,UNREACHABLE,UNREACHABLE,UNREACHABLE,UNREACHABLE], 0)?;   // fake insert
    
    /*  TODO
        - Wait for signal from kernel
        KL ==> { PID, Condition Verified } ==> UL
        OnSignalReceived:
            1. Update condition
            2. Look for children
            5. Update Graph status and check if a vulnerability has been triggered

    */

    // When this thread is finished, the program should terminate
    // Ensure that every infinite loop finish when wait_for_ctrl_c terminates
    let wait_for_ctrl_c = tokio::spawn(async {
        info!("Waiting for Ctrl-C...");
        signal::ctrl_c().await.unwrap();
        info!("Exiting...");
    });

    // Listen for messages from the kernel
    loop {
        match (ring_buf).next() {
            Some(data) => {
                // TMP, test communication and array modifications
                let ptr = data.as_ptr() as *const RingData;
                let ring = unsafe { *ptr };
                info!("Received data {:?} from {}", ring.args, ring.pid);
                //process_map.insert(1234, [(ring.pid % 100) as u8;16], 0)?;
            },
            None => {}
        };
        // Exit when user pressed CTRL+C
        if wait_for_ctrl_c.is_finished() {
            break;
        }
    };
    Ok(())

}
