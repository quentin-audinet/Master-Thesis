use aya::maps::{Array, HashMap, RingBuf};
use aya::programs::KProbe;
use aya::{include_bytes_aligned, Bpf};
use aya_log::BpfLogger;
use log::{info, warn, debug};
use thesis_code_common::{get_based_graph, CheckTypes, ConditionTypes, CONDITION_NUM};
use thesis_code_common::{ConditionStates, NodeCondition, RingData};
use tokio::signal;


pub trait ToSlice {
    
    fn to_32bytes(&self) -> [u8;32];
}

impl ToSlice for &str {
    fn to_32bytes(&self) -> [u8;32] {
        let mut buff: [u8;32] = [0;32];
    
        for i in 0..self.len().min(32) {
            buff[i] = self.as_bytes()[i];
        }
        buff
    }
}

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
        let function_list = [/* $KFUNCTIONS_PLACEHOLDER$ */];

        for f in function_list {
            let mut bpf_fun = "thesis_code".to_owned();
            bpf_fun.push_str(f);
            let program: &mut KProbe = bpf.program_mut(&bpf_fun).unwrap().try_into()?;
            program.load()?;
            program.attach(&f, 0)?;
        }
    
        let program: &mut KProbe = bpf.program_mut("test").unwrap().try_into()?;
        program.load()?;
        program.attach("tcp_connect", 0)?;

    // Create the ring buffer
    let mut ring_buf = RingBuf::try_from(bpf.take_map("ARRAY").unwrap())?;

    // Create the Graph of Conditions.
    let mut condition_graph: Array<_, NodeCondition> = Array::try_from(bpf.take_map("CONDITION_GRAPH").unwrap())?;

/* $GRAPH_FILL_PLACEHOLDER$ */


    // Create the process map
    let mut process_map: HashMap<_, u32, [ConditionStates; CONDITION_NUM]> = HashMap::try_from(bpf.map_mut("PROCESS_CONDITIONS").unwrap())?;    

    //--- END OF INITIALISATION --- //


    /*  
        - Wait for signal from kernel
        KL ==> { PID, Condition Verified } ==> UL
        OnSignalReceived:
            1. Update condition
            2. For each children, look if parents have been verified, if so make it WAITING
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
            // If data is received, a condition should be updated
            Some(data) => {
                // Grab the data from the ring
                let ptr = data.as_ptr() as *const RingData;
                let ring = unsafe { *ptr };
                info!("[{}] Condition {} verified !", ring.pid, ring.condition);

                // Get the verified condition node 
                let condition = condition_graph.get(&(ring.condition as u32), 0)?;

                // Get the process graph
                let map_result = process_map.get(&ring.pid, 0);
                // Get the map and update the current condition
                let mut map = match map_result {
                    Ok(mut m) => {
                        m[ring.condition] = ConditionStates::VERIFIED;
                        m
                    },
                    Err(_) => {
                        let mut m = get_based_graph();
                        m[ring.condition] = ConditionStates::VERIFIED;
                        m
                    },
                };
                info!("MAP[0,3,8] [{},{},{}]", map[0] as u8, map[3] as u8, map[8] as u8);

                // Update any child if necessary
                for child_id in condition.children {
                    info!("\tChild n°{}",child_id);
                    let child = condition_graph.get(child_id, 0)?;
                    let parents = child.parents;
                    info!("Parents of {} are {:?}", child_id, parents);

                    
                    // Check if the new child is reachable ie all its parents are verified
                    let mut reachable = true;
                    for p in parents {
                        if !map[*p as usize].eq(&ConditionStates::VERIFIED) {
                            reachable = false;
                            info!("Parent {} still unverified", p);
                            break;
                        }
                    }
                    // If reachable update its state
                    if reachable {
                        map[*child_id as usize] = ConditionStates::WAITING;
                        // Check if the node isn't a trigger one
                        if child.node_type.eq(&ConditionTypes::TRIGGER) {
                            info!("EXPLOIT HAS BEEN TRIGGERED");
                        }
                    }
                }
                // Save the map
                process_map.insert(ring.pid, map, 0)?;
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
