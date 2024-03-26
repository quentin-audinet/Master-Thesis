#![no_std]
#![no_main]

use aya_bpf::{helpers::bpf_probe_read_kernel, macros::{kprobe, map}, maps::{lpm_trie::Key, Array, HashMap, RingBuf}, programs::ProbeContext, BpfContext};
use aya_log_ebpf::info;
use thesis_code_common::{get_based_graph, ConditionStates, NodeCondition, RingData, CONDITION_NUM};

mod conditions;
use conditions::check;

/*
    - Create a KProbe for each function (Try to have a pattern for future auto generation)
    - Map : Process -> Graph status
    Hook:
    - Get PID, kfunction name and args
    - Send to UL for analysis
*/

#[map(name = "ARRAY")]
static mut RING_BUFFER:RingBuf = RingBuf::with_byte_size(1024, 0);

// based graph loaded in UL from a config file
// max_entries could be change with some formating before compilation
#[map(name = "CONDITION_GRAPH")]
static mut CONDITION_GRAPH: Array<NodeCondition> = Array::<NodeCondition>::with_max_entries(CONDITION_NUM as u32, 0);


// Map each process to the current conditions.
// The size of the array must be the number of conditions (or at least)
#[map(name = "PROCESS_CONDITIONS")]
static mut PROCESS_CONDITION: HashMap<u32, [ConditionStates;CONDITION_NUM]> = HashMap::<u32, [ConditionStates; CONDITION_NUM]>::with_max_entries(4096, 0);


#[map(name = "CALL_HISTORY")]
static mut CALL_HISTORY: HashMap<[u8;36], u32> = HashMap::<[u8;36], u32>::with_max_entries(1024, 0);

// The global hook
fn hook(kfunction: &'static str, ctx: &ProbeContext) {

    let kfunction = kfunction.to_32bytes();

    // Get the key to the current call count
    let key = concat_kfunction_pid(&kfunction, ctx.pid());
    let history = unsafe { CALL_HISTORY.get(&key) };

    // Get the number of calls already performed
    let count = match history {
        Some(count) => {
            unsafe { if CALL_HISTORY.insert(&key, &(*count+1), 0).is_err() {
                info!(ctx, "ERROR: Updating count for pid {}", ctx.pid());
            } };
            *count+1
        },
        None => {
            unsafe { if CALL_HISTORY.insert(&key, &1, 0).is_err() {
                info!(ctx, "ERROR: Inserting count for pid {}", ctx.pid());
            }};
            1
        }
    };

    let graph = unsafe { PROCESS_CONDITION.get(&ctx.pid()) };    // key is PID
    
    // get the conditions to read
    let current_conditions =
    // If a Some result is returned, then the processed is already tracked
    if graph.is_some() {
        let array = graph.unwrap();
        let value = unsafe { bpf_probe_read_kernel(array as *const [ConditionStates;CONDITION_NUM]).map_err(|_e| 1u32).unwrap() };
        value
    }
    // Otherwise, we should add a new entry in the map
    // For now, just grab the primary conditions
    else {
        get_based_graph()
    };

    // Loop through all conditions
    for i in 0..current_conditions.len() {
        // Current condition
        let status = current_conditions[i];
    
        // This status indicates the condition is under monitoring
        if status == ConditionStates::WAITING {
            // Grab the condition
            let condition = unsafe {
                bpf_probe_read_kernel(
                    CONDITION_GRAPH.get(i as u32).unwrap() as *const NodeCondition)
                            .map_err(|_e|1u32
                ).unwrap()
            };

            // Check if the kfunction is involved
            if kfunction.eq(&condition.kfunction){
                info!(ctx, "kfunction detected !");
 
                // Verify the condition
                // TODO later, improve the check depending on the type
                let verified = check(condition.check_type, condition.check_num, ctx, count);
                
                if verified {
                    info!(ctx, "VERIFIED !");
                    // Indicate UL that the condition i for process pid has been satisfied
                    unsafe {
                        match RING_BUFFER.output(&RingData { pid:  ctx.pid(), condition: i }, 0) {
                            Ok(_) => (),
                            Err(e) => {
                                info!(ctx, "Error: {}", e);
                            }
                        }
                    };
                }
            }
        }
    }
}

#[kprobe]
pub fn test(ctx: ProbeContext) -> u32 {
    match try_test(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_test(ctx: ProbeContext) -> Result<u32, u32> {
    hook("tcp_connect", &ctx);
    info!(&ctx, "function tcp_connect called on pid {}", ctx.pid());
    Ok(0)
}

/* $KPROBES_PLACEHOLDER$ */

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}


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

fn concat_kfunction_pid(kfunction: &[u8;32], pid: u32) -> [u8;36] {
    let mut buff: [u8;36] = [0;36];
    
        for i in 0..32 {
            buff[i] = kfunction[i];
        }
        for i in 0..4 {
            buff[32+i] = ((pid >> 8*i) & 0xff) as u8;
        }
        buff
}