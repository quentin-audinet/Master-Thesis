#![no_std]
#![no_main]

use aya_bpf::{cty::{c_char, c_void}, helpers::{bpf_probe_read_kernel, bpf_probe_read_kernel_str_bytes, gen::bpf_probe_read_kernel_str}, macros::{kprobe, map}, maps::{Array, HashMap, RingBuf}, programs::ProbeContext, BpfContext};
use aya_log_ebpf::info;
use thesis_code_common::{ConditionStates, NodeCondition, RingData};

/*  TODO
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
static mut CONDITION_GRAPH: Array<NodeCondition> = Array::<NodeCondition>::with_max_entries(16, 0);


// Map each process to the current conditions.
// The size of the array must be the number of conditions (or at least)
#[map(name = "PROCESS_CONDITIONS")]
static mut PROCESS_CONDITION: HashMap<u32, [ConditionStates;16]> = HashMap::<u32, [ConditionStates; 16]>::with_max_entries(4096, 0);


// The global hook
fn hook(kfunction: &'static str, pid: u32, ctx: &ProbeContext) {

    let graph = unsafe { PROCESS_CONDITION.get(&1234) };    // key is PID
    
    // get the conditions to read
    let current_conditions =
    // If a Some result is returned, then the processed is already tracked
    if graph.is_some() {
        let array = graph.unwrap();
        let value = unsafe { bpf_probe_read_kernel(array as *const [ConditionStates;16]).map_err(|_e| 1u32).unwrap() };
        value
    }
    // Otherwise, we should add a new entry in the map
    // For now, just grab the primary conditions
    else {
        // TODO - Grab primary conditions list
        [ConditionStates::UNREACHABLE;16]
    };

    for i in 0..current_conditions.len() {
        // Current condition
        let status = current_conditions[i];
    
        if status == ConditionStates::WAITING {
            // Grab the condition
            let condition = unsafe {
                bpf_probe_read_kernel(
                    CONDITION_GRAPH.get(i as u32).unwrap() as *const NodeCondition)
                            .map_err(|_e|1u32
                ).unwrap()
            };
            let cond_kfunc = unsafe { core::str::from_utf8_unchecked(&condition.kfunction) };

            // Check if the kfunction is involved
            if cond_kfunc.starts_with(kfunction) && condition.kfunction[kfunction.len()] == 0{ // Get from the condition
                info!(ctx, "{} detected !", kfunction);
                // TODO - Extract the condition
                /*let verified = (condition.check)(4);    // TODO - Check the condition
                if verified {
                    info!(ctx, "Children 0 is {}", condition.children[0])
                    // TODO - Update the Process Condition in UL
                }*/
            }
        }
    }

    unsafe { RING_BUFFER.output(&RingData {pid, args: [1,2,3]}, 0).unwrap() };
}

#[kprobe]
pub fn thesis_code(ctx: ProbeContext) -> u32 {
    match try_thesis_code(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_thesis_code(ctx: ProbeContext) -> Result<u32, u32> {
    hook("tcp_connect", ctx.pid(), &ctx);
    info!(&ctx, "function tcp_connect called on pid {}", ctx.pid());
    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
