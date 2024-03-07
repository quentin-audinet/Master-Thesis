#![no_std]
#![no_main]

use aya_bpf::{macros::kprobe, programs::ProbeContext};
use aya_log_ebpf::info;

/*  TODO
    - Create a KProbe for each function (Try to have a pattern for future auto generation)
    - Map : Process -> Graph status
    Hook:
        1. Get Process
        2. Check if some current condition rely on the hooked function
        3. Check if the condition is satisfied
        4. Update Graph status and check if a vulnerability has been triggered
*/

/// General hook used for all checking
fn hook(/* Args: Process, KFunction */) {
    // Get process status graph
    // For each condition check if it depends of the KFunction
    //      Get the condition
    //      Check the condition
    //      If verified update the graph and for each new node reached, check if it is final
}

#[kprobe]
pub fn thesis_code(ctx: ProbeContext) -> u32 {
    match try_thesis_code(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_thesis_code(ctx: ProbeContext) -> Result<u32, u32> {
    info!(&ctx, "function try_to_wake_up called");
    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
