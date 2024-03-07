#![no_std]
#![no_main]

use aya_bpf::{macros::kprobe, programs::ProbeContext};
use aya_log_ebpf::info;

/*  TODO
    - Create a KProbe for each function (Try to have a pattern for future auto generation)
    - Map : Process -> Graph status
    Hook:
    - Get PID, kfunction name and args
    - Send to UL for analysis
*/

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
