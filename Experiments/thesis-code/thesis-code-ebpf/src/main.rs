#![no_std]
#![no_main]

use aya_bpf::{macros::{kprobe, map}, maps::RingBuf, programs::ProbeContext, BpfContext};
use aya_log_ebpf::info;
use thesis_code_common::RingData;

/*  TODO
    - Create a KProbe for each function (Try to have a pattern for future auto generation)
    - Map : Process -> Graph status
    Hook:
    - Get PID, kfunction name and args
    - Send to UL for analysis
*/

#[map(name = "ARRAY")]
static mut RING_BUFFER:RingBuf = RingBuf::with_byte_size(1024, 0);

fn hook(kfunction: &'static str, pid: u32) {
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
    hook("tcp_connect", ctx.pid());
    info!(&ctx, "function tcp_connect called on pid {}", ctx.pid());
    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
