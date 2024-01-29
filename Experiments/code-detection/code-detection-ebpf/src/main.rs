#![no_std]
#![no_main]

use aya_bpf::{macros::kprobe, programs::ProbeContext, helpers::bpf_probe_read_kernel};
use aya_log_ebpf::info;

mod vmlinux;
use vmlinux::sk_buff;

mod xt;
use xt::xt_entry_target;
use xt::compat_xt_entry_target;

use crate::xt::xt_target;

#[kprobe]
pub fn code_detection_xt_compat_target_from_user(ctx: ProbeContext) -> u32 {
    match try_code_detection_xt_compat_target_from_user(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_code_detection_xt_compat_target_from_user(ctx: ProbeContext) -> Result<u32, u32> {

    let addr = unsafe { (*ctx.regs).rip };
    info!(&ctx, "function xt_compat_target_from_user called (0x{:x})", addr);

    let t: *mut xt_entry_target = ctx.arg(0).ok_or(1u32)?;
    let t = unsafe {
        bpf_probe_read_kernel(&(*t) as *const xt_entry_target).map_err(|_| 1u32)?
    };

    let target: *mut xt_target = unsafe { t.u.kernel.target };
    let target = unsafe {
        bpf_probe_read_kernel(&(*target) as *const xt_target).map_err(|_| 1u32)?
    };
 
    //let ct: *mut compat_xt_entry_target = (&t). as *mut compat_xt_entry_target;



    let name = unsafe { t.u.user.name };
    let size = target.targetsize;
    // let u8_slice: *const [u8] = unsafe { &name as *const [i8] as *const [u8] };
    // let string: &str = unsafe { core::str::from_utf8_unchecked(&*u8_slice) };
    info!(&ctx, "TARGETSIZE: {}", t.data);

    Ok(0)
}


/*
Probes on tcp functions to check everything is ok
*/

#[kprobe]
pub fn code_detection_tcp_connect(ctx: ProbeContext) -> u32 {
    match try_code_detection_tcp_connect(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}


fn try_code_detection_tcp_connect(ctx: ProbeContext) -> Result<u32, u32> {
    
    let addr = unsafe { (*ctx.regs).rip };
    info!(&ctx, "function tcp_connect called (0x{:x})", addr);
    Ok(0)
}

#[kprobe]
pub fn code_detection_tcp_v4_rcv(ctx: ProbeContext) -> u32 {
    match try_code_detection_tcp_v4_rcv(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_code_detection_tcp_v4_rcv(ctx: ProbeContext) -> Result<u32, u32> {
    
    let skb: *mut sk_buff = ctx.arg(0).ok_or(1u32)?;

    let skb = unsafe {
        bpf_probe_read_kernel(&(*skb) as *const sk_buff).map_err(|_| 1u32)?
    };

    let pointer = skb.data as usize;
    let slice_ptr = (pointer+2000) as *const [u8; 5];
    
    let slice = unsafe {
        bpf_probe_read_kernel(slice_ptr).map_err(|_| 1u32)?
    };

    let string = unsafe { core::str::from_utf8_unchecked(&slice) };    

    info!(&ctx, "function tcp_v4_rcv called. {} bytes received: {}", skb.mac_len, slice[0]);
    info!(&ctx, "\nhead = {:x}\ndata = {:x}\ntail = {:x}\nend = {:x}", skb.head as usize, skb.data as usize, skb.tail as usize, skb.end as usize);
    Ok(0)
}


#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
