#![no_std]
#![no_main]

use core::slice;
use aya_bpf::{macros::kprobe, programs::ProbeContext, helpers::{bpf_probe_read_kernel, bpf_get_current_comm, bpf_get_current_task_btf}};
use aya_log_ebpf::info;

mod vmlinux;
use vmlinux::{sock, sock_common, task_struct};

#[kprobe]
pub fn kprobe_hook(ctx: ProbeContext) -> u32 {
    match try_kprobe_hook(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_kprobe_hook(ctx: ProbeContext) -> Result<u32, u32> {
    
    // Get the sock struct parameter given to tcp_connect
    let sk: *mut sock = ctx.arg(0).ok_or(1u32)?;
    

    // Get the command name from the task_struct
    let btf_task: *mut aya_bpf::bindings::task_struct = unsafe { bpf_get_current_task_btf() };
    let current_task: *mut task_struct = unsafe { core::mem::transmute(btf_task as *mut task_struct) };

    let comm_slice = unsafe { slice::from_raw_parts(((*current_task).comm).as_ptr() as *const u8, ((*current_task).comm).len()) };
    let command = unsafe { core::str::from_utf8_unchecked(&comm_slice) };

    // Get the PID from the task_struct
    let pid = unsafe { (*current_task).pid };
    
    // Get the port from the sock structure
    let sk_common = unsafe {
        bpf_probe_read_kernel(&(*sk).__sk_common as *const sock_common)
        .map_err(|e| e as u32)?
    };
    
    let dport = unsafe { sk_common.__bindgen_anon_3.__bindgen_anon_1.skc_dport };
    // Big endian to little endian
    let port = dport >> 8 | (dport & 0xff) << 8;

    info!(&ctx, "function tcp_connect called on port {} by {} PID:{}", port, command, pid);
    
    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
