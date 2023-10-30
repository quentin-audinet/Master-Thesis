#![no_std]
#![no_main]

use aya_bpf::{
    macros::{kprobe, map},
    programs::ProbeContext,
    maps::HashMap, helpers::bpf_get_current_task_btf,
};

use aya_log_ebpf::info;
use stackrot_detection_common::Programs;

mod vmlinux;
use vmlinux::task_struct;

#[map(name = "MARKED_PROGRAMS")]
static mut MARKED_PROGRAMS: HashMap<u16, Programs> =
    HashMap::<u16, Programs>::with_max_entries(256, 0);

fn update_maliciousness(ctx: ProbeContext) -> () {
    let current_task: *mut task_struct = unsafe { core::mem::transmute(bpf_get_current_task_btf() as *mut task_struct) };
    let pid: u16 = unsafe { (*current_task).pid } as u16;

    match unsafe { MARKED_PROGRAMS.get_ptr_mut(&pid) } {
        Some(program) => {
            unsafe { (*program).maliciousness = (*program).maliciousness+1 };
            info!(&ctx, "{} is {} malicious", pid, unsafe { (*program).maliciousness })
        }
        None => {
            unsafe { MARKED_PROGRAMS.insert(&pid, &Programs { pid, maliciousness: 1}, 0).unwrap_or(()) };
            info!(&ctx, "Added {} to malicious list", pid);
        }
    };
}

// PROBE TO DETECT CALL TO SYNCHRONIZE_RCU
#[kprobe]
pub fn stackrot_detection_synchronize_rcu(ctx: ProbeContext) -> u32 {
    match try_stackrot_detection_synchronize_rcu(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_stackrot_detection_synchronize_rcu(ctx: ProbeContext) -> Result<u32, u32> {
    info!(&ctx, "function synchronize_rcu called");

    let current_task: *mut task_struct = unsafe { core::mem::transmute(bpf_get_current_task_btf() as *mut task_struct) };
    let pid: u16 = unsafe { (*current_task).pid } as u16;

    match unsafe { MARKED_PROGRAMS.get_ptr_mut(&pid) } {
        Some(program) => {
            unsafe { (*program).maliciousness = (*program).maliciousness+1 };
            info!(&ctx, "{} is {} malicious", pid, unsafe { (*program).maliciousness })
        }
        None => {
            unsafe { MARKED_PROGRAMS.insert(&pid, &Programs { pid, maliciousness: 1}, 0).unwrap_or(()) };
            info!(&ctx, "Added {} to malicious list", pid);
        }
    };
    
    Ok(0)
}

// PROBE TO DETECT CALL TO EXT4_MKDIR
#[kprobe]
pub fn stackrot_detection_ext4_mkdir(ctx: ProbeContext) -> u32 {
    match try_stackrot_detection_ext4_mkdir(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_stackrot_detection_ext4_mkdir(ctx: ProbeContext) -> Result<u32, u32> {
    info!(&ctx, "function ext4_mkdir called");

    let current_task: *mut task_struct = unsafe { core::mem::transmute(bpf_get_current_task_btf() as *mut task_struct) };
    let pid: u16 = unsafe { (*current_task).pid } as u16;

    match unsafe { MARKED_PROGRAMS.get_ptr_mut(&pid) } {
        Some(program) => {
            unsafe { (*program).maliciousness = (*program).maliciousness+1 };
            info!(&ctx, "{} is {} malicious", pid, unsafe { (*program).maliciousness })
        }
        None => {
            unsafe { MARKED_PROGRAMS.insert(&pid, &Programs { pid, maliciousness: 1}, 0).unwrap_or(()) };
            info!(&ctx, "Added {} to malicious list", pid);
        }
    };

    Ok(0)
}

// PROBE TO DETECT CALL TO EXT4_MKDIR
#[kprobe]
pub fn stackrot_detection_kfunction(ctx: ProbeContext) -> u32 {
    match try_stackrot_detection_kfunction(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_stackrot_detection_kfunction(ctx: ProbeContext) -> Result<u32, u32> {
    info!(&ctx, "function ktest called");

    let current_task: *mut task_struct = unsafe { core::mem::transmute(bpf_get_current_task_btf() as *mut task_struct) };
    let pid: u16 = unsafe { (*current_task).pid } as u16;

    match unsafe { MARKED_PROGRAMS.get_ptr_mut(&pid) } {
        Some(program) => {
            unsafe { (*program).maliciousness = (*program).maliciousness+1 };
            info!(&ctx, "{} is {} malicious", pid, unsafe { (*program).maliciousness })
        }
        None => {
            unsafe { MARKED_PROGRAMS.insert(&pid, &Programs { pid, maliciousness: 1}, 0).unwrap_or(()) };
            info!(&ctx, "Added {} to malicious list", pid);
        }
    };
    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
