#![no_std]
#![no_main]

use aya_bpf::{
    helpers::{bpf_get_current_task_btf, bpf_probe_read_kernel, bpf_probe_read_user},
    macros::{kprobe, map},
    maps::HashMap,
    programs::ProbeContext
};
use aya_log_ebpf::info;

mod vmlinux;

use vmlinux::task_struct;
use code_detection_common::{Calls, Condition, FuncKey, LinkedList, Node};

mod xt;
use xt::xt_entry_target;

use crate::xt::xt_target;

#[map(name = "CALL_LIST")]
static mut CALL_LIST: HashMap<[u8;16], Calls> =
    HashMap::<[u8;16], Calls>::with_max_entries(256, 0);


#[map(name = "EXPLOITS")]
static mut EXPLOITS: HashMap<[u8;32], LinkedList<Condition>> =
    HashMap::<[u8;32], LinkedList<Condition>>::with_max_entries(256, 0);



fn update_calls(ctx: ProbeContext, name: &'static str) -> () {
    let current_task: *mut task_struct = unsafe { core::mem::transmute(bpf_get_current_task_btf() as *mut task_struct) };
    let pid = unsafe { (*current_task).pid };

    let id = create_id(pid, name);

    match unsafe { CALL_LIST.get_ptr_mut(&id) } {
        Some(call) => {
            unsafe { (*call).num = (*call).num+1 };
            //info!(&ctx, "{} has been called {:x} times by {}", name, unsafe { (*call).num }, pid);
        }
        None => {
            unsafe { CALL_LIST.insert(&id, &Calls { pid:pid, call_name:name, num: 1}, 0).unwrap_or(()) };
            info!(&ctx, "Added {}-{} to call list", name, pid);
        }
    };
}

fn create_id(pid: i32, call_name: &str) -> [u8; 16] {
    let mut id: [u8; 16] = [81;16];
    let bpid = pid.to_be_bytes();
    let bname = call_name.as_bytes();
    id[0] = bpid[0];
    id[1] = bpid[1];
    id[2] = bpid[2];
    id[3] = bpid[3];
    for i in 0..bname.len().min(12) {
        id[i+4] = bname[i];
    }
    id
}


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

    let current_task: *mut task_struct = unsafe { core::mem::transmute(bpf_get_current_task_btf() as *mut task_struct) };
    let pid = unsafe { (*current_task).pid };


    let conditions = unsafe { EXPLOITS.get_ptr_mut(&FuncKey::get_key("xt_compat_target_from_user") ) };

    if conditions.is_none() {
        return Ok(0);
    }

    info!(&ctx, "Function is vulnerable, checking context...");


    let l: *mut LinkedList<Condition> = match conditions {
        Some(list) => list,
        None => core::ptr::null_mut(),
    };
    let mut l = unsafe  { bpf_probe_read_kernel(l).map_err(|_|1u32)? };
    l.go_head();
    info!(&ctx, "list at 0x{:x}", l.current as usize);
    let condition = l.current;
    let condition = unsafe { bpf_probe_read_user(condition).map_err(|_|1u32)? };
    let x = condition.next as usize;
    info!(&ctx, "condition: {:x}", x);
    //let l = unsafe {&mut *conditions.unwrap()};
    //info!(&ctx, "current: 0x{:x}", l.get_current() as usize);
    // l.set_current(0xdeadbeef as *mut Node<Condition>);
    // info!(&ctx, "current: 0x{:x}", l.get_current() as usize);
    // l.go_head();
    // info!(&ctx, "current: 0x{:x}", l.get_current() as usize);


    //let current = unsafe { *l.current };
    ////let data = current.next;
    //info!(&ctx, "Data at 0x{:x}", data as usize);

    //l.go_next();
    //info!(&ctx, "current: 0x{:x}", l.get_next() as usize );

    
    return Ok(0);

    /*while current != core::ptr::null_mut() {
        
        let node = unsafe { bpf_probe_read_user(current).map_err(|_| 1u32)? };
        //let condition = node.data;
        //info!(&ctx, "CONDITION: {} = {}", condition.func, condition.num);
        current = node.next;
    }*/
    



    let id = create_id(pid, "ksys_msgget");
    let mut msgget_num = 0;
    let mut msgsnd_num = 0;
    let mut msgrcv_num = 0;

    match unsafe { CALL_LIST.get_ptr_mut(&id)} {
        Some(call) => {
            info!(&ctx, "ksys_msgget called {} times.", unsafe { (*call).num });
            msgget_num = unsafe { (*call).num };
        },
        None => {},
    };
    let id = create_id(pid, "do_msgrcv");
    match unsafe { CALL_LIST.get_ptr_mut(&id)} {
        Some(call) => {
            info!(&ctx, "do_msgrcv called {} times.", unsafe { (*call).num });
            msgrcv_num = unsafe { (*call).num };
        },
        None => {},
    };
    let id = create_id(pid, "do_msgsnd");
    match unsafe { CALL_LIST.get_ptr(&id) } {
        Some(call) => {
            info!(&ctx, "do_msgsnd called {} times.", unsafe { (*call).num});

            msgsnd_num = unsafe { (*call).num};

            if msgget_num >= 1000 && msgrcv_num >= 1 && msgsnd_num >= 2000
            {
                info!(&ctx, "SPRAYING DETECTED, POSSIBLE CORRUPTION, ABORT !");
            }
        },
        None => {}
    };

    let t: *mut xt_entry_target = ctx.arg(0).ok_or(1u32)?;
    let t = unsafe {
        bpf_probe_read_kernel(&(*t) as *const xt_entry_target).map_err(|_| 1u32)?
    };

    let target: *mut xt_target = unsafe { t.u.kernel.target };
    let target = unsafe {
        bpf_probe_read_kernel(&(*target) as *const xt_target).map_err(|_| 1u32)?
    };
    info!(&ctx, "TARGETSIZE: {}", target.targetsize );

    Ok(0)
}

#[kprobe]
pub fn code_detection_do_msgsnd(ctx: ProbeContext) -> u32 {
    match try_code_detection_do_msgsnd(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_code_detection_do_msgsnd(ctx: ProbeContext) -> Result<u32, u32> {
    let size: usize = ctx.arg(3).ok_or(0_u32)?;
    let mtype: u32 = ctx.arg(1).ok_or(0_u32)?;
    let mtext: usize = ctx.arg(2).ok_or(0_u32)?;

    let x = unsafe { bpf_probe_read_user((mtext+8) as *const usize).map_err(|_| 1u32)? };

    // info!(&ctx, "send message 0x{:x} type {} of size {}", x, mtype, size);
    
    update_calls(ctx, "do_msgsnd");    
    Ok(0)
}

#[kprobe]
pub fn code_detection_ksys_msgget(ctx: ProbeContext) -> u32 {
    match try_code_detection_ksys_msgget(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_code_detection_ksys_msgget(ctx: ProbeContext) -> Result<u32, u32> {
    //  info!(&ctx, "ksys_msgget called");
    update_calls(ctx, "ksys_msgget");
    Ok(0)
}

#[kprobe]
pub fn code_detection_do_msgrcv(ctx: ProbeContext) -> u32 {
    match try_code_detection_do_msgrcv(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_code_detection_do_msgrcv(ctx: ProbeContext) -> Result<u32, u32> {
    // info!(&ctx, "do_msgrcv called");
    update_calls(ctx, "do_msgrcv");
    Ok(0)
}

#[kprobe]
pub fn code_detection_test(ctx: ProbeContext) -> u32 {
    match try_code_detection_test(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_code_detection_test(ctx: ProbeContext) -> Result<u32, u32> {
    info!(&ctx, "test called");
    Ok(0)
}


#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}