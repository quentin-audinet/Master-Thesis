
use aya_bpf::{programs::ProbeContext, BpfContext};
use thesis_code_common::CheckTypes;

pub fn f0(ctx: &ProbeContext) -> bool {
    ctx.arg(1).ok_or(0_u32).unwrap() > 20
}

pub fn f1(pid: u32) -> bool {
    pid%100 > 20
}

pub fn f2(count: u32) -> bool {
    count>10
}

pub fn f3(pid: u32) -> bool {
    pid%2==0
}

pub static CHECKS_TYPE_Context: [fn(&ProbeContext)->bool;1] = [f0]; // Context based
pub static CHECKS_TYPE_PID: [fn(u32)->bool;2] = [f1, f3]; // PID based
pub static CHECKS_TYPE_Count: [fn(u32)->bool;1] = [f2]; // Count based


// Looks like num should be known at compilation time when gathering the function from the array.
// Not efficient at all but only solution for now
pub fn check(check_type: CheckTypes, num: usize, ctx: &ProbeContext, pid: u32, count: u32) -> bool {

    if check_type == CheckTypes::Context {
        if num >= CHECK_TYPE_Context.len() { false }
        else if num == 0 { CHECKS_TYPE_Context[0](ctx) }
        else { false }
    }
    else if check_type == CheckTypes::PID {
        if num >= CHECK_TYPE_PID.len() { false }
        else if num == 0 { CHECKS_TYPE_PID[0](pid) }
		else if num == 1 { CHECKS_TYPE_PID[1](pid) }
        else { false }
    }
    else if check_type == CheckTypes::Count {
        if num >= CHECK_TYPE_Count.len() { false }
        else if num == 0 { CHECKS_TYPE_Count[0](count) }
        else { false }
    }
    else {
        false
    }
}