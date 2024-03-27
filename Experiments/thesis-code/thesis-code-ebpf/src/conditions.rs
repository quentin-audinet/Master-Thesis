
use aya_bpf::{programs::ProbeContext, BpfContext};
use thesis_code_common::CheckTypes;

pub fn f0(ctx: &ProbeContext) -> bool {
    ctx.pid() % 2 == 0
}

pub fn f1(pid: u32) -> bool {
    pid%100 > 20
}

pub fn f2(count: u32) -> bool {
    count>10
}

pub fn f3(pid: u32) -> bool {
    pid%4==0
}

pub fn f4(pid: u32) -> bool {
    pid%2==0
}

pub fn f5(count: u32) -> bool {
    count > 100
}

pub fn f6(pid: u32) -> bool {
    pid%2==0
}

pub static CHECK_TYPE_CONTEXT: [fn(&ProbeContext)->bool;1] = [f0]; // CONTEXT based
pub static CHECK_TYPE_PID: [fn(u32)->bool;4] = [f1, f3, f4, f6]; // PID based
pub static CHECK_TYPE_COUNT: [fn(u32)->bool;2] = [f2, f5]; // COUNT based


// Looks like num should be known at compilation time when gathering the function from the array.
// Not efficient at all but only solution for now
pub fn check(check_type: CheckTypes, num: usize, ctx: &ProbeContext, pid: u32, count: u32) -> bool {

    if check_type == CheckTypes::CONTEXT {
        if num >= CHECK_TYPE_CONTEXT.len() { false }
        else if num == 0 { CHECK_TYPE_CONTEXT[0](ctx) }
        else { false }
    }
    else if check_type == CheckTypes::PID {
        if num >= CHECK_TYPE_PID.len() { false }
        else if num == 0 { CHECK_TYPE_PID[0](pid) }
		else if num == 1 { CHECK_TYPE_PID[1](pid) }
		else if num == 2 { CHECK_TYPE_PID[2](pid) }
		else if num == 3 { CHECK_TYPE_PID[3](pid) }
        else { false }
    }
    else if check_type == CheckTypes::COUNT {
        if num >= CHECK_TYPE_COUNT.len() { false }
        else if num == 0 { CHECK_TYPE_COUNT[0](count) }
		else if num == 1 { CHECK_TYPE_COUNT[1](count) }
        else { false }
    }
    else {
        false
    }
}