
use aya_ebpf::{programs::ProbeContext, EbpfContext};
use thesis_code_common::CheckTypes;

pub fn f0(count: u32) -> bool {
    count > 1000
}

pub fn f1(count: u32) -> bool {
    count > 2000
}

pub fn f2(count: u32) -> bool {
    count > 1
}

pub fn f3(pid: u32) -> bool {
    pid == pid
}

pub static CHECK_TYPE_COUNT: [fn(u32)->bool;3] = [f0, f1, f2]; // COUNT based
pub static CHECK_TYPE_PID: [fn(u32)->bool;1] = [f3]; // PID based


// Looks like num should be known at compilation time when gathering the function from the array.
// Not efficient at all but only solution for now
pub fn check(check_type: CheckTypes, num: usize, ctx: &ProbeContext, pid: u32, count: u32) -> bool {

    if check_type == CheckTypes::COUNT {
        if num >= CHECK_TYPE_COUNT.len() { false }
        else if num == 0 { CHECK_TYPE_COUNT[0](count) }
		else if num == 1 { CHECK_TYPE_COUNT[1](count) }
		else if num == 2 { CHECK_TYPE_COUNT[2](count) }
        else { false }
    }
    else if check_type == CheckTypes::PID {
        if num >= CHECK_TYPE_PID.len() { false }
        else if num == 0 { CHECK_TYPE_PID[0](pid) }
        else { false }
    }
    else {
        false
    }
}