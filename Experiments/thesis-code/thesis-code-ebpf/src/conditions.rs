
use aya_bpf::{programs::ProbeContext, BpfContext};
use thesis_code_common::CheckTypes;


pub fn f1(ctx: &ProbeContext) -> bool {
    let x: usize = ctx.arg(1).ok_or(0_u32).unwrap();
    x > 20
    
}

pub fn f2(ctx: &ProbeContext) -> bool {
    ctx.pid() % 2 == 0
}

pub fn f3(n: u32) -> bool {
    n%100 > 20
}

pub fn f4(n: u32) -> bool {
    n > 10
}

/* $CHECK_FUNCS_PLACEHOLDER$ */

pub static CHECKS_TYPE1: [fn(&ProbeContext)->bool;2] = [f1, f2];    // Context based
pub static CHECKS_TYPE2: [fn(u32)->bool;1] = [f3];                  // PID Based
pub static CHECKS_TYPE3: [fn(u32)->bool;1] = [f4];                  // Count Based

// Looks like num should be known at compilation time when gathering the function from the array.
// Not efficient at all but only solution for now
pub fn check(check_type: CheckTypes, num: usize, ctx: &ProbeContext, count: u32) -> bool {

    if check_type == CheckTypes::Context {
        if num >= CHECKS_TYPE1.len() { false }
        else if num == 0 { CHECKS_TYPE1[0](ctx) }
        else if num == 1 { CHECKS_TYPE1[1](ctx) }
        else { false }
    } else if check_type == CheckTypes::PID {
        if num == 0 { CHECKS_TYPE2[0](ctx.pid())}
        else { false}
    } else if check_type == CheckTypes::Count {
        if num == 0 { CHECKS_TYPE3[0](count)}
        else {false}
    }
    else {
        false
    }
}

/* $CHECK_PLACEHOLDER$ */