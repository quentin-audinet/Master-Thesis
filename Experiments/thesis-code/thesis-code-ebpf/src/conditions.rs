use aya_bpf::{programs::ProbeContext, BpfContext};


pub fn f1(ctx: &ProbeContext) -> bool {
    let x: usize = ctx.arg(1).ok_or(0_u32).unwrap();
    x > 20
    
}

pub fn f2(ctx: &ProbeContext) -> bool {
    ctx.pid() % 2 == 0
}

pub fn f3(n: u32) -> bool {
    n > 10
}

pub static CHECKS_TYPE1: [fn(&ProbeContext)->bool;3 as usize] = [f1, f2, f2];
pub static CHECKS_TYPE2: [fn(u32)->bool;2] = [f3, f3];


// Looks like num should be known at compilation time when gathering the function from the array.
// Not efficient at all but only solution for now
pub fn check(check_type: u8, num: usize, ctx: &ProbeContext) -> bool {
    if check_type == 0 {
        if num == 0 { CHECKS_TYPE1[num](ctx) }
        else if num == 1 { CHECKS_TYPE1[num](ctx)}
        else { false }
    } else if check_type == 1 {
        if num == 0 { CHECKS_TYPE2[num](ctx.pid())}
        else { false}
    } else {
        false
    }
}