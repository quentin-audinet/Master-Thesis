
use aya_ebpf::{helpers::bpf_probe_read_kernel, programs::ProbeContext, EbpfContext};

pub fn f0(ctx: &ProbeContext, pid: u32, count: u32) -> Result<bool,bool> {
    
Ok(count>1000)
}

pub fn f1(ctx: &ProbeContext, pid: u32, count: u32) -> Result<bool,bool> {
    
Ok(count>2000)
}

pub fn f2(ctx: &ProbeContext, pid: u32, count: u32) -> Result<bool,bool> {
    
Ok(count>1)
}

pub fn f3(ctx: &ProbeContext, pid: u32, count: u32) -> Result<bool,bool> {
    
Ok(pid>0)
}


// Looks like num should be known at compilation time when gathering the function from the array.
// Not efficient at all but only solution for now
pub fn check(id: usize, ctx: &ProbeContext, pid: u32, count: u32) -> bool {
    let result = 
    if id == 0 { f0(ctx, pid, count) }
	else if id == 1 { f1(ctx, pid, count) }
	else if id == 2 { f2(ctx, pid, count) }
	else if id == 3 { f3(ctx, pid, count) }

    else {
        Err(false)
    };
    result.unwrap()
}