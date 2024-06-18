
use aya_ebpf::{helpers::bpf_probe_read_kernel, programs::ProbeContext, EbpfContext};

/* $CHECK_FUNCS_PLACEHOLDER$ */


// Looks like num should be known at compilation time when gathering the function from the array.
// Not efficient at all but only solution for now
/* $CHECK_PLACEHOLDER$ */