# NUS Thesis 2023-2024

## Introduction

## Setting up an environment

## Using Aya to hook kernel functions

To initialize a new project, use the following command

``` bash
cargo generate https://github.com/aya-rs/aya-template
```

To launch the eBPF program, execute

```bash
RUST_LOG=info cargo xtask run --release
```

### Hooking one function

#### User file

Import the required aya modules 

```rust
use aya::programs::KProbe;
use aya::{include_bytes_aligned, Bpf};
use aya_log::BpfLogger;
use log::{info, warn, debug};
use tokio::signal;
```

```rust
#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    // Required to log message to the console
    env_logger::init();

    // Load the eBPF program at compile time
    #[cfg(debug_assertions)]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/debug/kprobe-hook"
    ))?;
    #[cfg(not(debug_assertions))]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/kprobe-hook"
    ))?;
    // If an error occurs with logging
    if let Err(e) = BpfLogger::init(&mut bpf) {
        warn!("failed to initialize eBPF logger: {}", e);
    }

    // Initialize the kprobe. "kprobe_hook" is the hook function name in the eBPF program
    let program: &mut KProbe = bpf.program_mut("kprobe_hook").unwrap().try_into()?;
    // Load and eBPF program in the Kernel
    program.load()?;
    // Attach the hook to the "tcp_connect" kfunction
    program.attach("tcp_connect", 0)?;

    info!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;
    info!("Exiting...");

    Ok(())
}
```

#### eBPF program (loaded inside the kernel)

```rust
#![no_std]
#![no_main]

use aya_bpf::{macros::kprobe, programs::ProbeContext};
use aya_log_ebpf::info;

// This is the hook function 
#[kprobe]
pub fn kprobe_hook(ctx: ProbeContext) -> u32 {
    match try_kprobe_hook(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

// This function is the one that contain the logic
fn kprobe_hook(ctx: ProbeContext) -> Result<u32, u32> {
    info!(&ctx, "function tcp_connect called");
    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
```

### Getting arguments from the context

#### Using the arguments

Refer to https://elixir.bootlin.com/linux/latest/source for information about kfunctions and structure used.

The ProbeContext implementation is as follows

```rust
impl ProbeContext {
    pub fn new(ctx: *mut c_void) -> ProbeContext
    pub fn arg<T: FromPtRegs>(&self, n: usize) -> Option<T> // Returns the nth argument to passed to the probe function, starting from 0.
    pub fn ret<T: FromPtRegs>(&self) -> Option<T> // Returns the return value of the probed function.
}
```

The Trait implementation of ProbeContext is

```rust
impl BpfContext for ProbeContext {
    fn as_ptr(&self) -> *mut c_void
    fn command(&self) -> Result<[u8; 16], c_long>
    fn pid(&self) -> u32
    fn tgid(&self) -> u32
    fn uid(&self) -> u32
    fn gid(&self) -> u32
}
```

Let's get the port number used during `tcp_connect` call.

`tcp_connect` is defined as follows in `tcp.h` :

```C
int tcp_connect(struct sock *sk);
```

To get the sock structure, we need to get the argument 0. To convert the C structure into a Rust object, use the `aya-tool` command.

```bash
$ aya-tool generate [list of structures required] > project-ebpf/vmlinux.rs
```

The declare `vmlinux` module and import the struct.

```rust
mod vmlinux;
use vmlinux::{sock, sock_common};
```

Inside the hook, get the object from the context

```rust
let sk: *mut sock = ctx.arg(0).ok_or(1u32)?;
```

According to the kernel the port number is given inside : 

```
sock->sock_common.<third union>.<first struct>.skc_dport
```

The sock is a pointer and need to be dereferenced. Use unsafe `bpf_probe_read_kernel` function to do that.

```rust
let sk_common: sock_common = unsafe {
        bpf_probe_read_kernel(&(*sk).__sk_common as *const sock_common)
        .map_err(|e| e as u32)?
    };
```

We can then get the port number. The operation is still unsafe

```rust
let dport: u16 = unsafe { sk_common.__bindgen_anon_3.__bindgen_anon_1.skc_dport };
```

the port number is written in big endian in te memory so a conversion is required to get it

```rust
let port: u16 = dport >> 8 | (dport & 0xff) << 8;
```

#### Using BPF functions

It may be required to access other information such as the task_struct, not defined in the context. We can use some BPF functions to access those elements.

`bpf_get_current_task_btf` returns a `task_struct` pointer to the hooked process. However, this `task_struct` is defined in `aya_bpf::bindings::task_struct` and can't be easily read. It is needed to convert the pointer to a `vmlinux::task_struct` object, defined using `aya-tool`.

We achieve this conversion using rust transmutation, which is extremely unsafe, but allowed here since the structure is exactly the same.

```rust
use vmlinux::task_struct

... 

let btf_task: *mut aya_bpf::bindings::task_struct = unsafe { bpf_get_current_task_btf() };
let current_task: *mut task_struct = unsafe { core::mem::transmute(btf_task as *mut task_struct) };
```

#### Obtain string from u8 or i8 slices

Often, C structures contain u8 or i8 slices which are not directly printable as string for Rust. To convert those slices into str reference, we can use the `from_utf8_unchecked` from `core::str`.

```rust
// Convert a i8 slice to a u8 one
let u8_slice: *const [u8] = unsafe { i8_slice as *const [i8] as *const [u8] };
let string: &str = unsafe { core::str::from_utf8_unchecked(&*u8_slice) };
```

### Hooking multiple functions

Sometimes, it can be useful to hook multiple kernel functions in the same program. In order to do this, just create other 'programs' in the user program:

```rust
let program_1: &mut KProbe = bpf.program_mut("code_detection_kfunction_1").unwrap().try_into()?;
program_1.load()?;
program_1.attach("kfunciton_1", 0)?;

let program_2: &mut KProbe = bpf.program_mut("code_detection_kfunction_2").unwrap().try_into()?;
program_2.load()?;
program_2.attach("kfunction_2", 0)?;


let program_n: &mut KProbe = bpf.program_mut("code_detection_kfunction_n").unwrap().try_into()?;
program_n.load()?;
program_n.attach("kfunction_n", 0)?;
```

In the eBPF program, add the corresponding hook functions:

```rust
#[kprobe]
pub fn code_detection_kfunction_1(ctx: ProbeContext) -> u32 {
    match try_code_detection_kfunction_1(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_code_detection_kfunction_1(ctx: ProbeContext) -> Result<u32, u32> {
    info!(&ctx, "function kfunction_1 called");
    Ok(0)
}

#[kprobe]
pub fn code_detection_kfunction_2(ctx: ProbeContext) -> u32 {
    match try_code_detection_kfunction_2(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_code_detection_kfunction_2(ctx: ProbeContext) -> Result<u32, u32> {
    info!(&ctx, "function kfunction_2 called");
    Ok(0)
}

...


#[kprobe]
pub fn code_detection_kfunction_n(ctx: ProbeContext) -> u32 {
    match try_code_detection_kfunction_n(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_code_detection_kfunction_n(ctx: ProbeContext) -> Result<u32, u32> {
    info!(&ctx, "function kfunction_n called");
    Ok(0)
}

```