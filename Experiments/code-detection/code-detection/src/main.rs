use std::borrow::BorrowMut;

use aya::programs::KProbe;
use aya::{include_bytes_aligned, Bpf};
use aya_log::BpfLogger;
use aya::maps::HashMap;
use code_detection_common::{Calls, Condition, FuncKey, LinkedList, Node};
use log::{info, warn, debug};
use tokio::signal;

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    env_logger::init();

    // Bump the memlock rlimit. This is needed for older kernels that don't use the
    // new memcg based accounting, see https://lwn.net/Articles/837122/
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {}", ret);
    }

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    #[cfg(debug_assertions)]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/debug/code-detection"
    ))?;
    #[cfg(not(debug_assertions))]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/code-detection"
    ))?;
    if let Err(e) = BpfLogger::init(&mut bpf) {
        // This can happen if you remove all log statements from your eBPF program.
        warn!("failed to initialize eBPF logger: {}", e);
    }

    let function_list = ["xt_compat_target_from_user", "do_msgsnd", "ksys_msgget", "do_msgrcv"];

    for f in function_list {
        let mut bpf_fun = "code_detection_".to_owned();
        bpf_fun.push_str(f);
        let program: &mut KProbe = bpf.program_mut(&bpf_fun).unwrap().try_into()?;
        program.load()?;
        program.attach(&f, 0)?;
    }

    let test = "test";

    if test != "test" {
        let program: &mut KProbe = bpf.program_mut("code_detection_test").unwrap().try_into()?;
        program.load()?;
        program.attach(test, 0)?;
    }

    let mut call_list: HashMap<_, [u8;16] , Calls> = HashMap::try_from(bpf.map_mut("CALL_LIST").unwrap())?;
    let mut exploits: HashMap<_, [u8;32], LinkedList<Condition>> = HashMap::try_from(bpf.map_mut("EXPLOITS").unwrap())?;


    let mut CVE_2021_22555 = LinkedList::new(Node::new(Condition {
        func: "ksys_msgget",
        num: 2000,
    }.borrow_mut()));
    CVE_2021_22555.append(Node::new(Condition{
        func: "do_msgsnd",
        num: 4000,
    }.borrow_mut()));




    exploits.insert(FuncKey::get_key("xt_compat_target_from_user"), &CVE_2021_22555,0)?;

    info!("{} -> Conditions: {}", "xt_compat_target_from_user", exploits.get(&FuncKey::get_key("xt_compat_target_from_user"), 0).unwrap().size);


    info!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;
    info!("Exiting...");

    Ok(())
}
