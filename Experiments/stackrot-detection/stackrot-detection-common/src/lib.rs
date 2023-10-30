#![no_std]

#[repr(C)]
#[derive(Clone, Copy)]
pub struct Programs {
    pub pid: u16,
    pub maliciousness: u32,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for Programs {}