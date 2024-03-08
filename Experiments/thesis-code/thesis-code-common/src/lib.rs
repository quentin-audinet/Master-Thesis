#![no_std]

/*  TODO
    Struture to implement:
    - Conditions
    - Shared Graph
*/

#[repr(C)]
#[derive(Clone, Copy)]
pub struct NodeCondition {
    pub value: u32,     // Fake value for testing purposes
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for NodeCondition {}

pub struct GraphStatus {
    pub conditions: [NodeCondition],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct RingData {
    pub pid: u32, 
    pub args: [u8;3],
}