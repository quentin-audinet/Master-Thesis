#![no_std]

/*  TODO
    Struture to implement:
    - Conditions
    - Shared Graph
*/

pub struct Condition {

}

pub struct GraphStatus {
    pub conditions: [Condition],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct RingData {
    pub pid: u32, 
    pub args: [u8;3],
}