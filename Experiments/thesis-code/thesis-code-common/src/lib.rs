#![no_std]

/*  TODO
    Struture to implement:
    - Conditions
    - Shared Graph
*/

// Different states of the node conditions
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum ConditionStates {
    UNREACHABLE,            // The condition cannot be validated yet
    WAITING,                // The condition is waiting for validation
    VERIFIED,               // The condition has already been validated
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for ConditionStates {}

#[repr(C)]
#[derive(Clone, Copy)]
pub enum ConditionTypes  {
    PRIMARY,                // A condition depending on nothing
    SECONDARY,              // Intermediate condition, depending on some others and whose others depend
    TRIGGER,                // A final condition, if validated a vulnerability is triggered
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct NodeCondition {
    pub node_type: ConditionTypes,  // The type of the condition
    pub check: fn(u32) -> bool,     // The condition to check 
    pub children: &'static [u32],   // List of children indexes
    pub kfunction: [u8;32],    // kfunction involved
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