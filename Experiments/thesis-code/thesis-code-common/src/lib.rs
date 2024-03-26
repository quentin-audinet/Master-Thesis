#![no_std]

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
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum ConditionTypes  {
    PRIMARY,                // A condition depending on nothing
    SECONDARY,              // Intermediate condition, depending on some others and whose others depend
    TRIGGER,                // A final condition, if validated a vulnerability is triggered
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum CheckTypes {
    Context,
    PID,
    Count,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct NodeCondition {
    pub node_type: ConditionTypes,  // The type of the condition
    pub check_type: CheckTypes,     // The condition collection to check
    pub check_num: usize,           // Which check pick in the collection
    pub children: &'static [u32],   // List of children indexes
    pub parents: &'static [u32],    // List of parents indexes
    pub kfunction: [u8;32],         // kfunction involved
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
    pub condition: usize,
}

pub const CONDITION_NUM: usize = 16;

use ConditionStates::*;
pub fn get_based_graph() -> [ConditionStates; CONDITION_NUM] {
    /* $BASED_GRAPH_PLACEHOLDER$ */
    [WAITING,UNREACHABLE,UNREACHABLE,UNREACHABLE,UNREACHABLE,UNREACHABLE,UNREACHABLE,UNREACHABLE,UNREACHABLE,UNREACHABLE,UNREACHABLE,UNREACHABLE,UNREACHABLE,UNREACHABLE,UNREACHABLE,UNREACHABLE]
}