#![no_std]

pub struct KFunction {
    name: *const str,
    args: *const usize,
}

#[derive(Clone, Copy)]
pub struct LinkedList {
    pub data: u32,
    pub next: *mut LinkedList,
}

impl LinkedList {
    pub fn new(data: u32) -> Self {
        LinkedList {
            data,
            next: core::ptr::null_mut(),
        }
    }

    pub fn append(&mut self, new_node: &mut LinkedList) {
        self.next = new_node as *mut LinkedList;
    }
}


pub struct Node {
    pub data: u32,
    next: *mut Node,
}

impl Node {
    pub fn new(data: u32) -> Self {
        Node { data, next: core::ptr::null_mut() }
    }

    pub fn append(&mut self, data: u32) {
        let mut current = self;
        while !current.next.is_null() {
            unsafe {
                current = &mut *current.next;
            }
        }
        let mut new_node = Node::new(data);
        current.next = &mut new_node as *mut Node;
    }

    pub fn iterate(&self) {
        let mut current = self;
        while !current.next.is_null() {
            unsafe {
                current = &*(current.next);
            }
        }
    }

    // Implement a cleanup method if you need to deallocate memory manually.
    pub fn cleanup(&mut self) {
        let current = self;
        while !current.next.is_null() {
            unsafe {
                let next = current.next;
                current.next = (*next).next;
                // Deallocate the node manually if necessary.
                // std::ptr::drop_in_place(next);
            }
        }
    }
}

// Implement Drop trait for automatic cleanup when the list goes out of scope.
impl Drop for Node {
    fn drop(&mut self) {
        self.cleanup();
    }
}