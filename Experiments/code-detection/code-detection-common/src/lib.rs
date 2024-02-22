#![no_std]

use core::cmp::min;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct Calls {
    pub pid: i32,
    pub call_name: &'static str,
    pub num: u32,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for Calls {}


#[repr(C)]
#[derive(Clone, Copy)]
pub struct Condition {
    pub func: &'static str,
    pub num: u32,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for Condition {}

#[cfg(feature = "user")]
unsafe impl aya::Pod for LinkedList<Condition> {}


pub struct KFunction {
    pub name: &'static str,
    pub args: usize,
}

#[derive(Clone, Copy)]
pub struct LinkedList<T> {
    pub head: *const Node<T>,
    pub current: *mut Node<T>,
    pub size: u32,
}

impl<T> LinkedList<T> {

    pub fn new(mut node: Node<T>) -> Self {
        LinkedList {
            head: &node,
            current: &mut node,
            size: 1,
        }
    }

    pub fn set_current(&mut self, node: *mut Node<T>) {
        self.current = node;
    }

    pub fn append(&mut self, mut new_node: Node<T>) {
        let prev_node = unsafe { &mut *self.current };
        prev_node.next = &mut new_node;
        self.current = &mut new_node;
        self.size = self.size+1;
    }

    pub fn get_current_data(&self) -> &T {
        let node = self.current;
        unsafe {&*(&*node).data}
    }

    pub fn go_head(&mut self) {
        self.set_current(self.head as *mut Node<T>);
    }

    pub fn get_next(&self) -> *mut Node<T>{
        (unsafe{&*self.current}).next
    }

    pub fn go_next(&mut self) {
        let node = unsafe{&*self.current};
        self.set_current(node.next);
    }

    pub fn get_current(self) -> *mut Node<T>{
        self.current
    }
}

#[derive(Clone, Copy)]
pub struct Node<T> {
    pub data: *mut T,
    pub next: *mut Node<T>,
}

impl<T> Node<T> {
    pub fn new(data: *mut T) -> Self {
        Node {
            data,
            next: core::ptr::null_mut(),
        }
    }
}

pub struct FuncKey {}

impl FuncKey {
    pub fn get_key(name: &'static str ) -> [u8; 32] {
        let mut key = [0_u8; 32];
        let size = name.len();
        let nbytes = name.as_bytes();
        for i in 0..min(size, 32) {
            key[i] = nbytes[i];
        }
        key
    }
}