#![no_std]

pub struct KFunction {
    name: *const str,
    args: *const usize,
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

    pub fn append(&mut self, mut new_node: Node<T>) {
        let prev_node = unsafe { &mut *self.current };
        prev_node.next = &mut new_node;
        self.current = &mut new_node;
        self.size = self.size+1;
    }

    pub fn get_current_data(&self) -> &T {
        let node = unsafe { &*self.current };
        &node.data
    }
}

#[derive(Clone, Copy)]
pub struct Node<T> {
    pub data: T,
    pub next: *mut Node<T>,
}

impl<T> Node<T> {
    pub fn new(data: T) -> Self {
        Node {
            data,
            next: core::ptr::null_mut(),
        }
    }
}