//!Implementation of [`TaskManager`]
use super::TaskControlBlock;
use crate::sync::UPSafeCell;
use alloc::collections::VecDeque;
use alloc::sync::Arc;
use lazy_static::*;

/// BIG_STRIDE constant for stride scheduling
const BIG_STRIDE: usize = 1 << 16;  // 65536, a moderately large constant

///A array of `TaskControlBlock` that is thread-safe
pub struct TaskManager {
    ready_queue: VecDeque<Arc<TaskControlBlock>>,
}

/// Stride scheduler implementation.
impl TaskManager {
    ///Creat an empty TaskManager
    pub fn new() -> Self {
        Self {
            ready_queue: VecDeque::new(),
        }
    }
    /// Add process back to ready queue
    pub fn add(&mut self, task: Arc<TaskControlBlock>) {
        // Initialize pass value based on priority when adding to queue
        let mut inner = task.inner_exclusive_access();
        if inner.priority < 2 {
            inner.priority = 16;
        }
        inner.pass = BIG_STRIDE / inner.priority;
        drop(inner);
        self.ready_queue.push_back(task);
    }
    /// Take a process out of the ready queue using stride scheduling
    /// Returns the task with minimum stride value
    pub fn fetch(&mut self) -> Option<Arc<TaskControlBlock>> {
        if self.ready_queue.is_empty() {
            return None;
        }
        
        // Find the task with minimum stride (暴力扫一遍)
        let mut min_stride = usize::MAX;
        let mut min_index = 0;
        
        for (i, task) in self.ready_queue.iter().enumerate() {
            let inner = task.inner_exclusive_access();
            if inner.stride < min_stride {
                min_stride = inner.stride;
                min_index = i;
            }
            drop(inner);
        }
        
        // Remove and get the task with minimum stride
        let task = self.ready_queue.remove(min_index).unwrap();
        
        // Update stride after scheduling
        let mut inner = task.inner_exclusive_access();
        inner.stride = inner.stride.saturating_add(inner.pass);
        drop(inner);
        
        Some(task)
    }
}

lazy_static! {
    /// TASK_MANAGER instance through lazy_static!
    pub static ref TASK_MANAGER: UPSafeCell<TaskManager> =
        unsafe { UPSafeCell::new(TaskManager::new()) };
}

/// Add process to ready queue
pub fn add_task(task: Arc<TaskControlBlock>) {
    //trace!("kernel: TaskManager::add_task");
    TASK_MANAGER.exclusive_access().add(task);
}

/// Take a process out of the ready queue
pub fn fetch_task() -> Option<Arc<TaskControlBlock>> {
    //trace!("kernel: TaskManager::fetch_task");
    TASK_MANAGER.exclusive_access().fetch()
}
