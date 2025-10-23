//! Process management syscalls
use alloc::sync::Arc;

use crate::{
    loader::get_app_data_by_name,
    mm::{translated_refmut, translated_str, MapPermission, VirtAddr},
    task::{
        add_task, current_task, current_user_token, exit_current_and_run_next,
        suspend_current_and_run_next, TaskControlBlock,
    },
    timer,
};

#[repr(C)]
#[derive(Debug)]
pub struct TimeVal {
    pub sec: usize,
    pub usec: usize,
}

/// task exits and submit an exit code
pub fn sys_exit(exit_code: i32) -> ! {
    trace!("kernel:pid[{}] sys_exit", current_task().unwrap().pid.0);
    exit_current_and_run_next(exit_code);
    panic!("Unreachable in sys_exit!");
}

/// current task gives up resources for other tasks
pub fn sys_yield() -> isize {
    trace!("kernel:pid[{}] sys_yield", current_task().unwrap().pid.0);
    suspend_current_and_run_next();
    0
}

pub fn sys_getpid() -> isize {
    trace!("kernel: sys_getpid pid:{}", current_task().unwrap().pid.0);
    current_task().unwrap().pid.0 as isize
}

pub fn sys_fork() -> isize {
    trace!("kernel:pid[{}] sys_fork", current_task().unwrap().pid.0);
    let current_task = current_task().unwrap();
    let new_task = current_task.fork();
    let new_pid = new_task.pid.0;
    // modify trap context of new_task, because it returns immediately after switching
    let trap_cx = new_task.inner_exclusive_access().get_trap_cx();
    // we do not have to move to next instruction since we have done it before
    // for child process, fork returns 0
    trap_cx.x[10] = 0;
    // add new task to scheduler
    add_task(new_task);
    new_pid as isize
}

pub fn sys_exec(path: *const u8) -> isize {
    trace!("kernel:pid[{}] sys_exec", current_task().unwrap().pid.0);
    let token = current_user_token();
    let path = translated_str(token, path);
    if let Some(data) = get_app_data_by_name(path.as_str()) {
        let task = current_task().unwrap();
        task.exec(data);
        0
    } else {
        -1
    }
}

/// If there is not a child process whose pid is same as given, return -1.
/// Else if there is a child process but it is still running, return -2.
pub fn sys_waitpid(pid: isize, exit_code_ptr: *mut i32) -> isize {
    trace!("kernel::pid[{}] sys_waitpid [{}]", current_task().unwrap().pid.0, pid);
    let task = current_task().unwrap();
    // find a child process

    // ---- access current PCB exclusively
    let mut inner = task.inner_exclusive_access();
    if !inner
        .children
        .iter()
        .any(|p| pid == -1 || pid as usize == p.getpid())
    {
        return -1;
        // ---- release current PCB
    }
    let pair = inner.children.iter().enumerate().find(|(_, p)| {
        // ++++ temporarily access child PCB exclusively
        p.inner_exclusive_access().is_zombie() && (pid == -1 || pid as usize == p.getpid())
        // ++++ release child PCB
    });
    if let Some((idx, _)) = pair {
        let child = inner.children.remove(idx);
        // confirm that child will be deallocated after being removed from children list
        assert_eq!(Arc::strong_count(&child), 1);
        let found_pid = child.getpid();
        // ++++ temporarily access child PCB exclusively
        let exit_code = child.inner_exclusive_access().exit_code;
        // ++++ release child PCB
        *translated_refmut(inner.memory_set.token(), exit_code_ptr) = exit_code;
        found_pid as isize
    } else {
        -2
    }
    // ---- release current PCB automatically
}

/// YOUR JOB: get time with second and microsecond
/// HINT: You might reimplement it with virtual memory management.
/// HINT: What if [`TimeVal`] is splitted by two pages ?
pub fn sys_get_time(ts: *mut TimeVal, _tz: usize) -> isize {
    trace!(
        "kernel:pid[{}] sys_get_time",
        current_task().unwrap().pid.0
    );
    let token = current_user_token();
    let time_us = timer::get_time_us();
    let sec = time_us / 1_000_000;
    let usec = time_us % 1_000_000;
    
    let ts_ref = translated_refmut(token, ts);
    ts_ref.sec = sec;
    ts_ref.usec = usec;
    0
}

/// YOUR JOB: Implement mmap.
pub fn sys_mmap(start: usize, len: usize, port: usize) -> isize {
    trace!(
        "kernel:pid[{}] sys_mmap start={:#x} len={} prot={}",
        current_task().unwrap().pid.0,
        start,
        len,
        port
    );
    
    // 检查start地址是否按页对齐
    if start & (crate::config::PAGE_SIZE - 1) != 0 {
        return -1;
    }
    
    // 检查len是否为0
    if len == 0 {
        return -1;
    }
    
    // 检查prot的有效性
    // prot: bit 0 = PROT_READ, bit 1 = PROT_WRITE, bit 2 = PROT_EXEC
    // prot=0 无效
    if port == 0 {
        return -1;
    }
    // prot > 7 超过有效范围
    if port > 7 {
        return -1;
    }
    
    let task = current_task().unwrap();
    let mut inner = task.inner_exclusive_access();
    
    // 检查是否与现有映射重叠
    let start_va = VirtAddr(start);
    let end_va = VirtAddr(start + len);
    let start_vpn = start_va.floor();
    let end_vpn = end_va.ceil();
    
    // 使用check_overlap方法检查重叠
    if inner.memory_set.check_overlap(start_vpn, end_vpn) {
        return -1;
    }
    
    // 根据prot参数构建MapPermission
    let mut perm = MapPermission::U;
    if port & 1 != 0 {
        perm |= MapPermission::R;
    }
    if port & 2 != 0 {
        perm |= MapPermission::W;
    }
    if port & 4 != 0 {
        perm |= MapPermission::X;
    }
    
    // 在进程的内存空间中插入新的映射区域
    inner.memory_set.insert_framed_area(start_va, end_va, perm);
    
    0
}

/// YOUR JOB: Implement munmap.
pub fn sys_munmap(start: usize, len: usize) -> isize {
    trace!(
        "kernel:pid[{}] sys_munmap start={:#x} len={}",
        current_task().unwrap().pid.0,
        start,
        len
    );
    
    // 检查start地址是否按页对齐
    if start & (crate::config::PAGE_SIZE - 1) != 0 {
        return -1;
    }
    
    // 检查len是否为0
    if len == 0 {
        return -1;
    }
    
    let task = current_task().unwrap();
    let mut inner = task.inner_exclusive_access();
    
    // 计算虚拟地址范围
    let start_va = VirtAddr(start);
    let end_va = VirtAddr(start + len);
    let start_vpn = start_va.floor();
    let end_vpn = end_va.ceil();
    
    // 使用remove_area_with_range移除完全匹配的区域
    if inner.memory_set.remove_area_with_range(start_vpn, end_vpn) {
        0
    } else {
        -1
    }
}

/// change data segment size
pub fn sys_sbrk(size: i32) -> isize {
    trace!("kernel:pid[{}] sys_sbrk", current_task().unwrap().pid.0);
    if let Some(old_brk) = current_task().unwrap().change_program_brk(size) {
        old_brk as isize
    } else {
        -1
    }
}

/// YOUR JOB: Implement spawn.
/// HINT: fork + exec =/= spawn
pub fn sys_spawn(path: *const u8) -> isize {
    trace!(
        "kernel:pid[{}] sys_spawn",
        current_task().unwrap().pid.0
    );
    
    // 从用户空间读取程序名称
    let token = current_user_token();
    let path = translated_str(token, path);
    
    // 检查程序是否存在
    if let Some(data) = get_app_data_by_name(path.as_str()) {
        // 获取当前进程
        let parent = current_task().unwrap();
        
        // 创建新的子进程（从 ELF 数据创建新的地址空间）
        let child = Arc::new(TaskControlBlock::new(data));
        let child_pid = child.pid.0;
        
        // 建立父子关系
        let mut parent_inner = parent.inner_exclusive_access();
        let mut child_inner = child.inner_exclusive_access();
        
        // 设置子进程的父进程指针
        child_inner.parent = Some(Arc::downgrade(&parent));
        
        // 释放锁
        drop(child_inner);
        
        // 将子进程添加到父进程的子进程列表
        parent_inner.children.push(child.clone());
        drop(parent_inner);
        
        // 将子进程添加到调度器的就绪队列
        add_task(child);
        
        // 返回子进程的 pid
        child_pid as isize
    } else {
        // 文件名无效
        -1
    }
}

// YOUR JOB: Set task priority.
pub fn sys_set_priority(prio: isize) -> isize {
    trace!(
        "kernel:pid[{}] sys_set_priority prio={}",
        current_task().unwrap().pid.0,
        prio
    );
    
    // 优先级必须大于等于2
    if prio < 2 {
        return -1;
    }
    
    let task = current_task().unwrap();
    let mut inner = task.inner_exclusive_access();
    
    // 更新优先级
    inner.priority = prio as usize;
    
    // 计算对应的 pass 值
    const BIG_STRIDE: usize = 1 << 16;  // 65536
    inner.pass = BIG_STRIDE / inner.priority;
    
    prio
}
