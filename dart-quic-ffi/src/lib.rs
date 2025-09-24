
pub mod runtime_manager;
pub mod async_dart_task_executor;
pub mod memory_manager;
pub mod binary_protocol;
pub mod quic_command_handler;

pub use async_dart_task_executor::*;
pub use quic_command_handler::{QuicCommandHandler, QuicCommandType};
pub use memory_manager::{
    allocate, deallocate, memory_stats, MemoryStats,
    initialize_memory_manager, initialize_memory_manager_with_config,
    destroy_memory_manager, is_memory_manager_available, PoolConfig
};

// Create QUIC-specific type for FFI
pub type QuicTaskExecutor = AsyncDartTaskExecutor<QuicCommandHandler>;

// FFI export functions - unified management
/// Create QUIC task executor
#[unsafe(no_mangle)]
pub extern "C" fn dart_quic_executor_new(dart_port: DartPort) -> *mut QuicTaskExecutor {
    let handler = QuicCommandHandler::new();
    let executor = AsyncDartTaskExecutor::new(dart_port, handler);
    Box::into_raw(Box::new(executor))
}

/// Initialize QUIC executor runtime (async, returns TaskId for event tracking)
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dart_quic_executor_init_runtime(executor: *mut QuicTaskExecutor, threads: usize) -> TaskId {
    if executor.is_null() {
        return 0;
    }
    unsafe {
        let executor_ref = &*executor;
        executor_ref.init_runtime(threads)
    }
}

/// Submit QUIC task
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dart_quic_executor_submit_params(
    executor: *mut QuicTaskExecutor,
    command_type: u8,
    data_ptr: *mut u8,
    data_len: usize,
    params_ptr: *mut u64,
    params_count: usize,
) -> TaskId {
    if executor.is_null() {
        return 0;
    }
    unsafe {
        let executor_ref = &*executor;
        executor_ref.submit_task(command_type, data_ptr, data_len, params_ptr, params_count)
    }
}

/// Check QUIC executor running status
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dart_quic_executor_is_running(executor: *mut QuicTaskExecutor) -> bool {
    if executor.is_null() {
        return false;
    }
    unsafe {
        let executor_ref = &*executor;
        executor_ref.is_running()
    }
}

/// Release QUIC executor - returns immediately, closes asynchronously
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dart_quic_executor_free(executor: *mut QuicTaskExecutor) {
    if !executor.is_null() {
        unsafe {
            let executor_box = Box::from_raw(executor);
            std::thread::spawn(move || {
                drop(executor_box);
            });
        }
    }
}

/// Release QUIC executor - synchronous version (will block)
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dart_quic_executor_free_sync(executor: *mut QuicTaskExecutor) {
    if !executor.is_null() {
        unsafe {
            let _executor_box = Box::from_raw(executor);
        }
    }
}

/// Allocate native memory
#[unsafe(no_mangle)]
pub extern "C" fn dart_allocate_memory(size: usize) -> *mut u8 {
    allocate(size)
}

/// Release native allocated memory - requires providing original allocation size
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dart_free_memory(ptr: *mut u8, size: usize) {
    deallocate(ptr, size);
}

/// Get memory manager statistics
#[unsafe(no_mangle)]
pub extern "C" fn dart_get_memory_stats() -> *const MemoryStats {
    if let Some(stats) = memory_stats() {
        let stats_box = Box::new(stats);
        Box::into_raw(stats_box)
    } else {
        std::ptr::null()
    }
}

/// Release memory statistics structure
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dart_free_memory_stats(stats: *mut MemoryStats) {
    if !stats.is_null() {
        unsafe {
            let _stats_box = Box::from_raw(stats);
        }
    }
}

// Singleton memory manager FFI functions
/// Initialize global memory manager (default configuration)
#[unsafe(no_mangle)]
pub extern "C" fn dart_initialize_memory_manager() -> bool {
    initialize_memory_manager()
}

/// Initialize global memory manager with custom configuration
/// Parameter -1 means use default value, otherwise use specified value
#[unsafe(no_mangle)]
pub extern "C" fn dart_initialize_memory_manager_with_config(
    tiny_pool_size: i32,     // -1 = default value, otherwise use specified value
    small_pool_size: i32,    // -1 = default value, otherwise use specified value
    medium_pool_size: i32,   // -1 = default value, otherwise use specified value
    large_pool_size: i32,    // -1 = default value, otherwise use specified value
    huge_pool_size: i32,     // -1 = default value, otherwise use specified value
    xlarge_pool_size: i32,   // -1 = default value, otherwise use specified value
) -> bool {
    let config = PoolConfig {
        tiny_pool_size: if tiny_pool_size >= 0 { Some(tiny_pool_size as usize) } else { None },
        small_pool_size: if small_pool_size >= 0 { Some(small_pool_size as usize) } else { None },
        medium_pool_size: if medium_pool_size >= 0 { Some(medium_pool_size as usize) } else { None },
        large_pool_size: if large_pool_size >= 0 { Some(large_pool_size as usize) } else { None },
        huge_pool_size: if huge_pool_size >= 0 { Some(huge_pool_size as usize) } else { None },
        xlarge_pool_size: if xlarge_pool_size >= 0 { Some(xlarge_pool_size as usize) } else { None },
    };
    initialize_memory_manager_with_config(config)
}

/// Destroy global memory manager
#[unsafe(no_mangle)]
pub extern "C" fn dart_destroy_memory_manager() -> bool {
    destroy_memory_manager()
}

/// Check if memory manager is available
#[unsafe(no_mangle)]
pub extern "C" fn dart_is_memory_manager_available() -> bool {
    is_memory_manager_available()
}

