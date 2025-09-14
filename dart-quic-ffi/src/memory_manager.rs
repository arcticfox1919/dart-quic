// High-performance memory manager
use std::ptr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use crossbeam_queue::SegQueue;

/// Memory pool configuration - supports on-demand configuration, uses defaults for unspecified values
#[derive(Debug, Clone)]
pub struct PoolConfig {
    pub tiny_pool_size: Option<usize>,    // 32B pool size, None uses default
    pub small_pool_size: Option<usize>,   // 128B pool size, None uses default  
    pub medium_pool_size: Option<usize>,  // 512B pool size, None uses default
    pub large_pool_size: Option<usize>,   // 4KB pool size, None uses default
    pub huge_pool_size: Option<usize>,    // 16KB pool size, None uses default
    pub xlarge_pool_size: Option<usize>,  // 64KB pool size, None uses default
}

impl PoolConfig {
    /// Create new configuration builder - all values initialized to None (use defaults)
    pub fn new() -> Self {
        Self {
            tiny_pool_size: None,
            small_pool_size: None,
            medium_pool_size: None,
            large_pool_size: None,
            huge_pool_size: None,
            xlarge_pool_size: None,
        }
    }
    
    /// Configure Tiny pool (32B)
    pub fn tiny_pool_size(mut self, size: usize) -> Self {
        self.tiny_pool_size = Some(size);
        self
    }
    
    /// Configure Small pool (128B)
    pub fn small_pool_size(mut self, size: usize) -> Self {
        self.small_pool_size = Some(size);
        self
    }
    
    /// Configure Medium pool (512B)
    pub fn medium_pool_size(mut self, size: usize) -> Self {
        self.medium_pool_size = Some(size);
        self
    }
    
    /// Configure Large pool (4KB)
    pub fn large_pool_size(mut self, size: usize) -> Self {
        self.large_pool_size = Some(size);
        self
    }
    
    /// Configure Huge pool (16KB)
    pub fn huge_pool_size(mut self, size: usize) -> Self {
        self.huge_pool_size = Some(size);
        self
    }
    
    /// Configure XLarge pool (64KB)
    pub fn xlarge_pool_size(mut self, size: usize) -> Self {
        self.xlarge_pool_size = Some(size);
        self
    }
    
    /// Get actual pool size - supports 0 to disable pool, None uses default
    pub fn get_tiny_pool_size(&self) -> Option<usize> {
        match self.tiny_pool_size {
            Some(0) => None,        // 0 means disable this pool
            Some(size) => Some(size), // Explicitly specified size
            None => Some(20),       // Default size
        }
    }
    
    pub fn get_small_pool_size(&self) -> Option<usize> {
        match self.small_pool_size {
            Some(0) => None,
            Some(size) => Some(size),
            None => Some(20),
        }
    }
    
    pub fn get_medium_pool_size(&self) -> Option<usize> {
        match self.medium_pool_size {
            Some(0) => None,
            Some(size) => Some(size),
            None => Some(20),
        }
    }
    
    pub fn get_large_pool_size(&self) -> Option<usize> {
        match self.large_pool_size {
            Some(0) => None,
            Some(size) => Some(size),
            None => Some(10),
        }
    }
    
    pub fn get_huge_pool_size(&self) -> Option<usize> {
        match self.huge_pool_size {
            Some(0) => None,
            Some(size) => Some(size),
            None => Some(10),
        }
    }
    
    pub fn get_xlarge_pool_size(&self) -> Option<usize> {
        match self.xlarge_pool_size {
            Some(0) => None,
            Some(size) => Some(size),
            None => Some(5),
        }
    }
    
    /// Check if a specific pool is enabled
    pub fn is_tiny_pool_enabled(&self) -> bool {
        self.get_tiny_pool_size().is_some()
    }
    
    pub fn is_small_pool_enabled(&self) -> bool {
        self.get_small_pool_size().is_some()
    }
    
    pub fn is_medium_pool_enabled(&self) -> bool {
        self.get_medium_pool_size().is_some()
    }
    
    pub fn is_large_pool_enabled(&self) -> bool {
        self.get_large_pool_size().is_some()
    }
    
    pub fn is_huge_pool_enabled(&self) -> bool {
        self.get_huge_pool_size().is_some()
    }
    
    pub fn is_xlarge_pool_enabled(&self) -> bool {
        self.get_xlarge_pool_size().is_some()
    }
}

/// Memory block size categories - optimized for mobile devices, includes common small object sizes
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BlockSize {
    Tiny = 32,      // 32 bytes - tiny objects
    Small = 128,    // 128 bytes - small messages
    Medium = 512,   // 512 bytes - medium messages  
    Large = 4096,   // 4KB - data packets
    Huge = 16384,   // 16KB - large data packets
    XLarge = 65536, // 64KB - extra large data packets
}

impl BlockSize {
    /// Select the most suitable block size based on requested size
    pub fn for_size(size: usize) -> Option<Self> {
        match size {
            1..=32 => Some(BlockSize::Tiny),       // 1-32 bytes use Tiny pool
            33..=128 => Some(BlockSize::Small),    // 33-128 bytes use Small pool
            129..=512 => Some(BlockSize::Medium),  // 129-512 bytes use Medium pool
            513..=4096 => Some(BlockSize::Large),  // 513B-4KB use Large pool
            4097..=16384 => Some(BlockSize::Huge), // 4KB-16KB use Huge pool
            16385..=65536 => Some(BlockSize::XLarge), // 16KB-64KB use XLarge pool
            _ => None, // Memory larger than 64KB is allocated directly from system
        }
    }
    
    pub fn as_usize(self) -> usize {
        self as usize
    }
}

#[derive(Debug, Clone, Copy)]
struct TypedPointer {
    ptr: usize,             // Use usize to store pointer, automatically satisfies Send+Sync
    block_size: BlockSize,  // Memory block size pointed to by the pointer
}

impl TypedPointer {
    fn new(ptr: *mut u8, block_size: BlockSize) -> Self {
        Self {
            ptr: ptr as usize,
            block_size,
        }
    }
    
    /// Verify if pointer is valid and type matches
    fn is_valid_for_pool(&self, expected_block_size: BlockSize) -> bool {
        self.block_size == expected_block_size && self.ptr != 0
    }
    
    fn get_ptr(self) -> *mut u8 {
        self.ptr as *mut u8
    }
}

/// Type-safe high-performance memory pool - based on crossbeam SegQueue
struct TypeSafeMemoryPool {
    block_size: BlockSize,
    free_blocks: SegQueue<TypedPointer>,   // Use TypedPointer to store pointer and type information
    allocated_count: AtomicUsize,          // Atomic counter to avoid lock contention
    max_pool_size: usize,
    
    // Performance statistics
    pool_allocations: AtomicU64,
    pool_deallocations: AtomicU64,
    pool_hits: AtomicU64,
    pool_misses: AtomicU64,
    type_mismatches: AtomicU64,            // Block size mismatch count
}

impl TypeSafeMemoryPool {
    fn new(block_size: BlockSize, max_pool_size: usize) -> Self {
        Self {
            block_size,
            free_blocks: SegQueue::new(),
            allocated_count: AtomicUsize::new(0),
            max_pool_size,
            
            pool_allocations: AtomicU64::new(0),
            pool_deallocations: AtomicU64::new(0),
            pool_hits: AtomicU64::new(0),
            pool_misses: AtomicU64::new(0),
            type_mismatches: AtomicU64::new(0),
        }
    }
    
    /// Type-safe allocation
    fn allocate(&self) -> Option<*mut u8> {
        self.pool_allocations.fetch_add(1, Ordering::Relaxed);
        
        // Try to pop a TypedPointer from the lock-free queue
        if let Some(typed_ptr) = self.free_blocks.pop() {
            // Verify type match
            if typed_ptr.is_valid_for_pool(self.block_size) {
                self.pool_hits.fetch_add(1, Ordering::Relaxed);
                let ptr = typed_ptr.get_ptr();
                
                // Zero memory on allocation
                unsafe {
                    std::ptr::write_bytes(ptr, 0, self.block_size.as_usize());
                }
                
                return Some(ptr);
            } else {
                // Block size mismatch! Record error
                self.type_mismatches.fetch_add(1, Ordering::Relaxed);
                eprintln!("⚠️  Warning: Memory pool block size mismatch! expected={:?}, got={:?}", 
                         self.block_size, typed_ptr.block_size);
            }
        }
        
        // Queue is empty or type mismatch, check if new blocks can be allocated
        let current_count = self.allocated_count.load(Ordering::Relaxed);
        if current_count < self.max_pool_size {
            // Atomically increment count
            match self.allocated_count.compare_exchange_weak(
                current_count, 
                current_count + 1, 
                Ordering::Acquire, 
                Ordering::Relaxed
            ) {
                Ok(_) => {
                    // Successfully incremented count, allocate new memory block
                    let ptr = unsafe {
                        libc::calloc(1, self.block_size.as_usize()) as *mut u8
                    };
                    if !ptr.is_null() {
                        self.pool_hits.fetch_add(1, Ordering::Relaxed);
                        Some(ptr)
                    } else {
                        // Allocation failed, rollback count
                        self.allocated_count.fetch_sub(1, Ordering::Relaxed);
                        self.pool_misses.fetch_add(1, Ordering::Relaxed);
                        None
                    }
                }
                Err(_) => {
                    // CAS failed, other threads might have already filled the pool
                    self.pool_misses.fetch_add(1, Ordering::Relaxed);
                    None
                }
            }
        } else {
            // Pool is full, refuse allocation
            self.pool_misses.fetch_add(1, Ordering::Relaxed);
            None
        }
    }
    
    /// Type-safe deallocation
    fn deallocate(&self, ptr: *mut u8) -> bool {
        if ptr.is_null() {
            return false;
        }
        
        self.pool_deallocations.fetch_add(1, Ordering::Relaxed);
        
        let typed_ptr = TypedPointer::new(ptr, self.block_size);
        
        // Store in lock-free queue
        self.free_blocks.push(typed_ptr);
        true
    }
    
    /// Smart deallocation attempt - let the pool decide whether to accept this pointer
    /// Decide whether to accept based on size match and pool capacity
    fn try_deallocate(&self, ptr: *mut u8) -> bool {
        if ptr.is_null() {
            return false;
        }
        
        // Check if pool still has capacity (prevent unlimited growth)
        let current_free = self.free_blocks.len();
        if current_free >= self.max_pool_size {
            return false; // Pool is full, reject
        }
        
        // Accept this pointer, create TypedPointer and add to queue
        self.pool_deallocations.fetch_add(1, Ordering::Relaxed);
        let typed_ptr = TypedPointer::new(ptr, self.block_size);
        self.free_blocks.push(typed_ptr);
        true
    }
    
    /// Get pool statistics
    fn get_stats(&self) -> PoolStats {
        PoolStats {
            block_size: self.block_size,
            allocated_count: self.allocated_count.load(Ordering::Relaxed),
            free_count: self.free_blocks.len(),
            max_pool_size: self.max_pool_size,
            pool_allocations: self.pool_allocations.load(Ordering::Relaxed),
            pool_deallocations: self.pool_deallocations.load(Ordering::Relaxed),
            pool_hits: self.pool_hits.load(Ordering::Relaxed),
            pool_misses: self.pool_misses.load(Ordering::Relaxed),
            type_mismatches: self.type_mismatches.load(Ordering::Relaxed),
        }
    }
    
    /// Clean up all free memory in the pool
    fn cleanup(&self) {
        while let Some(typed_ptr) = self.free_blocks.pop() {
            if typed_ptr.is_valid_for_pool(self.block_size) {
                unsafe {
                    libc::free(typed_ptr.get_ptr() as *mut std::ffi::c_void);
                }
                self.allocated_count.fetch_sub(1, Ordering::Relaxed);
            } else {
                self.type_mismatches.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
}

impl Drop for TypeSafeMemoryPool {
    fn drop(&mut self) {
        // Release all cached memory blocks
        self.cleanup();
    }
}

// Pool statistics structure
#[derive(Debug, Clone)]
pub struct PoolStats {
    pub block_size: BlockSize,
    pub allocated_count: usize,
    pub free_count: usize,
    pub max_pool_size: usize,
    pub pool_allocations: u64,
    pub pool_deallocations: u64,
    pub pool_hits: u64,
    pub pool_misses: u64,
    pub type_mismatches: u64,  // Block size mismatch statistics
}

/// Flexible high-performance memory manager
/// Uses optional pool array, supports 0 configuration to disable corresponding pools
pub struct DartMemoryManager {
    pools: [Option<TypeSafeMemoryPool>; 6], // 6 optional pools: Tiny, Small, Medium, Large, Huge, XLarge
    stats: LockFreeMemoryStats, // Completely lock-free statistics
    config: PoolConfig, // Save configuration info for statistics and debugging
}

/// Completely atomic operation-based lock-free statistics structure
#[derive(Debug)]
pub struct LockFreeMemoryStats {
    pub direct_allocs: AtomicU64,
    pub direct_deallocs: AtomicU64,
    pub total_allocated_bytes: AtomicU64,
    pub allocation_requests: AtomicU64,  // Total allocation request count
}

impl Default for LockFreeMemoryStats {
    fn default() -> Self {
        Self {
            direct_allocs: AtomicU64::new(0),
            direct_deallocs: AtomicU64::new(0),
            total_allocated_bytes: AtomicU64::new(0),
            allocation_requests: AtomicU64::new(0),
        }
    }
}

/// BlockSize to array index mapping
impl BlockSize {
    /// Get index in pool array
    const fn pool_index(self) -> usize {
        match self {
            BlockSize::Tiny => 0,
            BlockSize::Small => 1,
            BlockSize::Medium => 2,
            BlockSize::Large => 3,
            BlockSize::Huge => 4,
            BlockSize::XLarge => 5,
        }
    }
    
    /// Get BlockSize from index - for debugging and statistics
    const fn from_index(index: usize) -> Option<Self> {
        match index {
            0 => Some(BlockSize::Tiny),
            1 => Some(BlockSize::Small),
            2 => Some(BlockSize::Medium),
            3 => Some(BlockSize::Large),
            4 => Some(BlockSize::Huge),
            5 => Some(BlockSize::XLarge),
            _ => None,
        }
    }
}


#[derive(Debug, Default, Clone)]
pub struct MemoryStats {
    pub pool_hits: u64,
    pub pool_misses: u64,
    pub direct_allocs: u64,
    pub total_allocated: u64,
    pub pool_stats: Vec<PoolStats>,
    pub total_type_mismatches: u64,  // Total block size mismatch count
    pub total_allocation_requests: u64, // Total allocation request count
}

impl DartMemoryManager {
    /// Create memory manager - supports 0 configuration to disable pools
    pub fn with_config(config: PoolConfig) -> Arc<Self> {
        let pools = [
            // Tiny pool (32B)
            config.get_tiny_pool_size()
                .map(|size| TypeSafeMemoryPool::new(BlockSize::Tiny, size)),
            // Small pool (128B)
            config.get_small_pool_size()
                .map(|size| TypeSafeMemoryPool::new(BlockSize::Small, size)),
            // Medium pool (512B)
            config.get_medium_pool_size()
                .map(|size| TypeSafeMemoryPool::new(BlockSize::Medium, size)),
            // Large pool (4KB)
            config.get_large_pool_size()
                .map(|size| TypeSafeMemoryPool::new(BlockSize::Large, size)),
            // Huge pool (16KB)
            config.get_huge_pool_size()
                .map(|size| TypeSafeMemoryPool::new(BlockSize::Huge, size)),
            // XLarge pool (64KB)
            config.get_xlarge_pool_size()
                .map(|size| TypeSafeMemoryPool::new(BlockSize::XLarge, size)),
        ];
        
        Arc::new(Self {
            pools,
            stats: LockFreeMemoryStats::default(),
            config: config.clone(),
        })
    }
    
    pub fn new() -> Arc<Self> {
        // Use default configuration
        Self::with_config(PoolConfig::new())
    }
    
    /// Lock-free allocation
    pub fn allocate(&self, size: usize) -> *mut u8 {
        if size == 0 {
            return ptr::null_mut();
        }
        
        self.stats.allocation_requests.fetch_add(1, Ordering::Relaxed);
        
        let ptr = if let Some(block_size) = BlockSize::for_size(size) {
            // Check if pool exists
            let pool_index = block_size.pool_index();
            
            // Check if corresponding pool is enabled
            if let Some(pool) = &self.pools[pool_index] {
                if let Some(ptr) = pool.allocate() {
                    self.stats.total_allocated_bytes.fetch_add(block_size.as_usize() as u64, Ordering::Relaxed);
                    return ptr;
                }
            }
            // Pool doesn't exist or allocation failed, use direct calloc
            let ptr = unsafe { libc::calloc(1, size) as *mut u8 };
            
            ptr
        } else {
            // Extra large memory uses direct calloc
            let ptr = unsafe { libc::calloc(1, size) as *mut u8 };
            
            ptr
        };
        
        if !ptr.is_null() {
            self.stats.direct_allocs.fetch_add(1, Ordering::Relaxed);
            self.stats.total_allocated_bytes.fetch_add(size as u64, Ordering::Relaxed);
        }
        
        ptr
    }
    
    /// Type-safe deallocation - requires original allocation size
    pub fn deallocate(&self, ptr: *mut u8, size: usize) {
        if ptr.is_null() {
            return;
        }
        
        // Determine which pool to return to based on size
        if let Some(block_size) = BlockSize::for_size(size) {
            let pool_index = block_size.pool_index();
            
            // Check if corresponding pool exists and is enabled
            if let Some(pool) = &self.pools[pool_index] {
                if pool.try_deallocate(ptr) {
                    return; // Successfully returned to correct pool
                }
            }
        }
        
        // Pool doesn't exist or return failed, free directly (possibly directly allocated large memory)
        unsafe {
            libc::free(ptr as *mut std::ffi::c_void);
        }
        self.stats.direct_deallocs.fetch_add(1, Ordering::Relaxed);
    }
    
    /// Get memory statistics
    pub fn stats(&self) -> MemoryStats {
        // Aggregate statistics from all enabled pools
        let mut total_pool_hits = 0u64;
        let mut total_pool_misses = 0u64;
        let mut total_type_mismatches = 0u64;
        let mut pool_stats = Vec::new();
        
        // Traverse optional pool array to collect statistics
        for (i, pool_opt) in self.pools.iter().enumerate() {
            if let Some(pool) = pool_opt {
                let stats = pool.get_stats();
                total_pool_hits += stats.pool_hits;
                total_pool_misses += stats.pool_misses;
                total_type_mismatches += stats.type_mismatches;
                pool_stats.push(stats);
            } else {
                // Pool is disabled, add placeholder statistics
                if let Some(block_size) = BlockSize::from_index(i) {
                    pool_stats.push(PoolStats {
                        block_size,
                        allocated_count: 0,
                        free_count: 0,
                        max_pool_size: 0,
                        pool_allocations: 0,
                        pool_deallocations: 0,
                        pool_hits: 0,
                        pool_misses: 0,
                        type_mismatches: 0,
                    });
                }
            }
        }
        
        MemoryStats {
            pool_hits: total_pool_hits,
            pool_misses: total_pool_misses,
            direct_allocs: self.stats.direct_allocs.load(Ordering::Relaxed),
            total_allocated: self.stats.total_allocated_bytes.load(Ordering::Relaxed),
            pool_stats,
            total_type_mismatches,
            total_allocation_requests: self.stats.allocation_requests.load(Ordering::Relaxed),
        }
    }
    
    /// Clean up memory pools - only clean enabled pools
    pub fn cleanup(&self) {
        // Clean up all enabled pools
        for pool_opt in &self.pools {
            if let Some(pool) = pool_opt {
                pool.cleanup();
            }
        }
    }
    
    /// Statistics printing
    pub fn print_stats(&self) {
        let stats = self.stats();
        println!("Pool hits: {}", stats.pool_hits);
        println!("Pool misses: {}", stats.pool_misses);
        println!("Direct allocations: {}", stats.direct_allocs);
        println!("Total allocated bytes: {}", stats.total_allocated);
        println!("Total allocation requests: {}", stats.total_allocation_requests);
        
        // Pool configuration status display
        println!("=== Memory Pool Configuration Status ===");
        let pool_configs = [
            ("Tiny (32B)", self.config.is_tiny_pool_enabled(), self.config.get_tiny_pool_size()),
            ("Small (128B)", self.config.is_small_pool_enabled(), self.config.get_small_pool_size()),
            ("Medium (512B)", self.config.is_medium_pool_enabled(), self.config.get_medium_pool_size()),
            ("Large (4KB)", self.config.is_large_pool_enabled(), self.config.get_large_pool_size()),
            ("Huge (16KB)", self.config.is_huge_pool_enabled(), self.config.get_huge_pool_size()),
            ("XLarge (64KB)", self.config.is_xlarge_pool_enabled(), self.config.get_xlarge_pool_size()),
        ];
        
        for (name, enabled, size) in pool_configs {
            if enabled {
                println!("✅ {} Pool: Enabled (Capacity: {})", name, size.unwrap_or(0));
            } else {
                println!("❌ {} Pool: Disabled (Configured as 0)", name);
            }
        }
        
        // Architecture advantage statistics
        println!("Block size mismatches: {}", stats.total_type_mismatches);

        
        if stats.total_type_mismatches > 0 {
            println!("⚠️  Warning: Detected {} block size mismatches, please check memory management logic!", stats.total_type_mismatches);
        }
        
        println!("=== Memory Pool Detailed Status ===");
        for (i, pool_stat) in stats.pool_stats.iter().enumerate() {
            let efficiency = if pool_stat.pool_allocations > 0 {
                (pool_stat.pool_hits as f64 / pool_stat.pool_allocations as f64) * 100.0
            } else {
                0.0
            };
            
            let status = if pool_stat.max_pool_size > 0 {
                format!("Enabled - {} total blocks, {} free blocks, {} hits, {} misses, {} size errors, efficiency: {:.2}%",
                    pool_stat.allocated_count,
                    pool_stat.free_count,
                    pool_stat.pool_hits,
                    pool_stat.pool_misses,
                    pool_stat.type_mismatches,
                    efficiency)
            } else {
                "Disabled".to_string()
            };
            
            println!("Pool[{}] {:?}: {}", i, pool_stat.block_size, status);
        }
        
        // Overall performance metrics
        let total_pool_ops = stats.pool_hits + stats.pool_misses;
        if total_pool_ops > 0 {
            println!("=== Overall Performance ===");
            println!("Pool hit rate: {:.2}%", (stats.pool_hits as f64 / total_pool_ops as f64) * 100.0);
            println!("Pool utilization rate: {:.2}%", (total_pool_ops as f64 / (total_pool_ops + stats.direct_allocs) as f64) * 100.0);
            println!("Block size match rate: {:.2}%", 
                if total_pool_ops > 0 {
                    ((total_pool_ops - stats.total_type_mismatches) as f64 / total_pool_ops as f64) * 100.0
                } else {
                    100.0
                }
            );
        }
    }
}

// Singleton memory manager

/// Global singleton memory manager
static GLOBAL_MEMORY_MANAGER: std::sync::OnceLock<Arc<DartMemoryManager>> = std::sync::OnceLock::new();

/// Initialize global memory manager
pub fn initialize_memory_manager() -> bool {
    // Check if already initialized to avoid duplicate initialization
    if is_memory_manager_available() {
        return true;
    }
    initialize_memory_manager_with_config(PoolConfig::new())
}

/// Initialize global memory manager with custom configuration
pub fn initialize_memory_manager_with_config(config: PoolConfig) -> bool {
    if is_memory_manager_available() {
        return true; 
    }
    GLOBAL_MEMORY_MANAGER.set(DartMemoryManager::with_config(config)).is_ok()
}

/// Clean up global memory manager's memory pools
/// Note: This only cleans pool contents, does not remove manager instance
/// Returns true if cleanup was performed, false if manager was not initialized
pub fn destroy_memory_manager() -> bool {
    // Check if manager is initialized before attempting cleanup
    if !is_memory_manager_available() {
        return false;
    }
    
    if let Some(manager) = GLOBAL_MEMORY_MANAGER.get() {
        manager.cleanup();
        true // Cleanup performed successfully
    } else {
        false // This should not happen given the check above, but handle safely
    }
}

/// Check if memory manager is available
pub fn is_memory_manager_available() -> bool {
    GLOBAL_MEMORY_MANAGER.get().is_some()
}

/// Get global memory manager reference - lock-free access, OnceLock ensures safety
fn get_global_manager() -> Option<&'static DartMemoryManager> {
    GLOBAL_MEMORY_MANAGER.get().map(|arc| arc.as_ref())
}

/// Convenient allocation function - automatically initializes manager
pub fn allocate(size: usize) -> *mut u8 {
    // Ensure manager is initialized (safe to call multiple times)
    if !is_memory_manager_available() {
        if !initialize_memory_manager() {
            // Initialization failed, use direct allocation as fallback
            return unsafe { libc::calloc(1, size) as *mut u8 };
        }
    }
    
    if let Some(manager) = get_global_manager() {
        manager.allocate(size)
    } else {
        // This should not happen if initialization succeeded, but handle it safely
        unsafe { libc::calloc(1, size) as *mut u8 }
    }
}

/// Convenient deallocation function - requires original allocation size
pub fn deallocate(ptr: *mut u8, size: usize) {
    if let Some(manager) = get_global_manager() {
        manager.deallocate(ptr, size)
    } else {
        // Manager doesn't exist, free directly
        unsafe { libc::free(ptr as *mut std::ffi::c_void) }
    }
}

/// Get memory statistics - requires manager to be initialized
pub fn memory_stats() -> Option<MemoryStats> {
    get_global_manager().map(|manager| manager.stats())
}