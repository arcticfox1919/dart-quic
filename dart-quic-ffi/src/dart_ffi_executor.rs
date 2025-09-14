use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::ptr;
use std::time::Duration;
use std::sync::mpsc::{self, Receiver, Sender};

// Binary protocol
use crate::binary_protocol::{TaskEventMessage, MessageSender, TaskStatus};

/// Task ID type
pub type TaskId = u64;

/// Dart Native Port type
pub type DartPort = i64;

/// Task command
#[derive(Debug)]
pub struct TaskCommand {
    pub task_id: TaskId,
    pub command_type: u8,  // Specific meaning defined by external business logic
    pub data_ptr: *mut u8, // Zero-copy data pointer
    pub data_len: usize,
    /// Parameter list pointer (zero-copy)
    pub params_ptr: *mut u64,
    /// Parameter count
    pub params_count: usize,
}

unsafe impl Send for TaskCommand {}

/// Command processing result
#[derive(Debug, PartialEq)]
pub enum CommandResult {
    /// No return data
    NoData,
    /// Return boolean value
    Bool(bool),
    /// Return 64-bit unsigned integer
    U64(u64),
    /// Has return data - zero-copy, memory ownership transferred to Dart
    /// (data_ptr: data pointer, data_len: data length)
    /// Note: Dart side must call dart_free_memory to release this memory
    WithData(*mut u8, usize),
    /// Return error
    Error(String),
}

/// Command handler trait
pub trait CommandHandler {
    /// Handle specific command
    /// 
    /// # Arguments
    /// * `command` - Command to process
    /// 
    /// # Returns
    /// Command processing result
    fn handle_command(&self, command: &TaskCommand) -> CommandResult;
}

/// Generic Dart FFI task executor
pub struct DartTaskExecutor<H: CommandHandler + Send + 'static> {
    /// Command sender (unique channel)
    command_sender: Sender<TaskCommand>,
    /// Worker thread handle
    thread_handle: Option<JoinHandle<()>>,
    /// Running state
    running: Arc<AtomicBool>,
    /// Task ID counter
    task_id_counter: Arc<AtomicU64>,
    /// Dart Native Port
    dart_port: DartPort,
    /// Prevent H from being optimized away
    _handler: std::marker::PhantomData<H>,
}

/// Internal shutdown command type
const SHUTDOWN_COMMAND: u8 = 255;

impl<H: CommandHandler + Send + 'static> DartTaskExecutor<H> {
    /// Create new Dart FFI task executor
    /// 
    /// # Arguments
    /// * `dart_port` - Dart Native Port for sending events
    /// * `handler` - Command handler implementation
    /// 
    /// # Returns
    /// New executor instance
    pub fn new(dart_port: DartPort, handler: H) -> Self {
        let (command_sender, command_receiver) = mpsc::channel();

        let running = Arc::new(AtomicBool::new(true));
        let running_clone = Arc::clone(&running);

        // Create worker thread
        let thread_handle = thread::Builder::new()
            .name("quic-worker".to_string())
            .spawn(move || {
                Self::worker_thread(command_receiver, dart_port, running_clone, handler);
            })
            .expect("Failed to spawn worker thread");

        Self {
            command_sender,
            thread_handle: Some(thread_handle),
            running,
            task_id_counter: Arc::new(AtomicU64::new(1)),
            dart_port,
            _handler: std::marker::PhantomData,
        }
    }

    /// Submit task
    /// 
    /// # Arguments
    /// * `command_type` - Command type
    /// * `data_ptr` - Data pointer (can be null)
    /// * `data_len` - Data length
    /// * `params_ptr` - Parameter array pointer (can be null)
    /// * `params_count` - Parameter count
    /// 
    /// # Returns
    /// Task ID
    /// 
    /// # Safety
    /// Caller must ensure data_ptr and params_ptr are valid during task execution
    pub unsafe fn submit_task(
        &self,
        command_type: u8,
        data_ptr: *mut u8,
        data_len: usize,
        params_ptr: *mut u64,
        params_count: usize,
    ) -> TaskId {
        let task_id = self.task_id_counter.fetch_add(1, Ordering::Relaxed);

        let command = TaskCommand {
            task_id,
            command_type,
            data_ptr,
            data_len,
            params_ptr,
            params_count,
        };

        // Send command to worker thread
        if let Err(_) = self.command_sender.send(command) {
            const ERROR_MSG: &str = "Worker thread not available";
            Self::send_error_event_static(self.dart_port, task_id, ERROR_MSG);
        }

        task_id
    }

    /// Safely shutdown executor
    pub fn shutdown(&mut self, timeout: Option<Duration>) -> bool {
        self.running.store(false, Ordering::Release);
        
        // Send shutdown command
        let shutdown_command = TaskCommand {
            task_id: 0,
            command_type: SHUTDOWN_COMMAND,
            data_ptr: ptr::null_mut(),
            data_len: 0,
            params_ptr: ptr::null_mut(),
            params_count: 0,
        };
        
        let _ = self.command_sender.send(shutdown_command);

        if let Some(handle) = self.thread_handle.take() {
            match timeout {
                Some(duration) => {
                    let start = std::time::Instant::now();
                    loop {
                        if handle.is_finished() {
                            let _ = handle.join();
                            return true;
                        }
                        
                        if start.elapsed() >= duration {
                            return false;
                        }
                        
                        std::thread::sleep(std::time::Duration::from_millis(10));
                    }
                }
                None => {
                    handle.join().is_ok()
                }
            }
        } else {
            true
        }
    }

    /// Check if running
    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::Acquire)
    }

    /// Worker thread main loop
    fn worker_thread(
        command_receiver: Receiver<TaskCommand>,
        dart_port: DartPort,
        running: Arc<AtomicBool>,
        handler: H,
    ) {
        println!("Dart FFI worker thread started with handler");

        let mut processed_count = 0u64;

        while running.load(Ordering::Acquire) {
            match command_receiver.recv() {
                Ok(command) => {
                    if command.command_type == SHUTDOWN_COMMAND {
                        println!("Worker thread shutting down");
                        break;
                    }

                    processed_count += 1;
                    
                    // Use handler to process command, send events based on result type
                    match handler.handle_command(&command) {
                        CommandResult::NoData => {
                            Self::send_success_event(dart_port, command.task_id);
                        }
                        CommandResult::Bool(value) => {
                            Self::send_bool_event(dart_port, command.task_id, value);
                        }
                        CommandResult::U64(value) => {
                            Self::send_u64_event(dart_port, command.task_id, value);
                        }
                        CommandResult::WithData(data_ptr, data_len) => {
                            // Zero-copy solution: send pointer directly, ownership transferred to Dart
                            Self::send_bytes_event(dart_port, command.task_id, data_ptr, data_len);
                        }
                        CommandResult::Error(error) => {
                            Self::send_error_event_static(dart_port, command.task_id, &error);
                        }
                    }
                }
                Err(_) => {
                    println!("Command channel closed");
                    break;
                }
            }
        }

        Self::send_shutdown_event(dart_port);
        println!("Dart FFI worker thread finished. Processed {} commands", processed_count);
    }

    /// Send no-data success event
    fn send_success_event(dart_port: DartPort, task_id: TaskId) {
        let msg = TaskEventMessage::no_data(task_id);
        MessageSender::send_to_dart(dart_port, msg);
    }

    /// Send boolean value event
    fn send_bool_event(dart_port: DartPort, task_id: TaskId, value: bool) {
        let msg = TaskEventMessage::bool_data(task_id, value);
        MessageSender::send_to_dart(dart_port, msg);
    }

    /// Send U64 event
    fn send_u64_event(dart_port: DartPort, task_id: TaskId, value: u64) {
        let msg = TaskEventMessage::u64_data(task_id, value);
        MessageSender::send_to_dart(dart_port, msg);
    }

    /// Send byte data event (zero-copy)
    fn send_bytes_event(dart_port: DartPort, task_id: TaskId, data_ptr: *mut u8, data_len: usize) {
        let msg = TaskEventMessage::bytes_data(task_id, data_ptr, data_len);
        MessageSender::send_to_dart(dart_port, msg);
    }

    /// Send error event
    fn send_error_event(&self, task_id: TaskId, error_msg: &str) {
        Self::send_error_event_static(self.dart_port, task_id, error_msg);
    }

    /// Send error event (static version)
    fn send_error_event_static(dart_port: DartPort, task_id: TaskId, error_msg: &str) {
        let msg = TaskEventMessage::string_data(task_id, TaskStatus::UnknownError, error_msg);
        MessageSender::send_to_dart(dart_port, msg);
    }

    /// Send shutdown event
    fn send_shutdown_event(dart_port: DartPort) {
        let msg = TaskEventMessage::shutdown_message();
        MessageSender::send_to_dart(dart_port, msg);
    }
}

impl<H: CommandHandler + Send + 'static> Drop for DartTaskExecutor<H> {
    fn drop(&mut self) {
        if self.is_running() {
            println!("Auto-shutting down Dart FFI executor");
            self.shutdown(Some(Duration::from_secs(5)));
        }
    }
}

/// Default command handler implementation - for testing and backward compatibility
#[derive(Debug, Clone)]
pub struct DefaultCommandHandler;

impl CommandHandler for DefaultCommandHandler {
    fn handle_command(&self, command: &TaskCommand) -> CommandResult {
        match command.command_type {
            1 => {
                // Example: echo command - return boolean value
                println!("DefaultCommandHandler: processing echo command ID={}", command.task_id);
                CommandResult::Bool(true)
            }
            2 => {
                // Example: calculation command - return numeric value
                println!("DefaultCommandHandler: processing calculation command ID={}", command.task_id);
                CommandResult::U64(42)
            }
            3 => {
                // Example: no data return
                println!("DefaultCommandHandler: processing no-data command ID={}", command.task_id);
                CommandResult::NoData
            }
            _ => {
                println!("DefaultCommandHandler: unknown command type {} ID={}", command.command_type, command.task_id);
                CommandResult::Error(format!("Unknown command type: {}", command.command_type))
            }
        }
    }
}
