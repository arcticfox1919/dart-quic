use crate::runtime_manager::RuntimeManager;
use std::sync::{Arc, atomic::{AtomicBool, AtomicU64, Ordering}};
use crate::binary_protocol::{TaskEventMessage, MessageSender, TaskStatus};

pub type TaskId = u64;
pub type DartPort = i64;

#[derive(Debug)]
pub struct TaskCommand {
    pub task_id: TaskId,
    pub command_type: u8,
    pub data_ptr: *mut u8,
    pub data_len: usize,
    pub params_ptr: *mut u64,
    pub params_count: usize,
}

unsafe impl Send for TaskCommand {}

#[derive(Debug, PartialEq)]
pub enum CommandResult {
    NoData,
    Bool(bool),
    U64(u64),
    WithData(*mut u8, usize),
    Error(String),
}

pub trait CommandHandler {
    fn handle_command(&self, command: &TaskCommand) -> CommandResult;
}

use once_cell::sync::OnceCell;

pub struct AsyncDartTaskExecutor<H: CommandHandler + Send + Sync + 'static> {
    runtime_manager: Arc<OnceCell<RuntimeManager>>,
    running: Arc<AtomicBool>,
    task_id_counter: Arc<AtomicU64>,
    dart_port: DartPort,
    handler: Arc<H>,
}

impl<H: CommandHandler + Send + Sync + 'static> AsyncDartTaskExecutor<H> {
    pub fn new(dart_port: DartPort, handler: H) -> Self {
        let running = Arc::new(AtomicBool::new(false));
        let task_id_counter = Arc::new(AtomicU64::new(1));
        let handler = Arc::new(handler);
        Self {
            runtime_manager: Arc::new(OnceCell::new()),
            running,
            task_id_counter,
            dart_port,
            handler,
        }
    }

    /// Asynchronously initialize the runtime manager in a separate thread
    pub fn init_runtime(&self, threads: usize) -> TaskId {
        let dart_port = self.dart_port;
        let task_id = self.task_id_counter.fetch_add(1, Ordering::Relaxed);
        let running = Arc::clone(&self.running);
        let runtime_manager = Arc::clone(&self.runtime_manager);
        std::thread::spawn(move || {
            let manager = RuntimeManager::new(threads);
            let set_result = runtime_manager.set(manager);
            let success = set_result.is_ok();
            running.store(success, Ordering::Release);
            // Send event to Dart: true if success, false otherwise
            AsyncDartTaskExecutor::<H>::send_bool_event(dart_port, task_id, success);
        });
        task_id
    }

    /// Submit a task to the async runtime
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
    let handler = Arc::clone(&self.handler);
        let dart_port = self.dart_port;
        if let Some(manager) = self.runtime_manager.get() {
            manager.spawn(async move {
                let result = handler.handle_command(&command);
                match result {
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
                        Self::send_bytes_event(dart_port, command.task_id, data_ptr, data_len);
                    }
                    CommandResult::Error(error) => {
                        Self::send_error_event_static(dart_port, command.task_id, &error);
                    }
                }
            });
        } else {
            Self::send_error_event_static(dart_port, command.task_id, "Runtime not initialized");
        }
        task_id
    }

    pub fn shutdown(&mut self) {
        self.running.store(false, Ordering::Release);
    }

    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::Acquire)
    }

    fn send_success_event(dart_port: DartPort, task_id: TaskId) {
        let msg = TaskEventMessage::no_data(task_id);
        MessageSender::send_to_dart(dart_port, msg);
    }
    fn send_bool_event(dart_port: DartPort, task_id: TaskId, value: bool) {
        let msg = TaskEventMessage::bool_data(task_id, value);
        MessageSender::send_to_dart(dart_port, msg);
    }
    fn send_u64_event(dart_port: DartPort, task_id: TaskId, value: u64) {
        let msg = TaskEventMessage::u64_data(task_id, value);
        MessageSender::send_to_dart(dart_port, msg);
    }
    fn send_bytes_event(dart_port: DartPort, task_id: TaskId, data_ptr: *mut u8, data_len: usize) {
        let msg = TaskEventMessage::bytes_data(task_id, data_ptr, data_len);
        MessageSender::send_to_dart(dart_port, msg);
    }
    fn send_error_event_static(dart_port: DartPort, task_id: TaskId, error_msg: &str) {
        let msg = TaskEventMessage::string_data(task_id, TaskStatus::UnknownError, error_msg);
        MessageSender::send_to_dart(dart_port, msg);
    }
}
