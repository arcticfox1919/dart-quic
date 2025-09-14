/// 
/// High-efficiency binary protocol - for Rust and Dart FFI communication
/// 

/// Protocol version - for backward compatibility
pub const PROTOCOL_VERSION: u8 = 1;

/// Protocol magic number
pub const PROTOCOL_MAGIC: u32 = 0xDABCFE01;

/// Task status
#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaskStatus {
    // === 0x0000 - 0x00FF ===
    Success = 0x0000,          // Task completed successfully, no return data
    SuccessWithData = 0x0001,  // Task completed successfully, has return data
    
    // === 0x0100 - 0x01FF ===
    WorkerShutdown = 0x0100,   // Worker thread shutdown normally

    
    // === 0x9000 - 0x9FFF ===
    UnknownError = 0x9001,     // Unknown error
    
    // === 0xF000 - 0xFFFF ===
    ProtocolError = 0xF001,    // Protocol error
    VersionMismatch = 0xF002,  // Version mismatch
    CorruptedData = 0xF003,    // Data corrupted
}

/// Data type - represents the specific type of data in the payload
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DataType {
    None = 0,        // No data
    Bool = 1,        // Boolean value
    U64 = 2,         // 64-bit unsigned integer
    Bytes = 3,       // Byte array (zero-copy pointer)
    String = 4,      // String (error messages, etc.)
}

/// High-efficiency message header - 16 bytes fixed size, cache-friendly
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct MessageHeader {
    /// Protocol magic number (4 bytes) 
    pub magic: u32,
    /// Protocol version (1 byte)
    pub version: u8,
    /// Data type (1 byte)
    pub data_type: DataType,
    /// Task status (2 bytes) 
    pub status: TaskStatus,
    /// Task ID (8 bytes)
    pub task_id: u64,
}

/// Data payload - corresponds to data types in CommandResult
#[repr(C)]
pub union DataPayload {
    // Basic types - directly embedded, zero-copy
    pub bool_val: bool,
    pub u64_val: u64,
    
    // Complex types - pointer + length
    pub bytes: BytesData,   // Corresponds to CommandResult::WithData
    pub string: StringData, // Corresponds to CommandResult::Error
}

/// Byte data structure
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct BytesData {
    pub ptr: *mut u8,
    pub len: usize,
}

/// String data structure (UTF-8)
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct StringData {
    pub ptr: *const u8,
    pub len: usize,
}

/// Complete task event message structure - 16-byte header + 16-byte payload = 32 bytes
#[repr(C)]
pub struct TaskEventMessage {
    /// Message header (16 bytes)
    pub header: MessageHeader,
    /// Data payload (16-byte union)
    pub payload: DataPayload,
}

impl TaskEventMessage {
    /// Create no-data success message (corresponds to CommandResult::NoData)
    pub fn no_data(task_id: u64) -> Self {
        Self {
            header: MessageHeader {
                magic: PROTOCOL_MAGIC,
                version: PROTOCOL_VERSION,
                status: TaskStatus::Success,
                data_type: DataType::None,
                task_id,
            },
            payload: DataPayload { u64_val: 0 },
        }
    }

    /// Create boolean value message (corresponds to CommandResult::Bool)
    pub fn bool_data(task_id: u64, value: bool) -> Self {
        Self {
            header: MessageHeader {
                magic: PROTOCOL_MAGIC,
                version: PROTOCOL_VERSION,
                status: TaskStatus::SuccessWithData,
                data_type: DataType::Bool,
                task_id,
            },
            payload: DataPayload { bool_val: value },
        }
    }

    /// Create U64 message (corresponds to CommandResult::U64)
    pub fn u64_data(task_id: u64, value: u64) -> Self {
        Self {
            header: MessageHeader {
                magic: PROTOCOL_MAGIC,
                version: PROTOCOL_VERSION,
                status: TaskStatus::SuccessWithData,
                data_type: DataType::U64,
                task_id,
            },
            payload: DataPayload { u64_val: value },
        }
    }

    /// Create byte data message (corresponds to CommandResult::WithData)
    pub fn bytes_data(task_id: u64, data_ptr: *mut u8, data_len: usize) -> Self {
        Self {
            header: MessageHeader {
                magic: PROTOCOL_MAGIC,
                version: PROTOCOL_VERSION,
                status: TaskStatus::SuccessWithData,
                data_type: DataType::Bytes,
                task_id,
            },
            payload: DataPayload {
                bytes: BytesData {
                    ptr: data_ptr,
                    len: data_len,
                },
            },
        }
    }

    /// Create string data message (general string transmission, including error messages)
    pub fn string_data(task_id: u64, status: TaskStatus, text: &str) -> Self {
        let text_bytes = text.as_bytes();
        Self {
            header: MessageHeader {
                magic: PROTOCOL_MAGIC,
                version: PROTOCOL_VERSION,
                status,
                data_type: DataType::String,
                task_id,
            },
            payload: DataPayload {
                string: StringData {
                    ptr: text_bytes.as_ptr(),
                    len: text_bytes.len(),
                },
            },
        }
    }

    /// Convenience method for creating error messages
    pub fn error_message(task_id: u64, error_type: TaskStatus, error_msg: &str) -> Self {
        Self::string_data(task_id, error_type, error_msg)
    }

    /// Create worker thread shutdown message
    pub fn shutdown_message() -> Self {
        Self {
            header: MessageHeader {
                magic: PROTOCOL_MAGIC,
                version: PROTOCOL_VERSION,
                status: TaskStatus::WorkerShutdown,
                data_type: DataType::None,
                task_id: 0,
            },
            payload: DataPayload { u64_val: 0 },
        }
    }

    /// Check if the message is successful
    pub fn is_success(&self) -> bool {
        matches!(self.header.status, TaskStatus::Success | TaskStatus::SuccessWithData)
    }

    /// Check if the message is an error
    pub fn is_error(&self) -> bool {
        !self.is_success() && self.header.status != TaskStatus::WorkerShutdown
    }

    /// Validate message integrity
    pub fn is_valid(&self) -> bool {
        self.header.magic == PROTOCOL_MAGIC && self.header.version == PROTOCOL_VERSION
    }

    /// Get total message size (fixed 32 bytes, zero-copy design)
    pub fn total_size(&self) -> usize {
        // All messages are fixed 32 bytes, data is passed through pointers for zero-copy
        std::mem::size_of::<TaskEventMessage>()
    }
}

/// High-performance serializer - based on TLV design
pub struct MessageSerializer;

impl MessageSerializer {
    /// Serialize message to binary data - fixed 32-byte zero-copy format
    /// 
    /// Format: [Header:16 bytes][Payload:16 bytes] = fixed 32 bytes
    /// 
    /// Design principles:
    /// 1. All messages are fixed 32 bytes for fast transmission and parsing
    /// 2. Basic types (bool, u64) are directly embedded in Payload
    /// 3. Complex types (Bytes, String) are passed through pointers for zero-copy
    /// 4. No copying of long data, maintains high performance
    pub fn serialize(msg: &TaskEventMessage) -> Vec<u8> {
        let msg_size = std::mem::size_of::<TaskEventMessage>();
        let mut buffer = Vec::with_capacity(msg_size);
        
        // Serialize the entire message structure (32 bytes)
        unsafe {
            let msg_bytes = std::slice::from_raw_parts(
                msg as *const _ as *const u8,
                msg_size,
            );
            buffer.extend_from_slice(msg_bytes);
        }
        
        // Note: Do not copy data pointed to by pointers, maintaining zero-copy characteristics
        // DataType::Bytes and DataType::String actual data is referenced by pointers
        // Dart side needs to access original data based on pointer and length
        
        buffer
    }

    /// Deserialize binary data to message
    /// 
    /// # Safety
    /// Caller must ensure data points to valid 32-byte message data
    pub unsafe fn deserialize(data: *const u8, len: usize) -> Option<TaskEventMessage> {
        let msg_size = std::mem::size_of::<TaskEventMessage>();
        if len < msg_size {
            return None;
        }

        // Read fixed 32-byte message
        unsafe {
            let msg = std::ptr::read(data as *const TaskEventMessage);
            
            // Validate protocol integrity
            if !msg.is_valid() {
                return None;
            }
            
            Some(msg)
        }
    }
    
    /// Get data pointed to by pointer (zero-copy access)
    /// 
    /// Note: Data pointed to by pointer is not in the serialization buffer, but at original location
    /// This is the core of zero-copy design - only pass pointers, don't copy data
    /// 
    /// # Safety
    /// Caller must ensure:
    /// 1. Pointer is valid during usage
    /// 2. Memory region pointed to by pointer is readable
    /// 3. Data length is correct
    pub unsafe fn get_data_pointer(msg: &TaskEventMessage) -> Option<(*const u8, usize)> {
        match msg.header.data_type {
            DataType::Bytes => {
                unsafe {
                    let bytes_data = &msg.payload.bytes;
                    if !bytes_data.ptr.is_null() && bytes_data.len > 0 {
                        Some((bytes_data.ptr, bytes_data.len))
                    } else {
                        None
                    }
                }
            }
            DataType::String => {
                unsafe {
                    let string_data = &msg.payload.string;
                    if !string_data.ptr.is_null() && string_data.len > 0 {
                        Some((string_data.ptr, string_data.len))
                    } else {
                        None
                    }
                }
            }
            _ => None,
        }
    }
}

/// Message sender - properly handles Dart memory model
pub struct MessageSender;

impl MessageSender {
    /// Send message to Dart - using Vec<u8>'s IntoDart implementation
    /// 
    pub fn send_to_dart(dart_port: i64, msg: TaskEventMessage) -> bool {
        // Serialize message to byte array
        let binary_data = MessageSerializer::serialize(&msg);
        
        // Send Vec<u8> directly, allo_isolate will automatically handle Dart_CObject creation and memory management
        use allo_isolate::Isolate;
        let isolate = Isolate::new(dart_port);
        isolate.post(binary_data) // Vec<u8> implements IntoDart
    }
}

// Compile-time assertions - ensure struct sizes meet expectations
const _: () = {
    assert!(std::mem::size_of::<MessageHeader>() == 16);
    // DataPayload is a union, size is the size of the largest member (BytesData or StringData = 16 bytes)
    assert!(std::mem::size_of::<DataPayload>() == 16);
    // TaskEventMessage total size: 16-byte header + 16-byte payload = 32 bytes
    assert!(std::mem::size_of::<TaskEventMessage>() == 32);
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_message_sizes() {
        println!("MessageHeader size: {}", std::mem::size_of::<MessageHeader>());
        println!("DataPayload size: {}", std::mem::size_of::<DataPayload>());
        println!("TaskEventMessage size: {}", std::mem::size_of::<TaskEventMessage>());
        
        // Verify alignment
        assert!(std::mem::align_of::<TaskEventMessage>() <= 8);
    }

    #[test]
    fn test_message_creation() {
        let msg = TaskEventMessage::bool_data(123, true);
        assert!(msg.is_valid());
        assert_eq!(msg.header.task_id, 123);
        assert_eq!(msg.header.status, TaskStatus::SuccessWithData);
        assert_eq!(msg.header.data_type, DataType::Bool);
        assert!(msg.is_success());
        
        unsafe {
            assert_eq!(msg.payload.bool_val, true);
        }
    }

    #[test]
    fn test_serialization() {
        let msg = TaskEventMessage::u64_data(456, 0xDEADBEEF12345678);
        let serialized = MessageSerializer::serialize(&msg);
        
        // Verify serialized size is fixed at 32 bytes
        assert_eq!(serialized.len(), std::mem::size_of::<TaskEventMessage>());
        assert_eq!(serialized.len(), 32);
        
        unsafe {
            let deserialized = MessageSerializer::deserialize(
                serialized.as_ptr(),
                serialized.len(),
            ).unwrap();
            
            assert!(deserialized.is_valid());
            assert_eq!(deserialized.header.task_id, 456);
            assert_eq!(deserialized.header.data_type, DataType::U64);
            assert_eq!(deserialized.payload.u64_val, 0xDEADBEEF12345678);
        }
    }

    #[test]
    fn test_string_data() {
        let test_text = "Hello, Dart FFI Protocol!";
        let msg = TaskEventMessage::string_data(789, TaskStatus::SuccessWithData, test_text);
        
        assert!(msg.is_valid());
        assert_eq!(msg.header.task_id, 789);
        assert_eq!(msg.header.status, TaskStatus::SuccessWithData);
        assert_eq!(msg.header.data_type, DataType::String);
        assert!(msg.is_success());
        
        unsafe {
            assert_eq!(msg.payload.string.len, test_text.len());
            let string_slice = std::slice::from_raw_parts(msg.payload.string.ptr, msg.payload.string.len);
            assert_eq!(string_slice, test_text.as_bytes());
        }
    }

    #[test]
    fn test_error_message_convenience() {
        let error_msg = "Something went wrong";
        let msg = TaskEventMessage::error_message(999, TaskStatus::UnknownError, error_msg);
        
        assert!(msg.is_valid());
        assert!(msg.is_error());
        assert_eq!(msg.header.task_id, 999);
        assert_eq!(msg.header.status, TaskStatus::UnknownError);
        assert_eq!(msg.header.data_type, DataType::String);
    }

    #[test]
    fn test_zero_copy_design() {
        let test_data = vec![1, 2, 3, 4, 5];
        let data_ptr = test_data.as_ptr() as *mut u8;
        let data_len = test_data.len();
        
        // Create byte data message, only pass pointer
        let msg = TaskEventMessage::bytes_data(123, data_ptr, data_len);
        
        // Serialization should only be 32 bytes, not including actual data
        let serialized = MessageSerializer::serialize(&msg);
        assert_eq!(serialized.len(), 32);
        
        // Verify pointer and length are saved correctly
        unsafe {
            assert_eq!(msg.payload.bytes.ptr, data_ptr);
            assert_eq!(msg.payload.bytes.len, data_len);
            
            // Access original data through pointer
            if let Some((ptr, len)) = MessageSerializer::get_data_pointer(&msg) {
                let data_slice = std::slice::from_raw_parts(ptr, len);
                assert_eq!(data_slice, &test_data);
            } else {
                panic!("Should be able to get data pointer");
            }
        }
        
        // Test string zero-copy
        let test_string = "Zero copy string test";
        let string_msg = TaskEventMessage::string_data(456, TaskStatus::SuccessWithData, test_string);
        let string_serialized = MessageSerializer::serialize(&string_msg);
        
        // Also only 32 bytes
        assert_eq!(string_serialized.len(), 32);
        
        unsafe {
            if let Some((ptr, len)) = MessageSerializer::get_data_pointer(&string_msg) {
                let str_slice = std::slice::from_raw_parts(ptr, len);
                let recovered_string = std::str::from_utf8(str_slice).unwrap();
                assert_eq!(recovered_string, test_string);
            } else {
                panic!("Should be able to get string pointer");
            }
        }
    }
}
