//! Kernel gRPC boundary: generated `kernel.v1` types, client, and ErrorInfo map.
//!
//! The api holds no protocol state. Handlers translate REST ↔ these types and
//! forward every call to the kernel process.

mod client;
mod error_info;
mod pb;

pub use client::{connect_lazy, KernelClient, KernelHandle, KernelRpc};
pub use error_info::{kernel_status_to_api_error, transport_error_to_api_error, ERROR_INFO_DOMAIN};
pub use pb::kernel_v1;

#[cfg(test)]
pub use error_info::{encode_kernel_error_status, ErrorInfo};
