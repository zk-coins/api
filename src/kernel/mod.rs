//! Kernel gRPC boundary: generated `kernel.v1` types, client, and ErrorInfo map.
//!
//! This module is the kernel client and ErrorInfo map. Health, GET `/`, and
//! Grant-Revoke are API-local and do not go through this module.

mod client;
mod error_info;
mod pb;

pub use client::{connect_lazy, KernelClient, KernelHandle, KernelRpc};
pub use error_info::{
    kernel_status_to_api_error, kernel_status_to_api_error_for, transport_error_to_api_error,
    KernelProcedure, ERROR_INFO_DOMAIN,
};
pub use pb::kernel_v1;

#[cfg(test)]
pub use error_info::{encode_kernel_error_status, ErrorInfo};
