pub mod doctor;
pub mod error;

#[cfg(not(target_os = "linux"))]
pub mod stub;

#[cfg(target_os = "linux")]
pub mod linux;

pub use doctor::{run_doctor, DoctorReport, ProbeResult, ProbeStatus};
pub use error::{Result, SandboxError};

#[cfg(not(target_os = "linux"))]
pub use stub::SandboxRunner;

#[cfg(target_os = "linux")]
pub use linux::SandboxRunner;
