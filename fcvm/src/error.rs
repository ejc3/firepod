use thiserror::Error;

#[derive(Error, Debug)]
pub enum VmError {
    #[error("Firecracker API error: {0}")]
    FirecrackerApi(String),

    #[error("Network error: {0}")]
    Network(String),

    #[error("Disk error: {0}")]
    Disk(String),

    #[error("Snapshot error: {0}")]
    Snapshot(String),

    #[error("State error: {0}")]
    State(String),

    #[error("VM not found: {0}")]
    VmNotFound(String),

    #[error("Snapshot not found: {0}")]
    SnapshotNotFound(String),

    #[error("Invalid configuration: {0}")]
    InvalidConfig(String),

    #[error("Permission denied: {0}")]
    PermissionDenied(String),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("YAML error: {0}")]
    Yaml(#[from] serde_yaml::Error),

    #[error("HTTP error: {0}")]
    Http(String),

    #[error("Process error: {0}")]
    Process(String),

    #[error("Timeout: {0}")]
    Timeout(String),

    #[error("Other error: {0}")]
    Other(#[from] anyhow::Error),
}

pub type Result<T> = std::result::Result<T, VmError>;
