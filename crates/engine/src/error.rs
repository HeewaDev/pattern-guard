use std::path::PathBuf;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("failed to read config from {0}: {1}")]
    ConfigLoad(PathBuf, #[source] std::io::Error),

    #[error("invalid config: {0}")]
    ConfigParse(#[source] toml::de::Error),

    #[error("invalid config: {0}")]
    ConfigInvalid(String),

    #[error("failed to read model from {0}: {1}")]
    ModelLoad(PathBuf, #[source] std::io::Error),

    #[error("invalid model: {0}")]
    ModelParse(String),

    /// A snapshot written in another format (an older or newer build).
    #[error("snapshot format {found} is not supported (this build reads format {expected})")]
    SnapshotVersion { found: u32, expected: u32 },

    /// A snapshot of another feature layout or key hashing (another build).
    #[error("snapshot was taken by a build with another feature layout or key hashing")]
    SnapshotLayout,

    /// A valid snapshot this guard can't use (its time source or clock).
    #[error("snapshot can't be restored: {0}")]
    SnapshotIncompatible(String),

    /// Truncated or malformed snapshot data.
    #[error("invalid snapshot: {0}")]
    SnapshotInvalid(String),
}
