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
}
