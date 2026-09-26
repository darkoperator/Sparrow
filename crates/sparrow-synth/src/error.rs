#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("scenario: {0}")]
    Scenario(String),
    #[error("{0}")]
    Invalid(String),
    #[error("{path}: {source}")]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("yaml: {0}")]
    Yaml(#[from] serde_norway::Error),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("sparrow: {0}")]
    Core(String),
}

pub type Result<T> = std::result::Result<T, Error>;

impl Error {
    pub fn io(path: impl AsRef<std::path::Path>, source: std::io::Error) -> Error {
        Error::Io {
            path: path.as_ref().display().to_string(),
            source,
        }
    }
}
