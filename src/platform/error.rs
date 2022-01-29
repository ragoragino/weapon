#[derive(Debug, thiserror::Error)]
pub enum DeviceError {
    #[error("io error: `{0}`")]
    IOError(#[from] std::io::Error),
    #[error("system error: `{0}`")]
    SysError(#[from] nix::errno::Errno),
    #[error("{0}")]
    UnexpectedError(String),
}