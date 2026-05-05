use thiserror::Error;

#[derive(Error, Debug)]
pub enum RuntimeError {
    #[error("config: {0}")]
    Config(#[from] ConfigError),
    #[error("control: {0}")]
    Control(#[from] ts_control::ControlError),
    #[error("derp: {0}")]
    Derp(#[from] ts_derp::DerpError),
    #[error("wg-engine: {0}")]
    WgEngine(#[from] wg_engine::WgError),
    #[error("netstack: {0}")]
    Netstack(#[from] netstack::NetstackError),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("missing field in config: {0}")]
    MissingConfig(&'static str),
    #[error("internal: {0}")]
    Internal(String),
}

#[derive(Error, Debug)]
pub enum ConfigError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("toml parse: {0}")]
    TomlParse(#[from] toml::de::Error),
    #[error("config not found at {path}; created template — fill in `auth_key` and re-run")]
    TemplateWritten { path: String },
}
