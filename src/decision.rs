use std::time::Duration;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    Allow,
    Warn,
    Delay(Duration),
    Block,
}
