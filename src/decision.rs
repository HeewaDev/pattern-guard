use std::time::Duration;

/// Recommended action. Pattern-Guard never enforces; the caller does.
///
/// Ordered from least to most severe: `Allow < Warn < Delay < Challenge < Block`.
/// `Challenge` is only produced when `challenge_below` is configured; it means
/// "probably automated — ask for proof of a human (CAPTCHA, JS check, re-auth)".
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    Allow,
    Warn,
    Delay(Duration),
    Challenge,
    Block,
}

impl Decision {
    /// True for decisions that should stop or slow the request (Delay, Challenge, Block).
    pub fn is_mitigation(&self) -> bool {
        matches!(
            self,
            Decision::Delay(_) | Decision::Challenge | Decision::Block
        )
    }

    pub fn label(&self) -> &'static str {
        match self {
            Decision::Allow => "allow",
            Decision::Warn => "warn",
            Decision::Delay(_) => "delay",
            Decision::Challenge => "challenge",
            Decision::Block => "block",
        }
    }
}
