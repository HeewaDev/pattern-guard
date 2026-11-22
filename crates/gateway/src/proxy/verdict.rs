//! Fusion: every layer's evidence becomes one action, one deciding layer, the status
//! an enforced block answers with, and the reasons for the log.
//!
//! Rules (unchanged from the original inline code, now unit-tested):
//! * the most severe action wins (`Block > Challenge > Delay > Allow`);
//! * on a tie the signal raised **first** keeps the attribution, so the order of
//!   [`Verdict::raise`] calls in `proxy::handle` is the tie-break order;
//! * every reason is kept, whichever layer wins; an `Allow` signal only adds a reason;
//! * with no winner the layer is [`Layer::Behaviour`] and a block answers with the
//!   block page.

use hyper::StatusCode;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default)]
pub enum Action {
    #[default]
    Allow,
    Delay,
    Challenge,
    Block,
}

impl Action {
    pub fn as_str(self) -> &'static str {
        match self {
            Action::Allow => "allow",
            Action::Delay => "delay",
            Action::Challenge => "challenge",
            Action::Block => "block",
        }
    }
}

/// The component that raised a signal. [`Layer::as_str`] is logged as
/// `pattern_guard.layer` and used as the `blocked_by` metric label: a public contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Layer {
    DenyList,
    Protocol,
    Trap,
    Rule,
    Geo,
    RateLimit,
    Operation,
    ChallengeList,
    Reputation,
    Waf,
    Behaviour,
    DataLeak,
}

impl Layer {
    pub const ALL: [Layer; 12] = [
        Layer::DenyList,
        Layer::Protocol,
        Layer::Trap,
        Layer::Rule,
        Layer::Geo,
        Layer::RateLimit,
        Layer::Operation,
        Layer::ChallengeList,
        Layer::Reputation,
        Layer::Waf,
        Layer::Behaviour,
        Layer::DataLeak,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Layer::DenyList => "deny_list",
            Layer::Protocol => "protocol",
            Layer::Trap => "trap",
            Layer::Rule => "rule",
            Layer::Geo => "geo",
            Layer::RateLimit => "rate_limit",
            Layer::Operation => "operation",
            Layer::ChallengeList => "challenge_list",
            Layer::Reputation => "reputation",
            Layer::Waf => "waf",
            Layer::Behaviour => "behaviour",
            Layer::DataLeak => "data_leak",
        }
    }

    /// Whether an enforced block by this layer counts towards an escalating ban.
    /// Reputation blocks and trap hits don't: they already are bans.
    pub fn counts_towards_bans(self) -> bool {
        !matches!(self, Layer::Reputation | Layer::Trap)
    }
}

/// How an enforced block answers.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum Respond {
    /// 403 with the block page (HTML or JSON by `Accept`).
    #[default]
    BlockPage,
    /// 429 with `Retry-After`.
    TooManyRequests { retry_after: u64 },
    /// A specific status and a short reason (protocol violations, operation checks).
    Status { status: StatusCode, reason: String },
}

impl Respond {
    pub fn status(&self) -> StatusCode {
        match self {
            Respond::BlockPage => StatusCode::FORBIDDEN,
            Respond::TooManyRequests { .. } => StatusCode::TOO_MANY_REQUESTS,
            Respond::Status { status, .. } => *status,
        }
    }
}

/// One layer's evidence.
#[derive(Debug, Clone)]
pub struct Signal {
    pub action: Action,
    pub layer: Layer,
    pub reason: String,
    pub respond: Respond,
}

impl Signal {
    /// A signal whose enforced block answers with the block page.
    pub fn new(action: Action, layer: Layer, reason: impl Into<String>) -> Self {
        Self {
            action,
            layer,
            reason: reason.into(),
            respond: Respond::BlockPage,
        }
    }

    pub fn respond(mut self, respond: Respond) -> Self {
        self.respond = respond;
        self
    }
}

#[derive(Debug, Default)]
pub struct Verdict {
    action: Action,
    winner: Option<(Layer, Respond)>,
    reasons: Vec<String>,
}

impl Verdict {
    /// Adds a signal. A strictly more severe action takes over the attribution.
    pub fn raise(&mut self, s: Signal) {
        if s.action > self.action {
            self.action = s.action;
            self.winner = Some((s.layer, s.respond));
        }
        self.reasons.push(s.reason);
    }

    /// Adds a reason that is not a layer's signal (`clearance`, `banned for …`).
    pub fn note(&mut self, reason: impl Into<String>) {
        self.reasons.push(reason.into());
    }

    /// With challenges disabled, a challenge becomes a block (same layer and response).
    pub fn challenge_disabled(&mut self) {
        if self.action == Action::Challenge {
            self.action = Action::Block;
        }
    }

    /// A valid clearance cookie lifts a challenge or a delay, never a block. Returns
    /// whether it did.
    pub fn clear(&mut self) -> bool {
        let lifted = matches!(self.action, Action::Challenge | Action::Delay);
        if lifted {
            self.action = Action::Allow;
            self.note("clearance");
        }
        lifted
    }

    pub fn action(&self) -> Action {
        self.action
    }

    pub fn layer(&self) -> Layer {
        self.winner.as_ref().map_or(Layer::Behaviour, |(l, _)| *l)
    }

    pub fn respond(&self) -> &Respond {
        self.winner.as_ref().map_or(&Respond::BlockPage, |(_, r)| r)
    }

    pub fn reasons(&self) -> &[String] {
        &self.reasons
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sig(action: Action, layer: Layer) -> Signal {
        Signal::new(action, layer, layer.as_str())
    }

    #[test]
    fn layer_names_are_the_public_contract() {
        let names: Vec<&str> = Layer::ALL.iter().map(|l| l.as_str()).collect();
        assert_eq!(
            names,
            [
                "deny_list",
                "protocol",
                "trap",
                "rule",
                "geo",
                "rate_limit",
                "operation",
                "challenge_list",
                "reputation",
                "waf",
                "behaviour",
                "data_leak"
            ]
        );
    }

    #[test]
    fn most_severe_wins_and_first_keeps_ties() {
        let mut v = Verdict::default();
        v.raise(sig(Action::Delay, Layer::RateLimit));
        v.raise(sig(Action::Block, Layer::Protocol));
        v.raise(sig(Action::Block, Layer::Waf));
        v.raise(sig(Action::Challenge, Layer::Behaviour));
        assert_eq!(v.action(), Action::Block);
        assert_eq!(v.layer(), Layer::Protocol);
        assert_eq!(
            v.reasons(),
            ["rate_limit", "protocol", "waf", "behaviour"].map(String::from)
        );
    }

    #[test]
    fn allow_signals_only_add_reasons() {
        let mut v = Verdict::default();
        v.raise(Signal::new(Action::Allow, Layer::Rule, "rule-log:audit"));
        assert_eq!(v.action(), Action::Allow);
        assert_eq!(v.layer(), Layer::Behaviour);
        assert_eq!(v.respond(), &Respond::BlockPage);
        assert_eq!(v.reasons(), ["rule-log:audit".to_string()]);
    }

    #[test]
    fn the_winner_decides_the_response() {
        let mut v = Verdict::default();
        v.raise(
            sig(Action::Block, Layer::RateLimit)
                .respond(Respond::TooManyRequests { retry_after: 7 }),
        );
        v.raise(sig(Action::Block, Layer::Waf));
        assert_eq!(v.respond(), &Respond::TooManyRequests { retry_after: 7 });
        assert_eq!(v.respond().status(), StatusCode::TOO_MANY_REQUESTS);

        let mut v = Verdict::default();
        v.raise(
            sig(Action::Delay, Layer::RateLimit)
                .respond(Respond::TooManyRequests { retry_after: 7 }),
        );
        v.raise(sig(Action::Block, Layer::Waf));
        assert_eq!(v.layer(), Layer::Waf);
        assert_eq!(v.respond(), &Respond::BlockPage);
    }

    #[test]
    fn disabled_challenge_becomes_a_block_with_the_same_response() {
        let mut v = Verdict::default();
        v.raise(
            sig(Action::Challenge, Layer::RateLimit)
                .respond(Respond::TooManyRequests { retry_after: 3 }),
        );
        v.challenge_disabled();
        assert_eq!(v.action(), Action::Block);
        assert_eq!(v.layer(), Layer::RateLimit);
        assert_eq!(v.respond().status(), StatusCode::TOO_MANY_REQUESTS);
    }

    #[test]
    fn clearance_lifts_challenge_and_delay_but_not_block() {
        for a in [Action::Challenge, Action::Delay] {
            let mut v = Verdict::default();
            v.raise(sig(a, Layer::Behaviour));
            assert!(v.clear());
            assert_eq!(v.action(), Action::Allow);
            assert_eq!(v.reasons().last().map(String::as_str), Some("clearance"));
        }
        let mut v = Verdict::default();
        v.raise(sig(Action::Block, Layer::Waf));
        assert!(!v.clear());
        assert_eq!(v.action(), Action::Block);
    }

    #[test]
    fn bans_and_traps_do_not_escalate_bans() {
        assert!(!Layer::Reputation.counts_towards_bans());
        assert!(!Layer::Trap.counts_towards_bans());
        assert!(Layer::Waf.counts_towards_bans());
        assert!(Layer::RateLimit.counts_towards_bans());
    }
}
