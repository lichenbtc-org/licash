//! How often the wallet acts, by what it may spend: a monthly budget in
//! sat, shared between the kinds of action. Each kind spends its share
//! evenly over the month: its actions come at a mean interval of its cost
//! over its share's rate, so that a cheap one comes often and a dear one
//! seldom, never more often than its floor, at random moments around that
//! mean. Over any 30 days, a kind spends no more than its share, and all
//! of them no more than the budget; what it cost is what the wallet holds
//! less after it, so a failure's losses count too.

use std::time::Duration;

use serde::Serialize;

use crate::store::Action;

/// The window a budget is spent over.
pub const MONTH: Duration = Duration::from_secs(30 * 24 * 3600);

/// What the wallet does.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    /// A payment to itself within one hub.
    Hub,
    /// A move of notes from one hub to another, through a swap provider.
    Swap,
    /// A payment from one hub to an invoice of another, over Lightning:
    /// no longer made, as hubs pay and make no invoices, and kept for the
    /// moves recorded before.
    Lightning,
    /// A payout on Bitcoin to a deposit address of a hub, through a swap
    /// provider: out of Licash and back in.
    Chain,
}

impl Kind {
    pub const ALL: [Kind; 4] = [Kind::Hub, Kind::Swap, Kind::Lightning, Kind::Chain];

    pub fn key(self) -> &'static str {
        match self {
            Kind::Hub => "hub",
            Kind::Swap => "swap",
            Kind::Lightning => "lightning",
            Kind::Chain => "chain",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|k| k.key() == s)
    }

    /// What it is called on the page.
    pub fn label(self) -> &'static str {
        match self {
            Kind::Hub => "Pay in Licash",
            Kind::Swap => "Move to another hub",
            Kind::Lightning => "Pay over Lightning",
            Kind::Chain => "Out on Bitcoin and back",
        }
    }

    /// Its share of the budget, in percent.
    pub fn share(self) -> u64 {
        match self {
            Kind::Hub => 10,
            Kind::Swap => 30,
            Kind::Lightning => 30,
            Kind::Chain => 30,
        }
    }

    /// The shortest mean interval between two of its actions, however
    /// large the budget.
    pub fn floor(self) -> Duration {
        match self {
            Kind::Hub => Duration::from_secs(10 * 60),
            Kind::Swap | Kind::Lightning => Duration::from_secs(30 * 60),
            Kind::Chain => Duration::from_secs(24 * 3600),
        }
    }
}

/// A kind's share of `monthly`, in sat.
pub fn allowance(kind: Kind, monthly: u64) -> u64 {
    monthly.saturating_mul(kind.share()) / 100
}

/// The mean interval between actions of `kind` costing `cost`, to spend
/// its share of `monthly` evenly; none if one action costs more than its
/// share of a whole month.
pub fn interval(kind: Kind, cost: u64, monthly: u64) -> Option<Duration> {
    let allowance = allowance(kind, monthly);
    let cost = cost.max(1);
    if cost > allowance {
        return None;
    }
    let mean = MONTH.as_secs_f64() * cost as f64 / allowance as f64;
    Some(Duration::from_secs_f64(mean).max(kind.floor()))
}

/// A wait around `mean`: from half of it to half as much again, by
/// `random`, so that no one can tell when the next comes.
pub fn jitter(mean: Duration, random: u64) -> Duration {
    let unit = (random % 1_000_001) as f64 / 1_000_000.0;
    mean.mul_f64(0.5 + unit)
}

/// How long an action took, in ms, as its kind says: the swap's time where
/// it was timed apart (a move on Bitcoin, which leaves out the waits for
/// blocks), else the whole of it. None for one not ended, or for a move on
/// Bitcoin not timed: never the waits for blocks in its stead.
pub fn took(action: &Action) -> Option<u64> {
    if let Some(swapped) = action.swapped {
        return Some(swapped);
    }
    if action.kind == Kind::Chain.key() {
        return None;
    }
    let ended = action.ended?;
    u64::try_from(ended - action.started).ok()
}

/// What `actions` cost, those of `kind` if given.
pub fn spent(actions: &[Action], kind: Option<Kind>) -> u64 {
    actions
        .iter()
        .filter(|a| kind.is_none_or(|k| a.kind == k.key()))
        .filter_map(|a| a.cost)
        .sum()
}

/// Whether an action of `kind` quoted at `cost` fits the budget, given the
/// actions of the last 30 days.
pub fn affordable(kind: Kind, cost: u64, monthly: u64, last_month: &[Action]) -> bool {
    let of_kind = spent(last_month, Some(kind));
    let all = spent(last_month, None);
    of_kind.saturating_add(cost) <= allowance(kind, monthly) && all.saturating_add(cost) <= monthly
}

/// The budget as shown.
#[derive(Clone, Debug, Serialize)]
pub struct Budget {
    /// In sat a month.
    pub monthly: u64,
    /// In the last 30 days.
    pub spent: u64,
    /// What the wallet holds, if known.
    pub balance: Option<u64>,
    pub kinds: Vec<KindBudget>,
    /// What the operator should know: the wallet empty, a hub it can't use.
    pub notes: Vec<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct KindBudget {
    pub kind: Kind,
    pub allowance: u64,
    pub spent: u64,
    /// Whether the wallet does it at all: some need a chain, or two hubs.
    pub enabled: bool,
    /// When it comes next, if planned.
    pub next: Option<i64>,
    /// Why the last try made no move, if it made none: no route, or no
    /// budget for it. Cleared by a move made.
    pub waiting: Option<String>,
}

impl Budget {
    pub fn new(
        monthly: u64,
        last_month: &[Action],
        balance: Option<u64>,
        plans: &[(Kind, bool, Option<i64>)],
    ) -> Self {
        let kinds = plans
            .iter()
            .map(|&(kind, enabled, next)| KindBudget {
                kind,
                allowance: allowance(kind, monthly),
                spent: spent(last_month, Some(kind)),
                enabled,
                next,
                waiting: None,
            })
            .collect();
        Self {
            monthly,
            spent: spent(last_month, None),
            balance,
            kinds,
            notes: Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::Outcome;

    fn action(kind: Kind, cost: u64) -> Action {
        Action {
            id: 0,
            kind: kind.key().into(),
            started: 0,
            ended: Some(1),
            source: None,
            target: None,
            via: None,
            amount: 1000,
            quoted: None,
            cost: Some(cost),
            outcome: Outcome::Done,
            detail: None,
            swapped: None,
        }
    }

    #[test]
    fn cheap_actions_come_more_often_than_dear_ones() {
        let monthly = 30_000;
        let cheap = interval(Kind::Lightning, 3, monthly).unwrap();
        let dear = interval(Kind::Lightning, 300, monthly).unwrap();
        assert!(cheap < dear);
        // 9,000 sat a month at 300 sat: 30 a month, one a day.
        assert_eq!(dear, Duration::from_secs(24 * 3600));
    }

    #[test]
    fn an_interval_never_falls_below_its_floor() {
        let floor = interval(Kind::Hub, 1, 1_000_000_000).unwrap();
        assert_eq!(floor, Kind::Hub.floor());
    }

    #[test]
    fn an_action_dearer_than_a_month_of_its_share_never_comes() {
        // 30% of 1,000 sat is 300 sat.
        assert_eq!(interval(Kind::Chain, 301, 1_000), None);
        assert!(interval(Kind::Chain, 300, 1_000).is_some());
    }

    #[test]
    fn jitter_stays_around_the_mean() {
        let mean = Duration::from_secs(100);
        assert_eq!(jitter(mean, 0), Duration::from_secs(50));
        assert_eq!(jitter(mean, 1_000_000), Duration::from_secs(150));
    }

    #[test]
    fn spending_stops_at_a_kinds_share_and_at_the_budget() {
        let monthly = 1_000;
        let month = vec![action(Kind::Swap, 290)];
        assert!(affordable(Kind::Swap, 10, monthly, &month));
        assert!(!affordable(Kind::Swap, 11, monthly, &month));
        let month = vec![
            action(Kind::Swap, 300),
            action(Kind::Lightning, 300),
            action(Kind::Chain, 300),
            action(Kind::Hub, 95),
        ];
        assert!(affordable(Kind::Hub, 5, monthly, &month));
        assert!(!affordable(Kind::Hub, 6, monthly, &month));
    }
}
