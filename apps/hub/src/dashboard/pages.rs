//! The hub's records as the pages its operator reads.

use std::collections::{BTreeMap, HashSet};
use std::path::Path;

use licash_contracts::hub::Summary;
use licash_dashboard::{
    grouped, Better, Card, Cell, Check, Column, Measure, Page, Panel, Ref, Report, Row, Table,
    Tone, Unit, Value,
};
use licash_hub::{Notice, Settled};

use super::{
    flows, levels, lock_kinds, reason, set_name, Records, CONTRACT, DEPOSIT, HOLDERS, HUB, LOCK,
    LOCKED, PAY, RECEIVE, RECENT, TRANSFER,
};

const DAY: i64 = 86_400;

/// Blocks to a lock's expiry, or a contract's close, that call for a look.
const SOON: i64 = 6;
const CLOSING: i64 = 1_008;

/// What is true of the hub now, beside its series.
struct Now {
    tip: Option<i64>,
    holders: i64,
    /// Signed and not closed as far as the chain scanned: an approximation,
    /// as F may never have confirmed.
    live: Vec<Summary>,
    under_way: usize,
}

impl Now {
    fn of(r: &Records) -> Self {
        let level = |label: &str| -> i64 {
            let notes = r.notes.movements.iter();
            let moved = notes.filter(|m| (if m.hub { HUB } else { HOLDERS }) == label);
            moved
                .map(|m| (if m.issued { 1 } else { -1 }) * m.denom as i64)
                .sum()
        };
        let tip = r.tip.map(i64::from);
        let live = r
            .openings
            .iter()
            .filter(|o| o.signed && !o.abandoned)
            .filter(|o| match (&o.terms, tip) {
                (Some(t), Some(tip)) => i64::from(t.close) > tip,
                _ => true,
            })
            .cloned()
            .collect();
        Self {
            tip,
            holders: level(HOLDERS),
            live,
            under_way: r
                .openings
                .iter()
                .filter(|o| !o.signed && !o.abandoned)
                .count(),
        }
    }

    fn collateral(&self) -> i64 {
        let terms = self.live.iter().filter_map(|o| o.terms.as_ref());
        terms.map(|t| t.graph as i64).sum()
    }

    fn protected(&self) -> i64 {
        let terms = self.live.iter().filter_map(|o| o.terms.as_ref());
        terms.map(|t| t.cap as i64).sum()
    }
}

pub(super) fn report(r: &Records, now: i64, service: Check, data: &Path) -> Report {
    let state = Now::of(r);
    let mut series = flows(r);
    series.extend(levels(r));
    let failures = failures(&series[2]);
    let mut checks = checks(r, &state, now, service);
    checks.push(payouts(r, data));
    // Where its records are; how far it follows the chain is its health's.
    let subtitle = data.display().to_string();
    let pages = vec![
        overview(&state, checks.clone(), recent(r)),
        payments(r, &state, failures),
        fees(),
        reserves(&state),
        contracts(r, &state),
        privacy(r),
        Page::new(
            "Health",
            vec![vec![Panel::Health(checks), Panel::Table(alerts(r))]],
        ),
    ];
    Report {
        title: "licash hub".into(),
        subtitle,
        now,
        since: r.created_at,
        series,
        pages,
    }
}

fn total(title: &str, of: Ref, better: Better) -> Card {
    Card::new(title, Value::of(of), better)
}

fn now_sat(title: &str, value: i64, detail: impl Into<String>) -> Card {
    Card::new(
        title,
        Value::now(Some(value), Unit::Sat, detail, Tone::Normal),
        Better::Neither,
    )
}

/// The payments made, of every kind, over those and the failed ones.
fn success() -> Value {
    Value::Ratio {
        num: vec![Ref::count("volume")],
        den: vec![Ref::count("volume"), Ref::count("failures")],
    }
}

fn collateral(state: &Now) -> Card {
    let (collateral, protected) = (state.collateral(), state.protected());
    let detail = match protected {
        0 => "no contract live".to_owned(),
        p => format!(
            "{:.0}x the {} sat it protects",
            collateral as f64 / p as f64,
            grouped(p)
        ),
    };
    now_sat("Collateral", collateral, detail)
}

fn protected(state: &Now) -> Card {
    let (protected, holders) = (state.protected(), state.holders.max(0));
    let detail = match holders {
        _ if protected == 0 => "no contract live".to_owned(),
        0 => "of no notes outstanding".to_owned(),
        h => format!(
            "{:.0}% of the holders' notes",
            100.0 * protected.min(h) as f64 / h as f64
        ),
    };
    now_sat("Protected", protected, detail)
}

fn overview(state: &Now, checks: Vec<Check>, recent: Table) -> Page {
    Page::new(
        "Overview",
        vec![
            vec![Panel::Cards(vec![
                total("Volume", Ref::sum("volume"), Better::Up),
                total("Payments", Ref::count("volume"), Better::Up),
                total("Fees", Ref::sum("fees"), Better::Up),
                Card::new("Success", success(), Better::Up),
                total("Notes outstanding", Ref::level("ecash"), Better::Neither),
                collateral(state),
            ])],
            // Fees and notes outstanding are charted on their own pages.
            vec![
                Panel::Health(checks),
                Panel::chart("Volume", "volume", Measure::Sum),
            ],
            vec![Panel::Table(recent)],
        ],
    )
}

fn fees() -> Page {
    let paid = [TRANSFER, LOCK, PAY, RECEIVE, DEPOSIT];
    let rate = Value::Ratio {
        num: paid.iter().map(|k| Ref::sum("fees").of(k)).collect(),
        den: vec![Ref::sum("volume")],
    };
    Page::new(
        "Fees",
        vec![
            vec![Panel::Cards(vec![
                total("Fees", Ref::sum("fees"), Better::Up),
                Card::new("Of the volume", rate, Better::Neither),
                total("Transfers", Ref::sum("fees").of(TRANSFER), Better::Up),
                total("Lightning, gross", Ref::sum("fees").of(PAY), Better::Up),
                total("Contracts", Ref::sum("fees").of(CONTRACT), Better::Up),
            ])],
            vec![
                Panel::chart("Fees by kind", "fees", Measure::Sum),
                Panel::breakdown(
                    "Fees by kind",
                    "fees",
                    vec![
                        Column::value("fees", Ref::sum("fees")),
                        Column::share("share", Ref::sum("fees")),
                        Column::change("change", Ref::sum("fees")),
                        Column::per_day("per day", Ref::sum("fees")),
                    ],
                ),
            ],
        ],
    )
}

fn reserves(state: &Now) -> Page {
    Page::new(
        "Reserves",
        vec![
            vec![Panel::Cards(vec![
                total("Outstanding", Ref::level("ecash"), Better::Neither),
                total("Holders'", Ref::level("ecash").of(HOLDERS), Better::Up),
                total("Hub's own", Ref::level("ecash").of(HUB), Better::Up),
                total(
                    "Behind locks",
                    Ref::level("ecash").of(LOCKED),
                    Better::Neither,
                ),
                collateral(state),
                protected(state),
            ])],
            vec![
                Panel::chart("Notes outstanding", "ecash", Measure::Level),
                Panel::breakdown(
                    "Where the notes are",
                    "ecash",
                    vec![
                        Column::value("now", Ref::level("ecash")),
                        Column::share("share", Ref::level("ecash")),
                        Column::value("moved", Ref::sum("ecash")),
                        Column::per_day("per day", Ref::sum("ecash")),
                    ],
                ),
            ],
        ],
    )
}

fn payments(r: &Records, state: &Now, failures: Table) -> Page {
    let count = |title: &str, kind: &str| total(title, Ref::count("volume").of(kind), Better::Up);
    Page::new(
        "Payments",
        vec![
            vec![Panel::Cards(vec![
                count("Transfers", TRANSFER),
                count("Locks", LOCK),
                count("Lightning out", PAY),
                count("Lightning in", RECEIVE),
                count("Deposits", DEPOSIT),
                total("Failed", Ref::count("failures"), Better::Down),
                total("Never paid", Ref::count("unpaid"), Better::Down),
            ])],
            vec![
                Panel::chart("Payments", "volume", Measure::Count),
                Panel::breakdown(
                    "By kind",
                    "volume",
                    vec![
                        Column::value("volume", Ref::sum("volume")),
                        Column::value("count", Ref::count("volume")),
                        Column::share("share", Ref::sum("volume")),
                        Column::change("change", Ref::sum("volume")),
                        Column::per_day("per day", Ref::sum("volume")),
                    ],
                ),
            ],
            vec![
                Panel::Table(under_way(r, state)),
                Panel::breakdown(
                    "Failures by reason",
                    "failures",
                    vec![
                        Column::value("failed", Ref::count("failures")),
                        Column::value("amount", Ref::sum("failures")),
                        Column::change("change", Ref::count("failures")),
                    ],
                ),
            ],
            vec![Panel::Table(failures)],
        ],
    )
}

/// The payments under way: open locks, invoices and deposit addresses,
/// the soonest to expire first.
fn under_way(r: &Records, state: &Now) -> Table {
    let kinds = lock_kinds(r);
    let paying: HashSet<[u8; 32]> = r
        .forwards
        .iter()
        .filter(|f| f.state == "pending")
        .map(|f| f.lock)
        .collect();
    let mut rows: Vec<(i64, Row)> = Vec::new();
    for lock in r.locks.iter().filter(|l| l.settled_at.is_none()) {
        let left = state.tip.map(|tip| i64::from(lock.expiry) - tip);
        let kind = kinds.get(&lock.id).copied().unwrap_or(LOCK);
        let what = match kind {
            PAY if paying.contains(&lock.id) => "paying out",
            PAY => "to pay out",
            RECEIVE => "paid in, settling",
            DEPOSIT => "deposited, settling",
            _ => "awaiting its preimage",
        };
        let tone = match left {
            Some(left) if left <= SOON => Tone::Warn,
            _ => Tone::Normal,
        };
        rows.push((
            left.unwrap_or(i64::MAX),
            Row::new(
                None,
                tone,
                vec![
                    Cell::Time(lock.created_at as i64),
                    Cell::Text(kind.into()),
                    Cell::Sat(lock.amount as i64),
                    left.map_or(Cell::Empty, Cell::Blocks),
                    Cell::Text(what.into()),
                ],
            ),
        ));
    }
    let asked = |at: i64, kind: &str, amount: u64, what: &str| {
        Row::new(
            None,
            Tone::Muted,
            vec![
                Cell::Time(at),
                Cell::Text(kind.into()),
                Cell::Sat(amount as i64),
                Cell::Empty,
                Cell::Text(what.into()),
            ],
        )
    };
    for x in r.receipts.iter().flatten().filter(|x| x.state == "open") {
        rows.push((
            i64::MAX,
            asked(x.created_at, RECEIVE, x.msat / 1000, "invoice open"),
        ));
    }
    let deposits = r.deposits.iter().flatten();
    for x in deposits.filter(|x| x.state == "open" && x.lock.is_none()) {
        let what = match x.confirmed {
            true => "confirmed, to lock",
            false => "awaiting payment",
        };
        rows.push((i64::MAX, asked(x.created_at, DEPOSIT, x.pays, what)));
    }
    rows.sort_by_key(|(left, row)| (*left, std::cmp::Reverse(time(row))));
    Table::now(
        "Under way",
        &["since", "kind", "amount", "expires", "state"],
        rows.into_iter().map(|(_, row)| row).collect(),
        "nothing under way",
    )
}

fn time(row: &Row) -> i64 {
    match row.cells.first() {
        Some(Cell::Time(t)) => *t,
        _ => 0,
    }
}

/// Each failed payment, newest first, as its series has it.
fn failures(series: &licash_dashboard::Series) -> Table {
    let mut rows: Vec<Row> = series
        .facts
        .iter()
        .map(|f| {
            let reason = &series.labels[f.label as usize];
            Row::new(
                Some(f.at),
                Tone::Bad,
                vec![
                    Cell::Time(f.at),
                    Cell::Sat(f.value),
                    Cell::Text(reason.clone()),
                ],
            )
        })
        .collect();
    rows.sort_by_key(|row| std::cmp::Reverse(row.at));
    Table::in_range(
        "Failed payments",
        &["when", "amount", "reason"],
        rows,
        "no payment failed",
    )
}

fn contracts(r: &Records, state: &Now) -> Page {
    let live = state.live.len() as i64;
    let mocks = state.live.iter().filter(|o| o.mock).count();
    let detail = match (mocks, state.under_way) {
        (0, 0) => "signed, not closed".to_owned(),
        (0, n) => format!("{n} more under way"),
        (m, _) => format!("{m} under mock proofs: they protect nothing"),
    };
    let tone = if mocks > 0 { Tone::Warn } else { Tone::Normal };
    Page::new(
        "Contracts",
        vec![
            vec![Panel::Cards(vec![
                Card::new(
                    "Live",
                    Value::now(Some(live), Unit::Count, detail, tone),
                    Better::Neither,
                ),
                collateral(state),
                protected(state),
                total("Opening fees", Ref::sum("fees").of(CONTRACT), Better::Up),
                total("Signed", Ref::count("openings").of("signed"), Better::Up),
                total(
                    "Given up",
                    Ref::count("openings").of("given up"),
                    Better::Down,
                ),
            ])],
            vec![Panel::Table(openings(r, state))],
        ],
    )
}

fn openings(r: &Records, state: &Now) -> Table {
    let live: HashSet<[u8; 32]> = state.live.iter().map(|o| o.id).collect();
    let mut rows: Vec<Row> = Vec::new();
    for o in r.openings.iter().rev().filter(|o| !o.abandoned) {
        let left = match (&o.terms, state.tip) {
            (Some(t), Some(tip)) => Some(i64::from(t.close) - tip),
            _ => None,
        };
        let (what, tone) = match (live.contains(&o.id), o.signed) {
            (true, _) if left.is_some_and(|l| l <= CLOSING) => ("live, closing", Tone::Warn),
            (true, _) => ("live", Tone::Good),
            (false, true) => ("closed", Tone::Muted),
            (false, false) => ("under way", Tone::Normal),
        };
        let what = match (o.mock, o.phase) {
            (true, _) => format!("{what}, mock"),
            (false, Some(phase)) if !o.signed => format!("{what}, {phase:?}").to_lowercase(),
            _ => what.to_owned(),
        };
        let what = match o
            .terms
            .as_ref()
            .and_then(|t| licash_dashboard::fee_share(t.fee as i64, t.cap as i64))
        {
            Some(share) => format!("{what}, cost {share} of cap"),
            None => what,
        };
        let sat = |v: Option<u64>| v.map_or(Cell::Empty, |v| Cell::Sat(v as i64));
        let t = o.terms.as_ref();
        rows.push(Row::new(
            None,
            tone,
            vec![
                Cell::Time(o.created_at as i64),
                Cell::Text(hex::encode(&o.id[..4])),
                Cell::Text(what),
                sat(t.map(|t| t.cap)),
                sat(t.map(|t| t.graph)),
                left.map_or(Cell::Empty, Cell::Blocks),
                sat(t.map(|t| t.fee)),
                Cell::Text(t.and_then(|t| t.funding).map_or(String::new(), |f| {
                    let f = f.to_string();
                    format!("{}…", &f[..12])
                })),
            ],
        ));
    }
    Table::now(
        "Contracts",
        &[
            "opened",
            "id",
            "state",
            "protects",
            "collateral",
            "closes",
            "fee",
            "funding",
        ],
        rows,
        "no contract opened",
    )
}

fn privacy(r: &Records) -> Page {
    let many = r
        .notes
        .movements
        .iter()
        .map(|m| m.keyset)
        .collect::<HashSet<_>>()
        .len()
        > 1;
    let mut sets: BTreeMap<(u32, u64), (i64, i64)> = BTreeMap::new();
    for m in &r.notes.movements {
        sets.entry((m.keyset, m.denom)).or_default().0 += if m.issued { 1 } else { -1 };
    }
    for u in &r.notes.unlinks {
        let unlinked = u.answered.saturating_sub(u.retired) as i64;
        sets.entry((u.keyset, u.denom)).or_default().1 = unlinked;
    }
    let smallest = sets.values().map(|(n, _)| *n).filter(|n| *n > 0).min();
    let unlinked: i64 = sets.values().map(|(_, u)| *u).sum();
    let rows = sets
        .iter()
        .filter(|(_, (n, _))| *n > 0)
        .map(|((keyset, denom), (n, u))| {
            let tone = if *n < 10 { Tone::Warn } else { Tone::Normal };
            Row::new(
                None,
                tone,
                vec![
                    Cell::Text(set_name(many, *keyset, *denom)),
                    Cell::Int(*n),
                    Cell::Int((*u).min(*n)),
                ],
            )
        })
        .collect();
    Page::new(
        "Privacy",
        vec![
            vec![Panel::Cards(vec![
                total("Notes outstanding", Ref::level("notes"), Better::Up),
                Card::new(
                    "Smallest set",
                    Value::now(
                        smallest,
                        Unit::Count,
                        "notes of one denomination",
                        Tone::Normal,
                    ),
                    Better::Up,
                ),
                Card::new(
                    "Unlinked, up to",
                    Value::now(
                        Some(unlinked),
                        Unit::Count,
                        "answered unlinks less unlinked notes spent",
                        Tone::Normal,
                    ),
                    Better::Up,
                ),
            ])],
            vec![
                Panel::chart("Notes by denomination", "notes", Measure::Level),
                Panel::Table(Table::now(
                    "Anonymity sets",
                    &["denomination", "notes", "unlinked, up to"],
                    rows,
                    "no notes outstanding",
                )),
            ],
        ],
    )
}

/// What the hub did, newest first, the latest [`RECENT`]: its ledger's
/// events, a lock's by what it paid for, beside the invoices, deposit
/// addresses and contracts asked for, which the ledger does not see.
fn recent(r: &Records) -> Table {
    let kinds = lock_kinds(r);
    // A payment out ends as its forward did: the lock settling with it
    // says no more.
    let forwarded: HashSet<[u8; 32]> = r
        .forwards
        .iter()
        .filter(|f| f.resolved_at.is_some())
        .map(|f| f.lock)
        .collect();
    let lock = |proposal: &str| -> Option<[u8; 32]> { hex::decode(proposal).ok()?.try_into().ok() };
    let kind = |proposal: &str| {
        let kind = lock(proposal).and_then(|id| kinds.get(&id).copied());
        kind.unwrap_or(LOCK)
    };
    let mut rows: Vec<Row> = Vec::new();
    let mut push = |at: i64, tone, kind, event: &str, amount: Option<u64>, detail: String| {
        rows.push(Row::new(
            Some(at),
            tone,
            vec![
                Cell::Time(at),
                Cell::Text(noun(kind).into()),
                Cell::Text(event.into()),
                amount.map_or(Cell::Empty, |a| Cell::Sat(a as i64)),
                Cell::Text(detail),
            ],
        ));
    };
    for e in &r.events {
        let at = e.at as i64;
        match e.notice() {
            Some(Notice::Started { .. }) => {
                push(at, Tone::Muted, "hub", "started", None, "".into())
            }
            Some(Notice::Released { amount, fee, .. }) => {
                push(
                    at,
                    Tone::Good,
                    TRANSFER,
                    "released",
                    Some(amount),
                    fees_of(fee, amount),
                );
            }
            Some(Notice::Locked {
                proposal,
                amount,
                expiry,
                ..
            }) => {
                let kind = kind(&proposal);
                let what = match kind {
                    PAY => "to pay out",
                    RECEIVE => "paid in",
                    DEPOSIT => "confirmed",
                    _ => "awaiting its preimage",
                };
                let detail = format!("{what}, expires at block {expiry}");
                push(at, Tone::Normal, kind, "locked", Some(amount), detail);
            }
            Some(Notice::Settled {
                proposal,
                amount,
                fee,
                branch,
            }) => {
                if lock(&proposal).is_some_and(|id| forwarded.contains(&id)) {
                    continue;
                }
                let (tone, event) = match branch {
                    Settled::Pay => (Tone::Good, "settled"),
                    Settled::Refund => (Tone::Warn, "refunded"),
                };
                push(
                    at,
                    tone,
                    kind(&proposal),
                    event,
                    Some(amount),
                    fees_of(fee, amount),
                );
            }
            Some(Notice::Forwarded {
                proposal,
                amount,
                failed,
            }) => {
                let (tone, event, why) = match failed {
                    None => (Tone::Good, "paid", String::new()),
                    Some(why) => (Tone::Bad, "failed", reason(&why)),
                };
                push(at, tone, kind(&proposal), event, Some(amount), why);
            }
            Some(Notice::Activated {
                proposal,
                height,
                refunded,
            }) => {
                let (tone, detail) = match refunded {
                    false => (
                        Tone::Normal,
                        format!("preimage on Bitcoin at block {height}"),
                    ),
                    true => (
                        Tone::Bad,
                        format!("after its refund, at block {height}: both branches owed"),
                    ),
                };
                push(at, tone, kind(&proposal), "activated", None, detail);
            }
            Some(Notice::Reorg { height }) => {
                let detail = format!("at block {height}: the scan stopped");
                push(at, Tone::Bad, "hub", "reorganized", None, detail);
            }
            Some(Notice::DoubleSpend { proposal, .. }) => {
                let detail = format!("proposal {}…", &proposal[..12.min(proposal.len())]);
                push(at, Tone::Bad, "hub", "double spend", None, detail);
            }
            Some(Notice::Alert { message }) => push(at, Tone::Warn, "hub", "alert", None, message),
            // Of a newer hub.
            _ => {
                let event = e.kind.replace('_', " ");
                push(at, Tone::Muted, "hub", &event, None, String::new());
            }
        }
    }
    for x in r.receipts.iter().flatten() {
        let amount = Some(x.msat / 1000);
        push(
            x.created_at,
            Tone::Normal,
            RECEIVE,
            "asked",
            amount,
            "invoice".into(),
        );
        if x.state == "canceled" && x.lock.is_none() {
            let at = x.done_at.unwrap_or(x.created_at);
            push(
                at,
                Tone::Muted,
                RECEIVE,
                "unpaid",
                amount,
                "invoice canceled".into(),
            );
        }
    }
    for x in r.deposits.iter().flatten() {
        let kind = DEPOSIT;
        push(
            x.created_at,
            Tone::Normal,
            kind,
            "asked",
            Some(x.pays),
            "address".into(),
        );
        if x.state == "canceled" && x.lock.is_none() {
            let at = x.done_at.unwrap_or(x.created_at);
            match x.confirmed {
                false => push(
                    at,
                    Tone::Muted,
                    kind,
                    "unpaid",
                    Some(x.pays),
                    "address expired".into(),
                ),
                true => push(
                    at,
                    Tone::Bad,
                    kind,
                    "canceled",
                    Some(x.pays),
                    "paid, never locked".into(),
                ),
            }
        }
    }
    for o in &r.openings {
        let id = hex::encode(&o.id[..4]);
        let t = o.terms.as_ref();
        let state = match (o.signed, o.abandoned, t.map_or(0, |t| t.fee)) {
            (true, _, 0) => "signed".to_owned(),
            (true, _, fee) => format!(
                "signed, fee {} of cap",
                licash_dashboard::fee(fee as i64, t.map_or(0, |t| t.cap) as i64)
            ),
            (false, true, _) => "given up".to_owned(),
            (false, false, _) => "under way".to_owned(),
        };
        let mock = if o.mock { ", mock" } else { "" };
        let (at, cap) = (o.created_at as i64, t.map(|t| t.cap));
        push(
            at,
            Tone::Normal,
            CONTRACT,
            "opened",
            cap,
            format!("{id} {state}{mock}"),
        );
        if o.abandoned {
            let at = o.updated_at as i64;
            push(at, Tone::Muted, CONTRACT, "given up", cap, id);
        }
    }
    // Newest first: of one second, the last recorded.
    rows.reverse();
    rows.sort_by_key(|row| std::cmp::Reverse(row.at));
    rows.truncate(RECENT);
    Table::in_range(
        "Recent events",
        &["when", "kind", "event", "amount", "detail"],
        rows,
        "nothing happened",
    )
}

/// A kind of payment, as one event of it reads.
fn noun(kind: &str) -> &str {
    match kind {
        TRANSFER => "transfer",
        LOCK => "lock",
        DEPOSIT => "deposit",
        CONTRACT => "contract",
        kind => kind,
    }
}

/// The hub's fee, if any.
fn fees_of(fee: u64, inputs: u64) -> String {
    match fee {
        0 => String::new(),
        fee => format!(
            "fee {} of input",
            licash_dashboard::fee(fee as i64, inputs as i64)
        ),
    }
}

/// What the hub alerted of, newest first.
fn alerts(r: &Records) -> Table {
    let mut rows: Vec<Row> = Vec::new();
    for e in &r.events {
        let at = e.at as i64;
        let (tone, text) = match e.notice() {
            Some(Notice::Alert { message }) => (Tone::Warn, message),
            Some(Notice::DoubleSpend { proposal, .. }) => (
                Tone::Bad,
                format!(
                    "double spend: proposal {}…",
                    &proposal[..12.min(proposal.len())]
                ),
            ),
            Some(Notice::Reorg { height }) => (
                Tone::Bad,
                format!("reorganized at block {height}: the scan stopped"),
            ),
            Some(Notice::Activated {
                height,
                refunded: true,
                ..
            }) => (
                Tone::Bad,
                format!("a refunded lock activated at block {height}: both branches owed"),
            ),
            Some(Notice::Started { .. }) => (Tone::Muted, "started".to_owned()),
            _ => continue,
        };
        rows.push(Row::new(
            Some(at),
            tone,
            vec![Cell::Time(at), Cell::Text(text)],
        ));
    }
    rows.reverse();
    Table::in_range("Alerts", &["when", "what"], rows, "no alert")
}

/// Whether the hub's payments out are paused, as `data` keeps it
/// ([`crate::payouts`]), and the notes the ledger retired beyond those it
/// issued.
fn payouts(r: &Records, data: &Path) -> Check {
    let beyond: u64 = r.notes.excess().iter().map(|e| e.notes).sum();
    let paused = match crate::payouts::kept(data) {
        Ok(Some(kept)) => kept.paused,
        Ok(None) if beyond == 0 => {
            return Check::new("Payouts", Tone::Muted, "not watched yet");
        }
        Ok(None) => None,
        Err(_) => Some("payouts.json does not read".into()),
    };
    match (paused, beyond) {
        (Some(why), _) => Check::new(
            "Payouts",
            Tone::Bad,
            format!("Notes made outside the ledger, payouts watch paused: {why}"),
        ),
        (None, 0) => Check::new("Payouts", Tone::Good, "every note retired was issued"),
        (None, n) => Check::new(
            "Payouts",
            Tone::Warn,
            format!("{n} notes retired beyond those issued, taken as known"),
        ),
    }
}

fn checks(r: &Records, state: &Now, now: i64, service: Check) -> Vec<Check> {
    let mut checks = vec![service];
    let last = |kind: &str| {
        r.events
            .iter()
            .rev()
            .find(|e| e.kind == kind)
            .map(|e| e.at as i64)
    };
    checks.push(match (state.tip, last("reorg")) {
        (_, Some(reorg)) if last("started").is_none_or(|s| s < reorg) => Check::new(
            "Chain",
            Tone::Bad,
            "reorganized below a checkpoint: the scan stopped",
        ),
        (None, _) => Check::new("Chain", Tone::Warn, "following no chain: locks are refused"),
        (Some(tip), _) => Check::new("Chain", Tone::Good, format!("scanned to block {tip}")),
    });
    let open: Vec<_> = r.locks.iter().filter(|l| l.settled_at.is_none()).collect();
    let soon = open
        .iter()
        .filter(|l| {
            state
                .tip
                .is_some_and(|tip| i64::from(l.expiry) - tip <= SOON)
        })
        .count();
    checks.push(match soon {
        0 => Check::new("Locks", Tone::Good, format!("{} open", open.len())),
        n => Check::new(
            "Locks",
            Tone::Warn,
            format!("{n} of {} open expire within {SOON} blocks", open.len()),
        ),
    });
    let stuck = r
        .forwards
        .iter()
        .filter(|f| f.state == "pending" && now - (f.created_at as i64) > 3_600)
        .count();
    checks.push(match (&r.receipts, r.forwards.is_empty(), stuck) {
        (None, true, _) => Check::new("Lightning", Tone::Muted, "no gateway ran"),
        (_, _, 0) => {
            let paying = r.forwards.iter().filter(|f| f.state == "pending").count();
            Check::new("Lightning", Tone::Good, format!("{paying} paying out"))
        }
        (_, _, n) => Check::new(
            "Lightning",
            Tone::Warn,
            format!("{n} paying for over an hour"),
        ),
    });
    checks.push(match &r.deposits {
        None => Check::new("Deposits", Tone::Muted, "none taken"),
        Some(all) => {
            let live = all.iter().filter(|d| d.done_at.is_none()).count();
            Check::new("Deposits", Tone::Good, format!("{live} under way"))
        }
    });
    let closing = state
        .live
        .iter()
        .filter_map(|o| o.terms.as_ref())
        .filter(|t| {
            state
                .tip
                .is_some_and(|tip| i64::from(t.close) - tip <= CLOSING)
        })
        .count();
    checks.push(
        match (state.live.len(), state.live.iter().any(|o| o.mock), closing) {
            (0, _, _) => Check::new("Contracts", Tone::Muted, "none live"),
            (_, true, _) => Check::new(
                "Contracts",
                Tone::Warn,
                "under mock proofs: they protect nothing",
            ),
            (n, _, 0) => Check::new("Contracts", Tone::Good, format!("{n} live")),
            (n, _, c) => Check::new(
                "Contracts",
                Tone::Warn,
                format!("{c} of {n} close within {CLOSING} blocks"),
            ),
        },
    );
    let recent = r
        .events
        .iter()
        .filter(|e| e.kind == "alert" && now - (e.at as i64) < DAY)
        .count();
    checks.push(match recent {
        0 => Check::new("Alerts", Tone::Good, "none in the last day"),
        n => Check::new("Alerts", Tone::Warn, format!("{n} in the last day")),
    });
    let doubles = r.events.iter().filter(|e| e.kind == "double_spend").count();
    checks.push(match doubles {
        0 => Check::new("Double spends", Tone::Good, "none"),
        n => Check::new(
            "Double spends",
            Tone::Bad,
            format!("{n} signed: see the alerts"),
        ),
    });
    checks
}
