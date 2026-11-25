//! The wallet's extra codes ([`licash_wallet::codes`]): codes of keys of
//! their own, naming no mailbox, that no one can tell are the wallet's or
//! each other's. What one is paid is collected with the wallet's own
//! payments and paid on to it, its hub's fee taken: the history shows each
//! payment taken at a code, its fee that of paying it on, rather than the
//! payment on.

use std::collections::HashSet;

use licash_wallet::CodeActivity;

use super::Wallet;
use crate::{Activity, Code, ExtraCode, Kind, LicashError, State};

#[uniffi::export]
impl Wallet {
    /// The wallet's extra codes, by number.
    pub fn codes(&self) -> Result<Vec<ExtraCode>, LicashError> {
        let hubs = self.code_hubs()?;
        let activity = self.wallet.code_activity()?;
        activity.iter().map(|at| self.extra(at, &hubs)).collect()
    }

    /// A new extra code, called `label`: the next number's, at the
    /// wallet's hubs.
    pub fn add_code(&self, label: String) -> Result<ExtraCode, LicashError> {
        let _timed = crate::log::timed("add_code");
        let made = self.operation(self.wallet.add_code(&label))?;
        let codes = self.codes()?;
        let code = codes.into_iter().find(|c| c.index == made.index);
        code.ok_or_else(|| LicashError::failed("an extra address made, then gone"))
    }

    /// Extra code `index`, asking `amount` if given, at the wallet's hubs.
    pub fn extra_code(&self, index: u32, amount: Option<u64>) -> Result<Code, LicashError> {
        let mut code = self.wallet.extra_code(index, &self.code_hubs()?)?;
        code.amount = amount.filter(|a| *a > 0);
        Ok(Code {
            text: code.to_string(),
            qr: code.qr(),
            address: None,
            silent: None,
        })
    }
}

impl Wallet {
    fn extra(&self, at: &CodeActivity, hubs: &[String]) -> Result<ExtraCode, LicashError> {
        let code = match hubs.is_empty() {
            true => None,
            false => Some(self.extra_code(at.code.index, None)?),
        };
        Ok(ExtraCode {
            index: at.code.index,
            label: at.code.label.clone(),
            created_at: at.code.created_at,
            code,
            received: at.received.iter().map(|r| r.amount).sum(),
            payments: u32::try_from(at.received.len()).unwrap_or(u32::MAX),
            fees: at.swept.iter().map(|s| s.fee).sum(),
        })
    }

    /// The lines of the history of the payments taken at the wallet's
    /// extra codes, and the ids of the payments they paid on to the wallet,
    /// not shown themselves.
    pub(crate) fn code_lines(&self) -> Result<(Vec<Activity>, HashSet<String>), LicashError> {
        let activity = self.wallet.code_activity()?;
        let swept = activity.iter().flat_map(|at| at.swept.iter());
        let swept = swept.map(|s| s.id.clone()).collect();
        Ok((activity.iter().flat_map(lines).collect(), swept))
    }
}

/// The lines of the payments taken at the code of `at`: each paid on to
/// the wallet with those taken before it and not yet paid on, the fee of
/// paying them on said with the last of them; pending until the payment
/// on is done.
fn lines(at: &CodeActivity) -> Vec<Activity> {
    let mut received: Vec<_> = at.received.iter().collect();
    received.sort_by_key(|r| r.received_at);
    let mut swept: Vec<_> = at.swept.iter().collect();
    swept.sort_by_key(|s| s.created_at);
    let mut lines = Vec::new();
    let mut taken = received.into_iter().peekable();
    for sweep in swept {
        let mut group = Vec::new();
        while let Some(r) = taken.next_if(|r| r.received_at <= sweep.created_at) {
            group.push(r);
        }
        let done = sweep.state == licash_wallet::State::Done;
        let last = group.len().saturating_sub(1);
        for (i, r) in group.into_iter().enumerate() {
            let fee = if i == last { sweep.fee } else { 0 };
            lines.push(line(at, r, fee, done));
        }
    }
    lines.extend(taken.map(|r| line(at, r, 0, false)));
    lines
}

fn line(at: &CodeActivity, received: &licash_wallet::Received, fee: u64, done: bool) -> Activity {
    let note = at.notes.get(&received.id);
    let from = note.and_then(|n| n.from.clone()).map(|licash| {
        licash_wallet::PaymentCode {
            address: None,
            amount: None,
            silent: None,
            licash: Some(licash),
        }
        .to_string()
    });
    Activity {
        id: received.id.clone(),
        kind: Kind::Received,
        state: if done { State::Done } else { State::Pending },
        amount: received.amount,
        fee,
        detail: received.hub.clone(),
        at: Some(received.received_at),
        memo: note.and_then(|n| n.text.clone()),
        from,
        code: Some(at.code.label.clone()),
    }
}
