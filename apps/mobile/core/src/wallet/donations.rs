//! The wallet's static address of donations: its code as an LNURL of a
//! swap provider announced on Nostr that takes donations at a hub of it.
//! Any Lightning wallet pays it, again and again, while the phone is
//! offline: the provider pays each donation in notes at the code's hub,
//! kept there for the wallet or mailed to it.
//!
//! Once shown, its provider and code are kept ([`Pinned`], in the app's
//! file) and shown again while it takes donations, as an address handed
//! out stays: the code while it pays the wallet at hubs it trusts, hubs
//! added since or not ([`licash_wallet::Wallet::donation_code`]); the provider
//! another, cheaper or holding more, takes its place only when it says it
//! takes no more ([`Asked::Refused`]), or once it failed to take any for
//! [`PATIENCE`] while another can now. Unheard, it is shown all the same,
//! as kept: the phone may be offline.

use std::{
    sync::PoisonError,
    time::{SystemTime, UNIX_EPOCH},
};

use licash_api::swaps::Donations;
use licash_nostr::wallet::{donation_providers_with, hub_relays, DonationProvider};
use licash_wallet::LicashCode;
use serde::{Deserialize, Deserializer, Serialize};

use super::Wallet;
use crate::{DonationAddress, LicashError};

/// How long a provider kept fails to take donations, unheard or holding
/// too little, before another able to now takes its place: a phone asking
/// now and then is not to move its address over one bad hour.
pub(crate) const PATIENCE: u64 = 7 * 24 * 3600;

/// The provider of the donation address shown, as the app keeps it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Pinned {
    /// Where the wallet asks it, and the key that announced it.
    pub url: String,
    pub key: String,
    pub name: Option<String>,
    /// What it last said it takes donations on: its public URL is in the
    /// address.
    pub donations: Donations,
    /// Since when it has failed to take donations, unheard or holding too
    /// little, if it does now (unix seconds).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failing_since: Option<u64>,
    /// The code in the address, as text: none, the one the wallet shows.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,
}

impl Pinned {
    fn of(found: &DonationProvider, code: &LicashCode) -> Self {
        Self {
            url: found.url.clone(),
            key: found.key.clone(),
            name: found.name.clone(),
            donations: found.address.donations.clone(),
            failing_since: None,
            code: Some(code.to_string()),
        }
    }

    fn tired(&self, now: u64) -> bool {
        self.failing_since
            .is_some_and(|since| now.saturating_sub(since) >= PATIENCE)
    }
}

/// A [`Pinned`] that no longer reads as one is none, rather than costing
/// the rest of what the app keeps.
pub(crate) fn lenient<'de, D: Deserializer<'de>>(d: D) -> Result<Option<Pinned>, D::Error> {
    let value = serde_json::Value::deserialize(d)?;
    Ok(serde_json::from_value(value).ok())
}

/// What the provider kept answered, asked at its URL.
pub(crate) enum Asked {
    /// A donation address, holding enough to take one or not.
    Took(Box<licash_wallet::DonationAddress>),
    /// That it takes no donations, or none at the hubs of the code.
    Refused,
    /// Nothing that says: unreachable, or failing.
    Unheard,
}

/// What to show.
#[derive(Debug)]
pub(crate) enum Shown {
    /// An address a provider gave now.
    Live(Box<DonationProvider>),
    /// The kept provider's, as kept: it was not heard.
    Kept(Pinned),
}

/// What to show, and the provider to keep from now on.
#[derive(Debug)]
pub(crate) struct Choice {
    pub shown: Option<Shown>,
    pub pin: Option<Pinned>,
}

/// The donation address to show, given the provider kept and what it
/// answered, if one is, the providers `found` (asked for only if needed,
/// the best first) and the time `now`.
pub(crate) fn choose(
    kept: Option<(Pinned, Asked)>,
    found: impl FnOnce() -> Vec<DonationProvider>,
    now: u64,
) -> Choice {
    let best = |found: Vec<DonationProvider>| Choice {
        shown: found.into_iter().next().map(|p| Shown::Live(Box::new(p))),
        pin: None,
    };
    // Another holding enough now, once the kept one has failed too long.
    let instead = |pin: &Pinned, found: Vec<DonationProvider>| {
        let other = found
            .into_iter()
            .find(|p| p.key != pin.key && p.address.stocked);
        other.map(|p| Choice {
            shown: Some(Shown::Live(Box::new(p))),
            pin: None,
        })
    };
    let Some((mut pin, asked)) = kept else {
        return best(found());
    };
    match asked {
        Asked::Took(address) => {
            pin.donations = address.donations.clone();
            pin.failing_since = match address.stocked {
                true => None,
                false => pin.failing_since.or(Some(now)),
            };
            if pin.tired(now) {
                if let Some(choice) = instead(&pin, found()) {
                    return choice;
                }
            }
            let live = DonationProvider {
                url: pin.url.clone(),
                key: pin.key.clone(),
                name: pin.name.clone(),
                address: *address,
            };
            Choice {
                shown: Some(Shown::Live(Box::new(live))),
                pin: Some(pin),
            }
        }
        Asked::Refused => best(found()),
        Asked::Unheard => {
            pin.failing_since = pin.failing_since.or(Some(now));
            let found = found();
            // Moved: announced at another URL by the same key.
            if let Some(moved) = found.iter().find(|p| p.key == pin.key) {
                pin.url = moved.url.clone();
                pin.donations = moved.address.donations.clone();
                if moved.address.stocked {
                    pin.failing_since = None;
                }
                return Choice {
                    shown: Some(Shown::Live(Box::new(moved.clone()))),
                    pin: Some(pin),
                };
            }
            if pin.tired(now) {
                if let Some(choice) = instead(&pin, found) {
                    return choice;
                }
            }
            Choice {
                shown: Some(Shown::Kept(pin.clone())),
                pin: Some(pin),
            }
        }
    }
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

#[uniffi::export]
impl Wallet {
    /// The wallet's static address of donations: through the provider
    /// kept since it was first shown, while it takes donations, else the
    /// one that suits best ([`donation_providers_with`]). None if no
    /// provider announced on the relays the hubs name takes donations at
    /// a hub the wallet trusts, and none is kept. Kept until shown
    /// ([`Wallet::keep_donation_address`]).
    pub fn donation_address(&self) -> Result<Option<DonationAddress>, LicashError> {
        let _timed = crate::log::timed("donation_address");
        let pinned = self.kept().donations;
        let kept_code = pinned.as_ref().and_then(|p| p.code.clone());
        let hubs = self.code_hubs()?;
        let code = match self.wallet.donation_code(kept_code.as_deref(), &hubs) {
            Ok(code) => code,
            // No hub, no donations.
            Err(licash_wallet::Error::Invalid(_)) => return Ok(None),
            Err(e) => return Err(e.into()),
        };
        let had = pinned.clone();
        let mut choice = self.offer(pinned, &code);
        // None at the hubs of the code kept: the one the wallet shows now.
        let mut code = code;
        if choice.shown.is_none() && kept_code.is_some() {
            let now = self.wallet.donation_code(None, &hubs)?;
            if now != code {
                choice = self.offer(None, &now);
                code = now;
            }
        }
        if choice.pin != had {
            let pin = choice.pin.clone();
            self.update_kept(|kept| kept.donations = pin)?;
        }
        let shown = choice.shown.map(|shown| match shown {
            Shown::Live(p) => {
                let address = DonationAddress {
                    lnurl: p.address.lnurl.clone(),
                    provider: p.url.clone(),
                    name: p.name.clone(),
                    fee_base: p.address.donations.fee.base,
                    fee_ppm: p.address.donations.fee.ppm,
                    min: p.address.donations.min,
                    max: p.address.donations.max,
                    stocked: p.address.stocked,
                    reachable: true,
                };
                (address, Pinned::of(&p, &code))
            }
            Shown::Kept(pin) => {
                let address = DonationAddress {
                    lnurl: code.lnurl(&pin.donations.url),
                    provider: pin.url.clone(),
                    name: pin.name.clone(),
                    fee_base: pin.donations.fee.base,
                    fee_ppm: pin.donations.fee.ppm,
                    min: pin.donations.min,
                    max: pin.donations.max,
                    stocked: false,
                    reachable: false,
                };
                (address, pin)
            }
        });
        let mut offered = self.offered.lock().unwrap_or_else(PoisonError::into_inner);
        *offered = shown
            .as_ref()
            .map(|(address, pin)| (address.lnurl.clone(), pin.clone()));
        Ok(shown.map(|(address, _)| address))
    }

    /// Keep the provider of the donation address `lnurl`, last offered
    /// ([`Wallet::donation_address`]), once the app shows it: it is shown
    /// again from then on, while it takes donations.
    pub fn keep_donation_address(&self, lnurl: String) -> Result<(), LicashError> {
        let offered = self
            .offered
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        let Some((_, pin)) = offered.filter(|(offered, _)| *offered == lnurl) else {
            return Err(LicashError::invalid("not the donation address offered"));
        };
        self.update_kept(|kept| {
            if kept.donations.as_ref().map(|k| &k.key) != Some(&pin.key) {
                kept.donations = Some(pin);
            }
        })
    }
}

/// What the provider `pin` answered at its URL: its answer only if it
/// answers as the key that announced it, else unheard there, as one that
/// moved (another there now, its URL taken over, or on the way to it):
/// found again only where that key announces it.
fn asked_of(
    pin: &Pinned,
    asked: Result<licash_wallet::DonationAddress, licash_wallet::Error>,
) -> Asked {
    match asked {
        Ok(address) => {
            let key = address.info.nostr.as_deref();
            if key.is_some_and(|key| key.eq_ignore_ascii_case(&pin.key)) {
                return Asked::Took(Box::new(address));
            }
            tracing::warn!(
                provider = %pin.url, ?key, pinned = %pin.key,
                "the donation provider kept answers as another key: unheard"
            );
            Asked::Unheard
        }
        Err(licash_wallet::Error::Invalid(why)) => {
            tracing::info!(provider = %pin.url, "the donation address kept gives way: {why}");
            Asked::Refused
        }
        Err(e) => {
            tracing::info!(provider = %pin.url, "the donation address kept is unheard: {e}");
            Asked::Unheard
        }
    }
}

impl Wallet {
    /// What to show of donations to `code`, given the provider `pinned`,
    /// asked first at its URL.
    fn offer(&self, pinned: Option<Pinned>, code: &LicashCode) -> Choice {
        let kept = pinned.map(|mut pin| {
            pin.code = Some(code.to_string());
            let asked = self.operation(self.wallet.donation_address(&pin.url, code));
            let asked = asked_of(&pin, asked);
            (pin, asked)
        });
        choose(kept, || self.donation_providers(code), now())
    }

    /// The providers announced on the relays the hubs name that take
    /// donations to `code`, the best first: none if they are not reached.
    fn donation_providers(&self, code: &LicashCode) -> Vec<DonationProvider> {
        let Ok(relays) = hub_relays(&self.wallet) else {
            return Vec::new();
        };
        if relays.is_empty() {
            return Vec::new();
        }
        let on = (&relays[..], &self.route);
        let found = donation_providers_with(&self.wallet, &self.announced, on, code);
        self.operation(found).unwrap_or_else(|e| {
            tracing::info!("no provider found taking donations: {e:#}");
            Vec::new()
        })
    }
}

#[cfg(test)]
mod tests {
    use licash::address::OwnerKeys;
    use licash_api::{swaps, Fee};

    use super::*;

    const DAY: u64 = 24 * 3600;

    fn donations(url: &str) -> Donations {
        Donations {
            url: url.into(),
            fee: Fee {
                base: 2,
                ppm: 5_000,
            },
            min: 100,
            max: 1_000_000,
        }
    }

    fn address(url: &str, stocked: bool) -> licash_wallet::DonationAddress {
        let owner = OwnerKeys::from_seed(&[1; 32]).unwrap();
        licash_wallet::DonationAddress {
            lnurl: format!("LNURL-{url}"),
            donations: donations(url),
            stocked,
            info: swaps::Info {
                address: owner.address(),
                fee: Fee { base: 0, ppm: 0 },
                min: 1,
                max: 2,
                margin: 6,
                hubs: Vec::new(),
                nostr: None,
                chain: None,
                lightning: None,
                donations: Some(donations(url)),
                receive: None,
                deposits: None,
                features: Vec::new(),
            },
        }
    }

    fn provider(key: &str, stocked: bool) -> DonationProvider {
        let url = format!("https://{key}.test");
        DonationProvider {
            url: url.clone(),
            key: key.into(),
            name: Some(key.into()),
            address: address(&url, stocked),
        }
    }

    fn pin(key: &str, failing_since: Option<u64>) -> Pinned {
        let owner = OwnerKeys::from_seed(&[1; 32]).unwrap();
        let code = LicashCode {
            network: licash::spend::ChainProfile::Core30DefaultRegtest,
            address: owner.address(),
            mailbox: None,
            hubs: vec![licash_wallet::HubId([1; 16])],
            locations: Vec::new(),
        };
        Pinned {
            failing_since,
            ..Pinned::of(&provider(key, true), &code)
        }
    }

    fn live(choice: &Choice) -> &str {
        match &choice.shown {
            Some(Shown::Live(p)) => &p.key,
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn with_none_kept_the_best_found_is_shown_and_kept_only_once_shown() {
        let choice = choose(None, || vec![provider("b", true), provider("c", true)], 0);
        assert_eq!((live(&choice), &choice.pin), ("b", &None));
        let choice = choose(None, Vec::new, 0);
        assert!(choice.shown.is_none() && choice.pin.is_none());
    }

    #[test]
    fn the_provider_kept_is_taken_only_answering_as_the_key_that_announced_it() {
        let pinned = pin("a", None);
        let answering = |nostr: Option<&str>| {
            let mut address = address("https://a.test", true);
            address.info.nostr = nostr.map(Into::into);
            asked_of(&pinned, Ok(address))
        };
        assert!(matches!(answering(Some("a")), Asked::Took(_)));
        assert!(matches!(answering(Some("A")), Asked::Took(_)));
        // Another key at its URL, or none: as if it moved, unheard there.
        assert!(matches!(answering(Some("b")), Asked::Unheard));
        assert!(matches!(answering(None), Asked::Unheard));
        // So the one found where its key announces it is shown instead.
        let choice = choose(
            Some((pin("a", None), answering(Some("b")))),
            || vec![provider("a", true)],
            DAY,
        );
        assert_eq!(live(&choice), "a");
    }

    #[test]
    fn the_provider_kept_stays_while_it_answers_whoever_else_is_found() {
        let asked = Asked::Took(Box::new(address("https://a.test", true)));
        let choice = choose(
            Some((pin("a", None), asked)),
            || panic!("not looked for"),
            DAY,
        );
        assert_eq!(live(&choice), "a");
        assert_eq!(choice.pin, Some(pin("a", None)));
        // Holding too little: kept, from now on failing, until it is tired.
        let asked = Asked::Took(Box::new(address("https://a.test", false)));
        let found = || vec![provider("b", true)];
        let choice = choose(Some((pin("a", None), asked)), found, DAY);
        assert_eq!(live(&choice), "a");
        assert_eq!(choice.pin.unwrap().failing_since, Some(DAY));
        // Its terms and public URL followed, as it now says.
        let mut moved = address("https://a.test", true);
        moved.donations.url = "https://pay.a.test".into();
        let choice = choose(
            Some((pin("a", Some(0)), Asked::Took(Box::new(moved)))),
            Vec::new,
            DAY,
        );
        let pinned = choice.pin.unwrap();
        assert_eq!(
            (pinned.donations.url.as_str(), pinned.failing_since),
            ("https://pay.a.test", None)
        );
    }

    #[test]
    fn the_provider_kept_gives_way_at_once_when_it_takes_no_more() {
        let found = || vec![provider("b", false), provider("c", true)];
        let choice = choose(Some((pin("a", None), Asked::Refused)), found, DAY);
        assert_eq!((live(&choice), &choice.pin), ("b", &None));
        let choice = choose(Some((pin("a", None), Asked::Refused)), Vec::new, DAY);
        assert!(choice.shown.is_none() && choice.pin.is_none());
    }

    #[test]
    fn the_provider_kept_unheard_is_shown_as_kept_until_tired_with_another_able() {
        let found = || vec![provider("b", true)];
        // Unheard for the first time: kept, failing from now.
        let choice = choose(Some((pin("a", None), Asked::Unheard)), found, 10 * DAY);
        let Some(Shown::Kept(shown)) = &choice.shown else {
            panic!("{choice:?}")
        };
        assert_eq!(shown.key, "a");
        assert_eq!(choice.pin.unwrap().failing_since, Some(10 * DAY));
        // Still within its patience: kept.
        let since = Some(10 * DAY);
        let choice = choose(Some((pin("a", since), Asked::Unheard)), found, 16 * DAY);
        assert!(matches!(choice.shown, Some(Shown::Kept(_))), "{choice:?}");
        // Tired, but none other holds enough: kept.
        let unstocked = || vec![provider("b", false)];
        let choice = choose(Some((pin("a", since), Asked::Unheard)), unstocked, 17 * DAY);
        assert!(matches!(choice.shown, Some(Shown::Kept(_))), "{choice:?}");
        // Tired, another able: it takes its place, kept once shown.
        let choice = choose(Some((pin("a", since), Asked::Unheard)), found, 17 * DAY);
        assert_eq!((live(&choice), &choice.pin), ("b", &None));
        // Holding too little that long, answering: the same.
        let asked = Asked::Took(Box::new(address("https://a.test", false)));
        let choice = choose(Some((pin("a", since), asked)), found, 17 * DAY);
        assert_eq!((live(&choice), &choice.pin), ("b", &None));
    }

    #[test]
    fn the_provider_kept_is_followed_to_where_its_key_announces_it() {
        let mut moved = provider("a", true);
        moved.url = "https://new.a.test".into();
        let found = || vec![provider("b", true), moved.clone()];
        let choice = choose(Some((pin("a", Some(0)), Asked::Unheard)), found, 30 * DAY);
        assert_eq!(live(&choice), "a");
        let pinned = choice.pin.unwrap();
        assert_eq!(
            (pinned.url.as_str(), pinned.failing_since),
            ("https://new.a.test", None)
        );
    }

    #[test]
    fn a_kept_provider_unreadable_is_none_and_costs_nothing_else() {
        use super::super::Kept;
        let kept: Kept =
            serde_json::from_str(r#"{"birthday": 7, "donations": {"url": 1}}"#).unwrap();
        assert_eq!((kept.birthday, kept.donations), (7, None));
        let text = serde_json::to_string(&pin("a", Some(3))).unwrap();
        let kept: Kept =
            serde_json::from_str(&format!(r#"{{"birthday": 7, "donations": {text}}}"#)).unwrap();
        assert_eq!(kept.donations, Some(pin("a", Some(3))));
        // None kept: written as before, read back as none.
        let none = Kept {
            birthday: 7,
            ..Kept::default()
        };
        let text = serde_json::to_string(&none).unwrap();
        assert_eq!(text, r#"{"birthday":7}"#);
        let kept: Kept = serde_json::from_str(&text).unwrap();
        assert_eq!(kept.donations, None);
    }
}
