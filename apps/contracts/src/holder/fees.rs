//! What she agreed to pay her contracts' hubs. The fees a hub charged as
//! a contract opened there are the most it may charge her from then on
//! ([`agree`], which tells her wallet): a hub may raise its fees whenever
//! it likes, and is then paid nothing until she [`approve`]s them. A hub
//! charging more than is sane ([`abusive`]), or a contract costing more
//! than is sane of the coin paying it ([`costly`]), opens none unasked.

use std::collections::HashMap;
use std::path::Path;

use anyhow::{ensure, Result};
use licash_api::{Fee, Fees};
use licash_contract::opening::Fate;
use licash_wallet::{Transport, Wallet};

use super::store::{Contract, Store};

const SANE_FEE: Fee = Fee {
    base: 10,
    ppm: 10_000,
};

/// The most a hub may charge for a contract to open there unasked: on a
/// payment and in each branch of a lock, 10 sat and 1% of what moves, and
/// a sat for each note made.
pub const SANE: Fees = Fees {
    spend: SANE_FEE,
    lock: SANE_FEE,
    refund: SANE_FEE,
    output_msat: 1_000,
};

/// Why no contract opens unasked at a hub charging `fees`: the first of
/// them that is more than is sane ([`SANE`]). None if none is. What a
/// contract itself costs is judged against the coin paying it ([`costly`]).
pub fn abusive(fees: &Fees) -> Option<String> {
    let parts = [
        (
            "a payment's base fee, in sat",
            fees.spend.base,
            SANE.spend.base,
        ),
        (
            "a payment's fee, in parts per million",
            fees.spend.ppm,
            SANE.spend.ppm,
        ),
        ("a lock's base fee, in sat", fees.lock.base, SANE.lock.base),
        (
            "a lock's fee, in parts per million",
            fees.lock.ppm,
            SANE.lock.ppm,
        ),
        (
            "a refund's base fee, in sat",
            fees.refund.base,
            SANE.refund.base,
        ),
        (
            "a refund's fee, in parts per million",
            fees.refund.ppm,
            SANE.refund.ppm,
        ),
        (
            "its fee for each note made, in thousandths of a sat",
            fees.output_msat,
            SANE.output_msat,
        ),
    ];
    let (what, is, most) = parts.iter().find(|(_, is, most)| is > most)?;
    Some(format!("{what}: {is}, where {most} at most is sane"))
}

/// The most of the coin paying for a contract its cost may be, as a
/// fraction: half. A sanity bound, not a price: what she pays is hers to
/// bound.
pub const SANE_SHARE: u64 = 2;

/// Why a contract priced `price` sat, `reserve` of it her reserve, paid
/// for by a coin of `coin` sat, opens unasked at no hub: its cost, the
/// hub's fee and interest (her reserve comes back to her as it closes),
/// more than half the coin ([`SANE_SHARE`]). None if not. A contract
/// mostly the hub's own funds (a coin little more than its price) costs
/// more than that: it opens only asked all the same, or of a price she
/// bounded herself, seen before she chose it.
pub fn costly(price: u64, reserve: u64, coin: u64) -> Option<String> {
    let cost = price.saturating_sub(reserve);
    let most = coin / SANE_SHARE;
    (cost > most).then(|| {
        format!(
            "its fee and interest, {cost} sat, more than {most}, half the coin of {coin} sat paying for it"
        )
    })
}

/// Tell `wallet` the most each hub it trusts may charge
/// ([`Wallet::set_fee_ceilings`]), by the contracts in `wallet_file`: of those at
/// a hub that protect notes at `tip` (all whose F is buried, if the tip is
/// not known), the least of each fee they opened under or she approved
/// since. No ceilings at a hub with no such contract, or whose contracts
/// were opened before any were kept: nothing is refused there. Its locks
/// kept claimable as [`super::exit::guard_locks`] says. To call as
/// the wallet opens, and whenever its contracts changed ([`super::resume`]
/// and [`approve`] do). Contracts that cannot be read hold each hub to no
/// fee at all, until they can: what they agreed is unknown, and a hub
/// charging anything is paid nothing meanwhile.
pub fn agree<T: Transport>(wallet: &Wallet<T>, wallet_file: &Path, tip: Option<u32>) -> Result<()> {
    // Its locks too: what keeps them claimable reads the contracts afresh.
    super::exit::guard_locks(wallet, wallet_file);
    let read = Store::existing(wallet_file).and_then(|store| match store {
        Some(store) => Ok(Some((store.list()?, store.ceilings()?))),
        None => Ok(None),
    });
    let (contracts, ceilings) = match read {
        Ok(Some(read)) => read,
        Ok(None) => return Ok(()),
        Err(e) => {
            for (url, _) in wallet.hubs()? {
                wallet.set_fee_ceilings(&url, Some(Fees::default()))?;
            }
            return Err(e);
        }
    };
    for (url, _) in wallet.hubs()? {
        let urls = wallet.hub_urls(&url)?;
        wallet.set_fee_ceilings(&url, strictest(&contracts, &ceilings, &urls, tip))?;
    }
    Ok(())
}

/// Agree to `fees` at `hub`, a hub `wallet` trusts: what it charges now,
/// as she was shown. The ceilings of each of her contracts there in
/// `wallet_file`, but those given up or whose F never confirms, are raised to
/// them, fee by fee, none lowered: those still opening too, not to refuse
/// the same fees again once they protect. Then as [`agree`].
pub fn approve<T: Transport>(
    wallet: &Wallet<T>,
    wallet_file: &Path,
    hub: &str,
    fees: &Fees,
    tip: Option<u32>,
) -> Result<()> {
    let urls = wallet.hub_urls(hub)?;
    ensure!(!urls.is_empty(), "{hub} is no hub this wallet trusts");
    let Some(store) = Store::existing(wallet_file)? else {
        return Ok(());
    };
    let ids: Vec<[u8; 32]> = store
        .list()?
        .iter()
        .filter(|c| c.at(&urls) && c.abandoned.is_none() && c.fate != Some(Fate::Dead))
        .map(|c| c.id)
        .collect();
    let raised = store.raise_ceilings(&ids, fees)?;
    tracing::info!(%hub, contracts = ids.len(), raised, "fees approved");
    drop(store);
    agree(wallet, wallet_file, tip)
}

/// The least of each fee in the `ceilings` of the `contracts` at the hub
/// of `urls` that protect notes at `tip`: none if none of them keeps any.
fn strictest(
    contracts: &[Contract],
    ceilings: &HashMap<[u8; 32], Fees>,
    urls: &[String],
    tip: Option<u32>,
) -> Option<Fees> {
    contracts
        .iter()
        .filter(|c| c.at(urls) && c.live(tip.unwrap_or(0)))
        .filter_map(|c| ceilings.get(&c.id))
        .copied()
        .reduce(|a, b| a.least(&b))
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use bitcoin::hashes::Hash as _;
    use bitcoin::{OutPoint, Txid};
    use licash::address::OwnerKeys;
    use licash::crypto::schnorr_sign;
    use licash::note::IssuerKeys;
    use licash::spend::ChainProfile;
    use licash_api::{Hex, Info};
    use licash_contract::opening::Phase;
    use licash_wallet::Response;

    use super::super::store::New;
    use super::*;

    /// Hubs by URL, each answering what it says of itself and no more.
    #[derive(Default)]
    struct Hubs(Mutex<HashMap<String, Info>>);

    impl Hubs {
        /// The hub at `url`, of keys of its own, charging `fees` from now.
        fn charge(&self, url: &str, seed: u8, fees: Fees) {
            let keys = IssuerKeys::from_seed(&[seed; 32], 0, 6).unwrap();
            let owner = OwnerKeys::from_seed(&[seed; 32]).unwrap();
            let mut info = Info::new(&[keys.keyset().unwrap()], owner.address(), fees, None);
            // A wallet keeps only a hub proving the identity it advertises.
            let identity = info.identity(ChainProfile::Core30DefaultRegtest).unwrap();
            let proof = schnorr_sign(owner.spend_secret(), &identity).unwrap();
            info.proof = Some(Hex(proof.0.to_vec()));
            self.0.lock().unwrap().insert(url.to_owned(), info);
        }
    }

    impl Transport for &Hubs {
        async fn request(&self, url: &str, _: Option<Vec<u8>>) -> Result<Response, String> {
            let hubs = self.0.lock().unwrap();
            let info = url
                .strip_suffix(licash_api::INFO)
                .and_then(|hub| hubs.get(hub))
                .ok_or("no hub here")?;
            Ok(Response {
                status: 200,
                body: serde_json::to_vec(info).unwrap(),
            })
        }
    }

    impl Transport for Hubs {
        async fn request(&self, _: &str, _: Option<Vec<u8>>) -> Result<Response, String> {
            Err("no hub here".into())
        }
    }

    fn fees(base: u64, ppm: u64, output_msat: u64) -> Fees {
        let fee = Fee { base, ppm };
        Fees {
            spend: fee,
            lock: fee,
            refund: fee,
            output_msat,
        }
    }

    fn contract(id: u8, hub: &str, fate: Option<Fate>) -> Contract {
        Contract {
            id: [id; 32],
            hub: hub.to_owned(),
            phase: Phase::Funded,
            mock: true,
            deposit: OutPoint {
                txid: Txid::from_byte_array([9; 32]),
                vout: u32::from(id),
            },
            value: 60_000,
            price: 23_000,
            cap: 4_096,
            assert_height: 360,
            close_height: 500,
            since: 200,
            funding: None,
            fate,
            abandoned: None,
            created_at: 0,
            folded: None,
            funded: 0,
            funded_received: false,
        }
    }

    #[test]
    fn a_hub_charging_what_hubs_do_is_sane_and_one_charging_more_is_told_why() {
        assert_eq!(abusive(&Fees::default()), None);
        assert_eq!(abusive(&fees(1, 100, 100)), None);
        assert_eq!(abusive(&SANE), None);
        // Each fee, of each kind.
        let over = |fees: Fees| abusive(&fees).unwrap();
        for (raised, what) in [
            (
                Fees {
                    spend: Fee { base: 11, ppm: 0 },
                    ..SANE
                },
                "payment's base",
            ),
            (
                Fees {
                    spend: Fee {
                        base: 0,
                        ppm: 10_001,
                    },
                    ..SANE
                },
                "payment's fee",
            ),
            (
                Fees {
                    lock: Fee { base: 11, ppm: 0 },
                    ..SANE
                },
                "lock's base",
            ),
            (
                Fees {
                    lock: Fee {
                        base: 0,
                        ppm: 10_001,
                    },
                    ..SANE
                },
                "lock's fee",
            ),
            (
                Fees {
                    refund: Fee { base: 11, ppm: 0 },
                    ..SANE
                },
                "refund's base",
            ),
            (
                Fees {
                    refund: Fee {
                        base: 0,
                        ppm: 10_001,
                    },
                    ..SANE
                },
                "refund's fee",
            ),
            (
                Fees {
                    output_msat: 1_001,
                    ..SANE
                },
                "each note",
            ),
        ] {
            let why = over(raised);
            assert!(why.contains(what), "{why}");
            assert!(raised.above(&SANE));
        }
    }

    /// A contract's cost is judged against the coin paying it, not its
    /// hub's rate: a high rate on a little of the hub's own is sane, her
    /// reserve is no cost, and a coin little more than the price, the hub
    /// funding most of a large cap, is not opened unasked.
    #[test]
    fn a_contract_costing_more_than_half_its_coin_is_told_why() {
        // Her reserve, 20,000 sat, comes back: 10,000 of fee of a 50,000 coin.
        assert_eq!(costly(30_000, 20_000, 50_000), None);
        // Half exactly, of an odd coin too.
        assert_eq!(costly(45_000, 20_000, 50_000), None);
        assert_eq!(costly(45_000, 20_000, 50_001), None);
        let why = costly(45_001, 20_000, 50_000).unwrap();
        assert!(why.contains("25001") && why.contains("25000"), "{why}");
        // Mostly the hub's: a coin of the price and a little more.
        assert!(costly(130_000, 20_000, 131_000).is_some());
        // A reserve above the price is no gain.
        assert_eq!(costly(10_000, 20_000, 0), None);
    }

    #[tokio::test]
    async fn a_hub_is_held_to_what_it_charged_as_her_contracts_opened_until_she_approves_more() {
        let (a, b) = ("http://a.example", "http://b.example");
        let hubs = Hubs::default();
        hubs.charge(a, 1, fees(1, 100, 100));
        hubs.charge(b, 2, fees(1, 100, 100));
        let dir = tempfile::tempdir().unwrap();
        let regtest = ChainProfile::Core30DefaultRegtest;
        let path = dir.path().join("wallet.sqlite");
        let wallet = Wallet::create(&path, &[7; 32], regtest, &hubs).unwrap();
        wallet.add_hub(a).await.unwrap();
        wallet.add_hub(b).await.unwrap();
        let agreed = |hub: &str| wallet.fee_ceilings(hub).unwrap();

        // No contract ever opened: nothing agreed, nothing made.
        agree(&wallet, &dir.path().join("wallet.sqlite"), None).unwrap();
        approve(
            &wallet,
            &dir.path().join("wallet.sqlite"),
            a,
            &fees(9, 9, 9),
            None,
        )
        .unwrap();
        assert_eq!((agreed(a), agreed(b)), (None, None));
        assert!(Store::existing(&path).unwrap().is_none());
        assert!(approve(
            &wallet,
            &dir.path().join("wallet.sqlite"),
            "http://c.example",
            &fees(9, 9, 9),
            None
        )
        .is_err());

        let new = |id: u8, hub: &'static str| New {
            id: [id; 32],
            hub,
            mock: true,
            deposit: OutPoint {
                txid: Txid::from_byte_array([9; 32]),
                vout: u32::from(id),
            },
            value: 60_000,
            price: 23_000,
            cap: 4_096,
            assert_height: 360,
            close_height: 500,
            since: 200,
            state: b"state",
        };
        let store = Store::open(&crate::testing::wallet_file(dir.path())).unwrap();
        // Two buried, one still opening and one given up, at the first hub;
        // one never to be, at the other.
        store
            .insert_under(&new(1, a), &fees(1, 100, 100), 0)
            .unwrap();
        store.set_fate(&[1; 32], Fate::Live).unwrap();
        store
            .insert_under(&new(2, a), &fees(1, 100, 100), 0)
            .unwrap();
        store.set_fate(&[2; 32], Fate::Live).unwrap();
        store
            .insert_under(&new(3, a), &fees(1, 100, 100), 0)
            .unwrap();
        store
            .insert_under(&new(4, a), &fees(1, 100, 100), 0)
            .unwrap();
        store.abandon(&[4; 32], "refused").unwrap();
        store
            .insert_under(&new(5, b), &fees(1, 100, 100), 0)
            .unwrap();
        store.set_fate(&[5; 32], Fate::Dead).unwrap();
        drop(store);

        agree(&wallet, &dir.path().join("wallet.sqlite"), Some(250)).unwrap();
        assert_eq!((agreed(a), agreed(b)), (Some(fees(1, 100, 100)), None));
        // Past the time of the one that protected: nothing agreed.
        agree(&wallet, &dir.path().join("wallet.sqlite"), Some(360)).unwrap();
        assert_eq!(agreed(a), None);
        agree(&wallet, &dir.path().join("wallet.sqlite"), None).unwrap();
        assert_eq!(agreed(a), Some(fees(1, 100, 100)));

        // It charges more, in one fee and less in another: hers to approve,
        // as she was shown.
        hubs.charge(a, 1, fees(0, 150, 100));
        let charged = wallet.add_hub(a).await.unwrap().fees;
        assert!(charged.above(&agreed(a).unwrap()));
        approve(
            &wallet,
            &dir.path().join("wallet.sqlite"),
            a,
            &charged,
            Some(250),
        )
        .unwrap();
        assert_eq!(agreed(a), Some(fees(1, 150, 100)));
        assert!(!charged.above(&agreed(a).unwrap()));
        // Of each of her contracts there that may yet protect, and no
        // other: kept, as a wallet opened again finds them.
        let kept = Store::open(&crate::testing::wallet_file(dir.path()))
            .unwrap()
            .ceilings()
            .unwrap();
        assert_eq!(kept.len(), 5);
        assert_eq!(kept[&[1; 32]], fees(1, 150, 100));
        assert_eq!(kept[&[2; 32]], fees(1, 150, 100));
        assert_eq!(kept[&[3; 32]], fees(1, 150, 100));
        assert_eq!(kept[&[4; 32]], fees(1, 100, 100));
        assert_eq!(kept[&[5; 32]], fees(1, 100, 100));
        wallet.set_fee_ceilings(a, None).unwrap();
        agree(&wallet, &dir.path().join("wallet.sqlite"), Some(250)).unwrap();
        assert_eq!(agreed(a), Some(fees(1, 150, 100)));

        // The hub changes fees after they were shown: approving the
        // snapshot never approves a higher schedule learned meanwhile.
        hubs.charge(a, 1, fees(0, 300, 100));
        let later = wallet.add_hub(a).await.unwrap().fees;
        approve(
            &wallet,
            &dir.path().join("wallet.sqlite"),
            a,
            &charged,
            Some(250),
        )
        .unwrap();
        assert_eq!(agreed(a), Some(fees(1, 150, 100)));
        assert!(later.above(&agreed(a).unwrap()));
    }

    #[test]
    fn the_strictest_ceilings_of_the_contracts_protecting_at_a_hub_are_hers() {
        let (a, b) = ("http://a.example", "http://b.example");
        let live = Some(Fate::Live);
        let mut expired = contract(4, a, live);
        expired.assert_height = 300;
        let mut given_up = contract(5, a, None);
        given_up.abandoned = Some("refused".into());
        let contracts = [
            contract(1, a, live),
            contract(2, a, live),
            // Opened before any were kept.
            contract(3, a, live),
            expired,
            given_up,
            // Not buried yet, or never to be.
            contract(6, a, Some(Fate::Open)),
            contract(7, a, Some(Fate::Dead)),
            contract(8, b, live),
        ];
        let ceilings = HashMap::from([
            ([1; 32], fees(2, 100, 100)),
            ([2; 32], fees(1, 500, 0)),
            ([4; 32], fees(0, 0, 0)),
            ([5; 32], fees(0, 0, 0)),
            ([6; 32], fees(0, 0, 0)),
            ([7; 32], fees(0, 0, 0)),
            ([8; 32], fees(7, 7, 7)),
        ]);
        let urls = |all: &[&str]| all.iter().map(|u| (*u).to_owned()).collect::<Vec<_>>();
        let of = |hubs: &[&str], tip| strictest(&contracts, &ceilings, &urls(hubs), tip);
        assert_eq!(of(&[a], Some(310)), Some(fees(1, 100, 0)));
        // The tip unknown: one whose F is buried counts, past its time too.
        assert_eq!(of(&[a], None), Some(fees(0, 0, 0)));
        // None protects any longer: nothing agreed.
        assert_eq!(of(&[a], Some(360)), None);
        // By any of the hub's addresses, however written.
        assert_eq!(of(&["http://b.example/"], Some(310)), Some(fees(7, 7, 7)));
        assert_eq!(of(&["http://c.example", b], Some(310)), Some(fees(7, 7, 7)));
        assert_eq!(of(&["http://c.example"], Some(310)), None);
        // At a hub whose contracts kept none: nothing agreed.
        let only = [contract(3, a, live)];
        assert_eq!(strictest(&only, &ceilings, &urls(&[a]), Some(310)), None);
    }
}
