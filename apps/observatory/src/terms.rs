//! A service's terms as its info says them, read part by part: the
//! services watched run versions older and newer than this one, and a part
//! this version cannot read is shown as unknown rather than failing the
//! rest, or the service's health.

use licash_api::{swaps, Deposits, Fee, Fees, Lightning};
use serde::{de::DeserializeOwned, Serialize};
use serde_json::Value;

/// What a hub's info says, as far as it is read.
#[derive(Clone, Debug, Default, Serialize)]
pub struct HubTerms {
    /// Its address, as its info writes it: how providers name it.
    pub address: Option<Value>,
    pub fees: Option<Fees>,
    pub lightning: Option<Lightning>,
    pub deposits: Option<Deposits>,
    pub protection: Option<Protection>,
    /// The height its chain is scanned to.
    pub height: Option<u32>,
}

/// The recovery contracts a hub opens, read from its info of any version.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct Protection {
    /// Under the mock authority: protects nothing.
    pub mock: bool,
    /// Its usual contract: what it protects, and what opening it costs.
    pub cap: Option<u64>,
    pub price: Option<u64>,
    /// If the holder may choose: the hub's fixed fee for an opening,
    /// interest by the year on the part the hub funds and on hers, in
    /// millionths, the holder's reserve, and the sizes offered.
    pub opening: Option<u64>,
    pub ppm_year: Option<u64>,
    pub ppm_year_funded: Option<u64>,
    pub reserve: Option<u64>,
    pub min_cap: Option<u64>,
    pub max_cap: Option<u64>,
}

/// What a provider's info says, as far as it is read.
#[derive(Clone, Debug, Default, Serialize)]
pub struct ProviderTerms {
    pub fee: Option<Fee>,
    pub min: Option<u64>,
    pub max: Option<u64>,
    /// Each hub it swaps at, by its address, and what it can lock to a
    /// client there now.
    pub hubs: Vec<(Value, u64)>,
    pub chain: Option<swaps::Chain>,
    pub lightning: Option<swaps::Lightning>,
    /// Its deposits on Bitcoin for notes at its hubs, if it takes them.
    pub deposits: Option<swaps::Deposits>,
}

fn part<T: DeserializeOwned>(info: &Value, key: &str) -> Option<T> {
    serde_json::from_value(info.get(key)?.clone()).ok()
}

fn number(value: &Value, key: &str) -> Option<u64> {
    value.get(key)?.as_u64()
}

pub fn hub(json: &str) -> Option<HubTerms> {
    let info: Value = serde_json::from_str(json).ok()?;
    Some(HubTerms {
        address: info.get("address").cloned(),
        fees: part(&info, "fees"),
        lightning: part(&info, "lightning"),
        deposits: part(&info, "deposits"),
        protection: info
            .get("contracts")
            .filter(|c| c.is_object())
            .map(protection),
        height: info
            .get("locks")
            .and_then(|l| number(l, "height"))
            .and_then(|h| u32::try_from(h).ok()),
    })
}

fn protection(contracts: &Value) -> Protection {
    let range = contracts.get("range").filter(|r| r.is_object());
    let of_range = |key| range.and_then(|r| number(r, key));
    Protection {
        mock: contracts
            .get("mock")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        cap: number(contracts, "cap"),
        price: number(contracts, "price"),
        // Hubs before the reserve called their fee `base`.
        opening: of_range("fee").or_else(|| of_range("base")),
        ppm_year: of_range("ppm_year"),
        ppm_year_funded: of_range("ppm_year_funded"),
        reserve: of_range("reserve"),
        min_cap: of_range("min_cap"),
        max_cap: of_range("max_cap"),
    }
}

pub fn provider(json: &str) -> Option<ProviderTerms> {
    let info: Value = serde_json::from_str(json).ok()?;
    let hubs = info
        .get("hubs")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|h| Some((h.get("address")?.clone(), number(h, "max")?)))
        .collect();
    Some(ProviderTerms {
        fee: part(&info, "fee"),
        min: number(&info, "min"),
        max: number(&info, "max"),
        hubs,
        chain: part(&info, "chain"),
        lightning: part(&info, "lightning"),
        deposits: part(&info, "deposits"),
    })
}

/// The Nostr key an info names, if it is an info of a hub (`hub`) or of a
/// provider at all: `Err` if it is not.
pub fn nostr(json: &Value, hub: bool) -> Result<Option<String>, String> {
    let shaped = if hub {
        json.get("keysets").is_some_and(Value::is_array) && json.get("fees").is_some()
    } else {
        json.get("hubs").is_some_and(Value::is_array) && json.get("fee").is_some()
    };
    if !shaped {
        let what = if hub { "a hub's" } else { "a swap provider's" };
        return Err(format!("not {what} info"));
    }
    Ok(json.get("nostr").and_then(Value::as_str).map(str::to_owned))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_older_hubs_protection_is_read() {
        // As the signet hub said it on 2026-11-21, before the reserve.
        let json = r#"{"keysets":[],"fees":{"spend":{"base":0,"ppm":10}},
            "contracts":{"cap":4096,"price":23000,"blocks":1000,"mock":false,
            "range":{"min_cap":4096,"max_cap":4096,"min_blocks":432,"max_blocks":52560,
            "per_coin":2,"base":23000,"ppm_year":10000}},
            "locks":{"height":331826},"lightning":{"bad":true}}"#;
        let terms = hub(json).unwrap();
        let protection = terms.protection.unwrap();
        assert_eq!(protection.opening, Some(23_000));
        assert_eq!(protection.ppm_year, Some(10_000));
        assert_eq!(protection.reserve, None);
        assert_eq!(terms.fees.unwrap().spend, Fee { base: 0, ppm: 10 });
        assert_eq!(terms.height, Some(331_826));
        assert!(terms.lightning.is_none(), "a part not read is unknown");
    }

    #[test]
    fn a_providers_deposits_are_read_if_it_takes_them() {
        let deposits = r#""deposits":{"fee":{"base":0,"ppm":5000},"miner":500,
            "min":10000,"max":1000000,"depth":3,"window":12,"timeout":1008}"#;
        let json = format!(r#"{{"hubs":[{{"address":"ab","max":5000}}],{deposits}}}"#);
        let terms = provider(&json).unwrap();
        let taken = terms.deposits.unwrap();
        assert_eq!((taken.min, taken.miner, taken.depth), (10_000, 500, 3));
        assert_eq!(taken.pays(10_000), 10_550);
        assert_eq!(terms.hubs, [(Value::from("ab"), 5_000)]);
        assert!(provider(r#"{"hubs":[]}"#).unwrap().deposits.is_none());
    }

    #[test]
    fn an_info_of_the_wrong_role_is_refused() {
        let hub: Value = serde_json::from_str(r#"{"keysets":[],"fees":{},"nostr":"ab"}"#).unwrap();
        assert_eq!(nostr(&hub, true), Ok(Some("ab".into())));
        assert!(nostr(&hub, false).is_err());
    }
}
