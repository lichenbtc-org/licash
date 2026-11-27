//! Lightning Addresses of donations (LUD-16): `name@domain`, its domain the
//! provider's public URL's ([`Provider::names_domain`]), its name made of a
//! wallet's code ([`licash_wallet::donation_name`]) and registered by the
//! wallet ([`Provider::register_name`]), paid as the code's LNURL is.
//!
//! A name is bound to its code: the provider makes it of the code itself,
//! so no one registers a name paying another wallet. Registering only makes
//! the code known under its name; any code's LNURL takes donations without.
//! New names are bounded by source and in all ([`MAX_NAMES`]): past those,
//! a wallet shows its LNURL instead.

use licash::spend::ChainProfile;
use licash_api::Problem;
use licash_wallet::{donation_name, Transport};
use rusqlite::{params, OptionalExtension};

use crate::{store, unavailable, Provider};

/// The component of the names registered, and its version.
const COMPONENT: &str = "provider_names";
const VERSION: i64 = 1;

const SCHEMA: &str = "
-- The names of the Lightning Addresses of donations (`crate::names`): each
-- the name of `code`, its text as the provider writes it, registered from
-- `source`, if known, at `created_at`.
CREATE TABLE provider_names (
    name TEXT PRIMARY KEY,
    code TEXT NOT NULL,
    source BLOB,
    created_at INTEGER NOT NULL
) STRICT;
CREATE INDEX provider_names_source ON provider_names (source, created_at);
";

/// The most names registered in all: past it, none new.
pub const MAX_NAMES: i64 = 100_000;

/// Seconds over which one source registers at most [`crate::PER_SOURCE`]
/// new names.
const SOURCE_WINDOW: i64 = 3600;

/// What a donation to a Lightning Address says of itself, as LNURL-pay
/// metadata (LUD-16): what [`crate::METADATA`] says, and the address.
pub fn named_metadata(address: &str) -> String {
    serde_json::json!([
        ["text/plain", "A donation to a Licash wallet"],
        ["text/identifier", address],
    ])
    .to_string()
}

/// The domain of the Lightning Addresses served at the public URL `url`,
/// `host` or `host:port`, on `network`: none unless `url` is an origin, no
/// path, as `.well-known` is at its root, and over HTTPS, or HTTP to an
/// onion service or on regtest, as payers ask.
pub fn names_domain(url: &str, network: ChainProfile) -> Option<String> {
    let url = url.trim_end_matches('/').to_ascii_lowercase();
    let (secure, origin) = match url.split_once("://")? {
        ("https", origin) => (true, origin),
        ("http", origin) => (false, origin),
        _ => return None,
    };
    if origin.is_empty() || origin.contains(['/', '?', '#', '@']) {
        return None;
    }
    let host = origin.split(':').next().unwrap_or(origin);
    let plain_ok = host.ends_with(".onion") || network == ChainProfile::Core30DefaultRegtest;
    (secure || plain_ok).then(|| origin.to_owned())
}

/// Lightning Addresses of donations.
impl<T: Transport> Provider<T> {
    /// The names' table, made if missing: with donations taken.
    pub(crate) fn keep_names(&self) -> Result<(), crate::Error> {
        self.store.write(|tx| {
            licash_store::component_in(tx, COMPONENT, VERSION, SCHEMA).map_err(store::setup)
        })
    }

    /// The domain of the Lightning Addresses of donations it serves, if it
    /// takes donations at a public URL that serves them ([`names_domain`]).
    pub fn names_domain(&self) -> Option<String> {
        let url = &self.donations.as_ref()?.url;
        names_domain(url, self.wallet.network())
    }

    /// Register the name of the Lightning Address of donations to the
    /// wallet of `code`, asked from `source`, if known: its name. Again
    /// and again, as kept. Unavailable past [`crate::PER_SOURCE`] new from
    /// `source` within an hour, or [`MAX_NAMES`] in all; refused if the
    /// provider serves no names, or another code has the name.
    pub fn register_name(&self, code: &str, source: Option<&[u8]>) -> Result<String, Problem> {
        if self.names_domain().is_none() {
            return Err(crate::declined(
                "the provider serves no Lightning Addresses",
            ));
        }
        let code = self.payee(code)?;
        let name = donation_name(&code);
        let text = code.to_string();
        let at = store::now();
        let registered = self
            .store
            .write(|tx| {
                let kept: Option<String> = tx
                    .query_row(
                        "SELECT code FROM provider_names WHERE name = ?1",
                        [&name],
                        |r| r.get(0),
                    )
                    .optional()?;
                match kept {
                    Some(kept) if kept == text => return Ok(Ok(())),
                    Some(_) => {
                        return Ok(Err(Problem::invalid(
                            "another code has the name of this one",
                        )))
                    }
                    None => {}
                }
                let all: i64 =
                    tx.query_row("SELECT count(*) FROM provider_names", [], |r| r.get(0))?;
                if all >= MAX_NAMES {
                    return Ok(Err(unavailable("no more Lightning Addresses now")));
                }
                if let Some(source) = source {
                    let lately: u32 = tx.query_row(
                        "SELECT count(*) FROM provider_names WHERE source = ?1 AND created_at > ?2",
                        params![source, at - SOURCE_WINDOW],
                        |r| r.get(0),
                    )?;
                    if lately >= crate::PER_SOURCE {
                        return Ok(Err(unavailable(
                            "too many Lightning Addresses asked from this source: try again later",
                        )));
                    }
                }
                tx.execute(
                    "INSERT INTO provider_names (name, code, source, created_at)
                     VALUES (?1, ?2, ?3, ?4)",
                    params![name, text, source, at],
                )?;
                Ok(Ok(()))
            })
            .map_err(unavailable)?;
        registered.map(|()| name)
    }

    /// The code registered under `name`, as written in an address, and the
    /// metadata its donations commit to: refused if none is.
    pub fn named(&self, name: &str) -> Result<(String, String), Problem> {
        let Some(domain) = self.names_domain() else {
            return Err(crate::declined(
                "the provider serves no Lightning Addresses",
            ));
        };
        let name = name.to_ascii_lowercase();
        let code: Option<String> = self
            .store
            .write(|tx| {
                let code = tx
                    .query_row(
                        "SELECT code FROM provider_names WHERE name = ?1",
                        [&name],
                        |r| r.get(0),
                    )
                    .optional()?;
                Ok(code)
            })
            .map_err(unavailable)?;
        let code = code.ok_or_else(|| Problem::invalid("no such Lightning Address"))?;
        Ok((code, named_metadata(&format!("{name}@{domain}"))))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_are_served_at_an_origin_payers_ask_as_they_may() {
        let main = ChainProfile::Core30Mainnet;
        let regtest = ChainProfile::Core30DefaultRegtest;
        let domain = |url: &str, network| names_domain(url, network);
        assert_eq!(
            domain("https://Donate.Example/", main),
            Some("donate.example".into())
        );
        assert_eq!(
            domain("https://donate.example:8443", main),
            Some("donate.example:8443".into())
        );
        assert_eq!(domain("http://abc.onion", main), Some("abc.onion".into()));
        assert_eq!(
            domain("http://127.0.0.1:8080", regtest),
            Some("127.0.0.1:8080".into())
        );
        // A path: `.well-known` is not under it.
        assert_eq!(domain("https://example.com/donate", main), None);
        // Plain HTTP, but to an onion service or on regtest.
        assert_eq!(domain("http://donate.example", main), None);
        assert_eq!(domain("ftp://donate.example", main), None);
        assert_eq!(domain("https://", main), None);
    }

    #[test]
    fn a_named_donation_says_its_address() {
        let metadata = named_metadata("0123456789abcdef@donate.example");
        let entries: Vec<(String, String)> = serde_json::from_str(&metadata).unwrap();
        assert_eq!(
            entries,
            [
                ("text/plain".into(), "A donation to a Licash wallet".into()),
                (
                    "text/identifier".into(),
                    "0123456789abcdef@donate.example".into()
                ),
            ]
        );
    }
}
