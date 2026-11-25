//! Payment codes: one text, or QR code, a payer scans to pay a wallet, in
//! notes or on Bitcoin, one or the other.
//!
//! A code to pay in notes is `licash:<code>[?amount=<sat>]`, its amount in
//! satoshis. A code to pay on Bitcoin is a BIP321 URI,
//! `bitcoin:<address>?sp=<silent payment address>`, which any wallet pays:
//! at the silent payment address if it pays them, else at the address, the
//! wallet's fallback address. A Licash code is bech32m (BIP350), at most
//! 1023 characters, under `licash` on mainnet and `tlicash` on the other
//! networks, of version 0:
//! the network's byte, the 99 bytes of the wallet's [`Address`], then
//! records of a type byte, a length byte and the value, in non-decreasing
//! order of type:
//!
//! - 1, once at most: the x-only Nostr key of the wallet's mailbox, where
//!   payers send it payments (NIP-17), on the relays its hubs name.
//! - 2, any number up to [`MAX_HUBS`]: a hub the wallet is paid at
//!   ([`HubId`]), in its order of preference. A wallet names
//!   [`CODE_HUBS`] at most.
//! - 3, once at most for each hub of type 2: where to reach it, its
//!   position among them (one byte), its URL's scheme (0 `https://`, 1
//!   `http://`, of an onion service but on regtest) and the rest of its
//!   URL, of 1 to 64 printable ASCII characters. Written only while the
//!   whole stays within 260 bytes.
//!
//! Records of other types are skipped, and locations that are not; a code
//! of a later version is refused. A
//! hub named in a code is no reason to trust it: a payer pays at a hub it
//! trusts already, or at one whose info proves it the hub named
//! ([`licash_api::Info::proved`]) wherever it was reached.

use std::{fmt, str::FromStr};

use bitcoin::{
    address::NetworkUnchecked,
    bech32::{
        primitives::{
            decode::CheckedHrpstring,
            iter::{ByteIterExt, Fe32IterExt},
        },
        Bech32m, Fe32, Hrp,
    },
    secp256k1::{Secp256k1, SecretKey},
    Amount, Denomination, NetworkKind,
};
use licash::{address::Address, crypto::tagged_hash, spend::ChainProfile};
use licash_onchain::silent::SpAddress;

use crate::{Error, Transport, Wallet};

/// The most hubs a code names that a payer reads.
pub const MAX_HUBS: usize = 8;
/// The most hubs a wallet names in its codes: its few preferred, which
/// keeps codes short and says little of where else it holds notes.
pub const CODE_HUBS: usize = 3;

const MAILBOX: u8 = 1;
const HUB: u8 = 2;
const LOCATION: u8 = 3;

/// The longest URL of a location, past its scheme.
const MAX_LOCATION: usize = 64;
/// The most bytes of a code its locations are written within.
const MAX_LOCATED: usize = 260;

/// A hub, as payment codes name it: the first 16 bytes of the tagged hash
/// of the address in its info. Its URLs may change, and differ between
/// wallets (one over Tor, one not); its address does not.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct HubId(pub [u8; 16]);

impl HubId {
    /// The hub whose info names `address`.
    pub fn of(address: &Address) -> Self {
        let hash = tagged_hash("licash/code/hub", &[&address.to_bytes()]);
        let mut id = [0; 16];
        id.copy_from_slice(&hash[..16]);
        Self(id)
    }
}

/// What a payment code asks to be paid with: in notes, if `licash`, else
/// on Bitcoin.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PaymentCode {
    /// An address on Bitcoin, as in any BIP21 URI.
    pub address: Option<bitcoin::Address<NetworkUnchecked>>,
    /// In satoshis.
    pub amount: Option<u64>,
    /// A silent payment address (BIP352).
    pub silent: Option<SpAddress>,
    /// The wallet to pay in notes: a code with it is written as a
    /// `licash:` URI, without `address` or `silent`.
    pub licash: Option<LicashCode>,
}

/// The Licash part of a payment code: the wallet to pay in notes, where.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LicashCode {
    pub network: ChainProfile,
    pub address: Address,
    /// The x-only Nostr key payments are sent to.
    pub mailbox: Option<[u8; 32]>,
    /// The hubs it is paid at, preferred first; at most [`MAX_HUBS`] are
    /// written.
    pub hubs: Vec<HubId>,
    /// Where to reach hubs of `hubs`, by URL: what a payer reaching one
    /// checks there is that hub. Written for those of `hubs` only, once
    /// each, while they fit.
    pub locations: Vec<(HubId, String)>,
}

/// The scheme byte and the rest of `url`, as a location on `network`
/// writes it: none if it can't. Plain HTTP only to an onion service, which
/// Tor authenticates, but on regtest.
fn location(network: ChainProfile, url: &str) -> Option<(u8, &str)> {
    let (scheme, rest) = match (url.strip_prefix("https://"), url.strip_prefix("http://")) {
        (Some(rest), _) => (0, rest),
        (_, Some(rest)) => (1, rest),
        _ => return None,
    };
    let host = rest.split(['/', ':']).next().unwrap_or(rest);
    let plain = scheme == 1 && !host.ends_with(".onion");
    let printable = rest.bytes().all(|b| (0x21..=0x7e).contains(&b));
    let fits = (1..=MAX_LOCATION).contains(&rest.len());
    (printable && fits && !(plain && network != ChainProfile::Core30DefaultRegtest))
        .then_some((scheme, rest))
}

fn network_kind(network: ChainProfile) -> NetworkKind {
    match network {
        ChainProfile::Core30Mainnet => NetworkKind::Main,
        _ => NetworkKind::Test,
    }
}

fn invalid(why: impl fmt::Display) -> Error {
    Error::Invalid(format!("not a payment code: {why}"))
}

impl LicashCode {
    fn hrp(network: ChainProfile) -> Hrp {
        let hrp = match network_kind(network) {
            NetworkKind::Main => "licash",
            NetworkKind::Test => "tlicash",
        };
        Hrp::parse(hrp).expect("a valid hrp")
    }

    /// Its bytes, as its text writes them in bech32: within 260 for a
    /// code naming at most [`CODE_HUBS`] hubs.
    pub(crate) fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = vec![self.network.tag()];
        bytes.extend(self.address.to_bytes());
        if let Some(mailbox) = &self.mailbox {
            bytes.extend([MAILBOX, 32]);
            bytes.extend(mailbox);
        }
        let hubs = &self.hubs[..self.hubs.len().min(MAX_HUBS)];
        for hub in hubs {
            bytes.extend([HUB, 16]);
            bytes.extend(hub.0);
        }
        for (index, hub) in hubs.iter().enumerate() {
            if hubs[..index].contains(hub) {
                continue;
            }
            let found = self.locations.iter().find(|(id, _)| id == hub);
            let Some((scheme, rest)) = found.and_then(|(_, url)| location(self.network, url))
            else {
                continue;
            };
            if bytes.len() + 4 + rest.len() > MAX_LOCATED {
                continue;
            }
            bytes.extend([LOCATION, 2 + rest.len() as u8, index as u8, scheme]);
            bytes.extend(rest.as_bytes());
        }
        bytes
    }

    /// The code `s` writes, or none if of a later version.
    fn decode(s: &str) -> Result<Option<Self>, Error> {
        let checked = CheckedHrpstring::new::<Bech32m>(s).map_err(invalid)?;
        let test = match checked.hrp().to_lowercase().as_str() {
            "licash" => false,
            "tlicash" => true,
            hrp => return Err(invalid(format!("prefix {hrp}"))),
        };
        let data = checked.data_part_ascii_no_checksum();
        let (version, data) = data.split_first().ok_or_else(|| invalid("empty"))?;
        let version = Fe32::from_char((*version).into()).map_err(invalid)?;
        if version != Fe32::Q {
            return Ok(None);
        }
        let code = Self::from_bytes(&fes_to_bytes(data)?)?;
        if test != (network_kind(code.network) == NetworkKind::Test) {
            return Err(invalid(format!(
                "a code of {} under {}",
                code.network,
                checked.hrp()
            )));
        }
        Ok(Some(code))
    }

    /// The code of version 0 `bytes` write ([`LicashCode::to_bytes`]).
    pub(crate) fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let (&network, rest) = bytes.split_first().ok_or_else(|| invalid("empty"))?;
        let network = ChainProfile::ALL
            .into_iter()
            .find(|n| n.tag() == network)
            .ok_or_else(|| invalid(format!("network {network}")))?;
        if rest.len() < 99 {
            return Err(invalid("too short"));
        }
        let (address, mut records) = rest.split_at(99);
        let mut code = Self {
            network,
            address: Address::from_bytes(address).map_err(invalid)?,
            mailbox: None,
            hubs: Vec::new(),
            locations: Vec::new(),
        };
        let mut located = Vec::new();
        let mut last = 0;
        while let [kind, len, rest @ ..] = records {
            let (kind, len) = (*kind, usize::from(*len));
            if kind < last || rest.len() < len {
                return Err(invalid("records out of order or cut short"));
            }
            let (value, rest) = rest.split_at(len);
            match kind {
                MAILBOX if last == MAILBOX || len != 32 => return Err(invalid("mailbox")),
                MAILBOX => code.mailbox = Some(value.try_into().expect("32 bytes")),
                HUB if len != 16 || code.hubs.len() == MAX_HUBS => return Err(invalid("hubs")),
                HUB => code.hubs.push(HubId(value.try_into().expect("16 bytes"))),
                // One not understood is no reason to refuse the rest.
                LOCATION => {
                    if let Some((index, url)) = code.location(value) {
                        if !located.contains(&index) {
                            located.push(index);
                            code.locations.push((code.hubs[index], url));
                        }
                    }
                }
                _ => {}
            }
            (last, records) = (kind, rest);
        }
        if !records.is_empty() {
            return Err(invalid("a record cut short"));
        }
        Ok(code)
    }

    /// The hub's position and URL a location's `value` writes, if valid.
    fn location(&self, value: &[u8]) -> Option<(usize, String)> {
        let [index, scheme, rest @ ..] = value else {
            return None;
        };
        let index = usize::from(*index);
        let scheme = match scheme {
            0 => "https://",
            1 => "http://",
            _ => return None,
        };
        let url = format!("{scheme}{}", std::str::from_utf8(rest).ok()?);
        location(self.network, &url)?;
        (index < self.hubs.len()).then_some((index, url))
    }
}

/// Bytes of bech32 characters, their padding zero.
fn fes_to_bytes(chars: &[u8]) -> Result<Vec<u8>, Error> {
    let (mut acc, mut bits, mut bytes) = (0u32, 0u32, Vec::with_capacity(chars.len() * 5 / 8));
    for c in chars {
        let fe = Fe32::from_char((*c).into()).map_err(invalid)?;
        acc = (acc << 5) | u32::from(fe.to_u8());
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            bytes.push((acc >> bits) as u8);
        }
        acc &= (1 << bits) - 1;
    }
    if bits >= 5 || acc != 0 {
        return Err(invalid("padding"));
    }
    Ok(bytes)
}

/// A wallet's static address of donations through a swap provider
/// ([`Wallet::donation_address`]).
#[derive(Clone, Debug)]
pub struct DonationAddress {
    /// The LNURL any Lightning wallet pays, upper case.
    pub lnurl: String,
    /// What the provider takes donations on.
    pub donations: licash_api::swaps::Donations,
    /// Whether it holds enough at a hub of the code now to take the least
    /// donation: if not, payers are refused until it does.
    pub stocked: bool,
    /// The provider's info, as it answered.
    pub info: licash_api::swaps::Info,
}

impl LicashCode {
    /// The static LNURL of donations to this code's wallet through the
    /// provider whose public URL is `base` ([`licash_api::swaps::Donations`]):
    /// its [`licash_api::swaps::donation_url`] in bech32, upper case, as a
    /// QR code holds it best. Any Lightning wallet pays it, again and
    /// again, while the payee is offline.
    pub fn lnurl(&self, base: &str) -> String {
        let url = licash_api::swaps::donation_url(base, &self.to_string());
        let hrp = Hrp::parse("lnurl").expect("a valid prefix");
        bitcoin::bech32::encode_upper::<bitcoin::bech32::Bech32>(hrp, url.as_bytes())
            .expect("a URL short enough")
    }
}

impl fmt::Display for LicashCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let hrp = Self::hrp(self.network);
        let chars = self
            .to_bytes()
            .into_iter()
            .bytes_to_fes()
            .with_checksum::<Bech32m>(&hrp)
            .with_witness_version(Fe32::Q)
            .chars();
        chars
            .into_iter()
            .try_for_each(|c| fmt::Write::write_char(f, c))
    }
}

impl FromStr for LicashCode {
    type Err = Error;

    /// A code of version 0: one of a later version is refused.
    fn from_str(s: &str) -> Result<Self, Error> {
        Self::decode(s)?.ok_or_else(|| invalid("a later version"))
    }
}

impl PaymentCode {
    /// The code to show as a QR code: in upper case, which QR codes hold
    /// in fewer modules, unless its address is not bech32.
    pub fn qr(&self) -> String {
        let text = self.to_string();
        let bech32 = self.address.as_ref().is_none_or(|a| {
            let a = a.assume_checked_ref().to_string();
            a.starts_with("bc1") || a.starts_with("tb1") || a.starts_with("bcrt1")
        });
        match bech32 {
            true => text.to_uppercase(),
            false => text,
        }
    }

    /// Refused unless all of it is of `network`: a payment on another
    /// chain is lost to the payee, so not even the rest is paid.
    pub fn check(&self, network: ChainProfile) -> Result<(), Error> {
        let wrong = |what: &str| Err(Error::Invalid(format!("{what} not on {network}")));
        if self.licash.as_ref().is_some_and(|c| c.network != network) {
            return wrong("a payment code");
        }
        if self
            .silent
            .is_some_and(|s| s.network != network_kind(network))
        {
            return wrong("a silent payment address");
        }
        let bitcoin = licash_onchain::network(network);
        if self
            .address
            .as_ref()
            .is_some_and(|a| !a.is_valid_for_network(bitcoin))
        {
            return wrong("an address");
        }
        Ok(())
    }
}

impl fmt::Display for PaymentCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(licash) = &self.licash {
            write!(f, "licash:{licash}")?;
            if let Some(amount) = self.amount {
                write!(f, "?amount={amount}")?;
            }
            return Ok(());
        }
        write!(f, "bitcoin:")?;
        if let Some(address) = &self.address {
            write!(f, "{}", address.assume_checked_ref())?;
        }
        let mut separator = '?';
        let mut param = |f: &mut fmt::Formatter<'_>, key: &str, value: &dyn fmt::Display| {
            let written = write!(f, "{separator}{key}={value}");
            separator = '&';
            written
        };
        if let Some(amount) = self.amount {
            let btc = Amount::from_sat(amount).to_string_in(Denomination::Bitcoin);
            param(f, "amount", &btc)?;
        }
        if let Some(silent) = &self.silent {
            param(f, "sp", silent)?;
        }
        Ok(())
    }
}

impl FromStr for PaymentCode {
    type Err = Error;

    /// A `licash:` URI, a BIP321 URI, or a bare address: a silent payment
    /// address, a Licash code or an address on Bitcoin. Refused if it asks
    /// for something this does not know (a `req-` parameter) or for
    /// nothing it can pay.
    fn from_str(s: &str) -> Result<Self, Error> {
        let s = s.trim();
        let mut code = Self {
            address: None,
            amount: None,
            silent: None,
            licash: None,
        };
        let scheme = |name: &str| {
            s.get(..name.len())
                .is_some_and(|p| p.eq_ignore_ascii_case(name))
        };
        if scheme("licash:") {
            let (path, query) = s[7..].split_once('?').unwrap_or((&s[7..], ""));
            code.licash = Some(path.parse()?);
            for pair in query.split('&').filter(|p| !p.is_empty()) {
                let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
                let key = key.to_lowercase();
                match key.as_str() {
                    "amount" if code.amount.is_some() => {
                        return Err(invalid(format!("{key} twice")))
                    }
                    "amount" => code.amount = Some(value.parse().map_err(invalid)?),
                    _ if key.starts_with("req-") => {
                        return Err(invalid(format!("it requires {key}")));
                    }
                    _ => {}
                }
            }
            return Ok(code);
        }
        if !scheme("bitcoin:") {
            let lower = s.to_lowercase();
            if lower.starts_with("sp1") || lower.starts_with("tsp1") {
                code.silent = Some(s.parse().map_err(invalid)?);
            } else if lower.starts_with("licash1") || lower.starts_with("tlicash1") {
                code.licash = Some(s.parse()?);
            } else {
                code.address = Some(s.parse().map_err(invalid)?);
            }
            return Ok(code);
        }
        let (path, query) = s[8..].split_once('?').unwrap_or((&s[8..], ""));
        if !path.is_empty() {
            code.address = Some(path.parse().map_err(invalid)?);
        }
        for pair in query.split('&').filter(|p| !p.is_empty()) {
            let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
            let key = key.to_lowercase();
            let twice = || invalid(format!("{key} twice"));
            match key.as_str() {
                "amount" if code.amount.is_some() => return Err(twice()),
                "amount" => {
                    let amount = Amount::from_str_in(value, Denomination::Bitcoin);
                    code.amount = Some(amount.map_err(invalid)?.to_sat());
                }
                "sp" if code.silent.is_some() => return Err(twice()),
                "sp" => code.silent = Some(value.parse().map_err(invalid)?),
                _ if key.starts_with("req-") => {
                    return Err(invalid(format!("it requires {key}")));
                }
                _ => {}
            }
        }
        if code.address.is_none() && code.silent.is_none() {
            return Err(invalid("nothing to pay"));
        }
        Ok(code)
    }
}

/// The keys a wallet's seed derives besides its owner's: its silent
/// payment keys, its mailbox's, and the seed of its contracts' keys.
pub(crate) struct CodeKeys {
    pub(crate) silent: licash_onchain::silent::Keys,
    pub(crate) mailbox: SecretKey,
    pub(crate) contract: [u8; 32],
    pub(crate) shaping: [u8; 32],
    /// What the secrets of the deposits asked derive from, with their hub
    /// and number ([`crate::deposits`]).
    pub(crate) deposit: [u8; 32],
    /// What the seeds of the wallet's extra codes derive from, with their
    /// number ([`crate::codes`]).
    pub(crate) codes: [u8; 32],
    /// What the wallet's keys at bridges derive from, with each bridge's
    /// Nostr key ([`crate::bridges`]).
    pub(crate) bridges: [u8; 32],
}

/// What a wallet brings to opening a recovery contract with a hub, as its
/// holder: the seed its contracts' keys derive from, of its own domain,
/// and the spending root's secret, whose notes a recovery claims. The
/// spending root's secret spends the wallet's notes: kept in memory only
/// as long as an opening or a recovery needs it, never logged or stored.
pub struct ContractSecrets {
    pub seed: [u8; 32],
    pub spend: k256::Scalar,
}

impl fmt::Debug for ContractSecrets {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ContractSecrets(..)")
    }
}

impl CodeKeys {
    pub(crate) fn from_seed(seed: &[u8; 32], network: ChainProfile) -> Result<Self, Error> {
        let silent = licash_onchain::silent::Keys::from_seed(seed, network_kind(network))
            .map_err(|e| Error::Setup(format!("silent payment keys: {e}")))?;
        let mailbox = tagged_hash("licash/mailbox", &[seed]);
        let mailbox = SecretKey::from_slice(&mailbox)
            .map_err(|_| Error::Setup("no mailbox key from this seed".into()))?;
        let contract = tagged_hash("licash/contract/seed", &[seed]);
        let shaping = tagged_hash("licash/shaping/key", &[seed]);
        let deposit = tagged_hash("licash/deposit/seed", &[seed]);
        let codes = tagged_hash("licash/codes/seed", &[seed]);
        let bridges = tagged_hash("licash/bridges/seed", &[seed]);
        Ok(Self {
            silent,
            mailbox,
            contract,
            shaping,
            deposit,
            codes,
            bridges,
        })
    }
}

impl<T: Transport> Wallet<T> {
    /// The code payers pay this wallet in notes with: at the first
    /// [`CODE_HUBS`] of `hubs`, which it trusts, preferred first, each
    /// once, reached at those URLs, and its mailbox if one of them names
    /// relays.
    pub fn payment_code(&self, hubs: &[String]) -> Result<PaymentCode, Error> {
        self.code_of(self.address(), true, hubs)
    }

    /// The code of the owner at `address` at the first [`CODE_HUBS`] of
    /// `hubs`, as [`Wallet::payment_code`] says, naming this wallet's
    /// mailbox only if `mailbox`.
    pub(crate) fn code_of(
        &self,
        address: Address,
        mailbox: bool,
        hubs: &[String],
    ) -> Result<PaymentCode, Error> {
        let trusted = self.hubs()?;
        let (mut ids, mut locations) = (Vec::new(), Vec::new());
        let mut relays = false;
        for url in hubs {
            if ids.len() == CODE_HUBS {
                break;
            }
            let url = crate::hub_url(url)?;
            let (_, info) = trusted
                .iter()
                .find(|(u, _)| *u == url)
                .ok_or_else(|| Error::UnknownHub(url.clone()))?;
            let id = HubId::of(&info.address);
            if !ids.contains(&id) {
                ids.push(id);
                locations.push((id, url));
            }
            relays |= !info.relays.is_empty();
        }
        let mailbox =
            (mailbox && relays).then(|| self.keys.mailbox.x_only_public_key(&Secp256k1::new()).0);
        Ok(PaymentCode {
            address: None,
            amount: None,
            silent: None,
            licash: Some(LicashCode {
                network: self.network,
                address,
                mailbox: mailbox.map(|key| key.serialize()),
                hubs: ids,
                locations,
            }),
        })
    }

    /// The code payers pay this wallet on Bitcoin with, for wallets that
    /// scan for it: at a fallback address for payers of no silent
    /// payments, handed out and watched from then on, the next once it is
    /// paid, and at its silent payment address if `silent`.
    pub fn onchain_code(&self, silent: bool) -> Result<PaymentCode, Error> {
        Ok(PaymentCode {
            address: Some(self.fallback_address()?.as_unchecked().clone()),
            amount: None,
            silent: silent.then(|| self.keys.silent.address()),
            licash: None,
        })
    }

    /// The code to take donations at: `kept`, a code given out before, as
    /// long as it still pays this wallet, at hubs it all trusts, so that
    /// an address handed out stays as hubs are added; else its code at
    /// `hubs`, those it trusts in its order of preference, as it shows it.
    pub fn donation_code(&self, kept: Option<&str>, hubs: &[String]) -> Result<LicashCode, Error> {
        let trusted: Vec<HubId> = (self.hubs()?.iter())
            .map(|(_, info)| HubId::of(&info.address))
            .collect();
        let mailbox = self.keys.mailbox.x_only_public_key(&Secp256k1::new()).0;
        let pays = |code: &LicashCode| {
            code.network == self.network
                && code.address == self.address()
                && code.mailbox.is_none_or(|key| key == mailbox.serialize())
                && !code.hubs.is_empty()
                && code.hubs.iter().all(|id| trusted.contains(id))
        };
        if let Some(code) = kept.and_then(|text| text.parse::<LicashCode>().ok()) {
            if pays(&code) {
                return Ok(code);
            }
        }
        if hubs.is_empty() {
            return Err(Error::Invalid("no donations without a hub".into()));
        }
        let code = self.payment_code(hubs)?.licash;
        Ok(code.expect("a Licash code"))
    }

    /// The static address of donations to `code`, this wallet's
    /// ([`Wallet::donation_code`]), through the swap provider at
    /// `provider`, if it takes them at a hub of the code: an LNURL of the
    /// provider's ([`LicashCode::lnurl`]). Refused if the provider takes
    /// no donations, or swaps at none of those hubs.
    pub async fn donation_address(
        &self,
        provider: &str,
        code: &LicashCode,
    ) -> Result<DonationAddress, Error> {
        let provider = crate::hub_url(provider)?;
        let info: licash_api::swaps::Info =
            self.get(&provider, licash_api::swaps::SWAPS_INFO).await?;
        let Some(donations) = info.donations.clone() else {
            return Err(Error::Invalid(format!("{provider} takes no donations")));
        };
        let at: Vec<&licash_api::swaps::Hub> = info
            .hubs
            .iter()
            .filter(|h| code.hubs.contains(&HubId::of(&h.address)))
            .collect();
        if at.is_empty() {
            return Err(Error::Invalid(format!(
                "{provider} swaps at none of the hubs you trust"
            )));
        }
        let stocked = at.iter().any(|h| h.max >= donations.min);
        Ok(DonationAddress {
            lnurl: code.lnurl(&donations.url),
            stocked,
            donations,
            info,
        })
    }

    /// The secret key of the wallet's mailbox, which opens what payers
    /// send it (NIP-17).
    pub fn mailbox_secret(&self) -> [u8; 32] {
        self.keys.mailbox.secret_bytes()
    }

    /// The wallet's silent payment keys, to scan for its outputs and spend
    /// them.
    pub fn silent_keys(&self) -> &licash_onchain::silent::Keys {
        &self.keys.silent
    }

    /// What the wallet brings to its recovery contracts as their holder.
    pub fn contract_secrets(&self) -> ContractSecrets {
        ContractSecrets {
            seed: self.keys.contract,
            spend: *self.owner.spend_secret(),
        }
    }

    /// The hub to pay `amount` at to the payee of `code`: the first it
    /// names that this wallet trusts and holds that much at, the hub's fee
    /// on top, if any.
    pub fn hub_to_pay(&self, code: &LicashCode, amount: u64) -> Result<Option<String>, Error> {
        if code.network != self.network {
            return Err(Error::Invalid(format!(
                "a payment code of {}, not {}",
                code.network, self.network
            )));
        }
        let trusted = self.hubs()?;
        for id in &code.hubs {
            let Some((url, _)) = trusted.iter().find(|(_, i)| HubId::of(&i.address) == *id) else {
                continue;
            };
            let (hub, info) = self.hub(url)?;
            match self.select(hub, amount, &info.fees.spending()) {
                Ok(_) => return Ok(Some(url.clone())),
                Err(Error::Insufficient { .. }) => {}
                Err(e) => return Err(e),
            }
        }
        Ok(None)
    }
}
