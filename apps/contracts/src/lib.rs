//! Recovery contracts opened over HTTP between a holder's wallet and a
//! hub: the hub's side and its routes ([`hub`]), the holder's ([`holder`]),
//! and what they send each other.
//!
//! An opening is the exchange of `licash_contract::opening`'s two machines,
//! carried as their envelopes. The holder takes the hub's [`Offer`] at
//! [`QUOTE`], opens on it at [`OPEN`], then POSTs each of her messages to
//! [`STEP`]. The hub chooses which holder-garbled instances it keeps;
//! she uploads them one by one at [`INSTANCE`]. A step of
//! the hub's that takes long (funding, checking opened instances) answers
//! 202 until done: she sends the same message again, and gets the answer.
//!
//! Once open, she may close it early with the hub, cooperatively, and be
//! paid her claim on it: the settled notes she holds at the hub, up to its
//! cap, as a forced close would claim them. She POSTs her MuSig2 nonce for
//! the fold of its output, the amount she claims and the notes it is made
//! of (a [`FoldAsk`]) at [`FOLD_CLAIM`], and gets the hub's [`FoldOffer`],
//! its answer that it would retire them (none is yet); then her partial
//! signature and her claim's filing at [`FOLD_SIGN`], and gets the fold,
//! signed and broadcast. It pays her the claim and her reserve back, the
//! hub the rest less the fee, taken from the hub's share. The hub retires
//! the notes of her claim before it signs, and only of notes nothing
//! spent: should the fold not confirm, she files that claim on Bitcoin.
//!
//! Without claim, [`FOLD`] takes her nonce alone and [`FOLD_SIGN`] her
//! partial signature alone: the fold pays her reserve back and nothing
//! more. Hubs keep it for wallets that close that way, which no longer
//! offer to.
//!
//! Openings under the mock authority (anyone "proves" anything) are for
//! regtest only, and say so; on signet they are under the genuine programs
//! kept in `r0/programs/`: [`trust`].
//!
//! The `node` feature, on by default, adds the hub's side and a node or an
//! Esplora API as the holder's chain: a wallet bringing its own chain, as
//! a phone's light client, goes without.

use anyhow::{bail, Result};
use hex_literal::hex;
use licash::spend::ChainProfile;
use licash_contract::opening::{Bounds, Quote, Trust};
use licash_contract::wire::{Reader, Writer};

pub mod holder;
#[cfg(feature = "node")]
pub mod hub;
#[cfg(test)]
mod testing;

/// GET: the hub's [`Offer`].
pub const QUOTE: &str = "/v1/contracts/quote";
/// POST an [`Opening`]: [`Frame`]s, or 202 while working on them.
pub const OPEN: &str = "/v1/contracts/open";
/// POST the holder's next message of opening `id` (hex): as [`OPEN`].
pub const STEP: &str = "/v1/contracts/openings/{id}";
/// POST a committed kept instance, as a versioned opening envelope.
pub const INSTANCE: &str = "/v1/contracts/openings/{id}/instances";
/// POST her public nonce (66 bytes) for the fold of contract `id`, paying
/// her reserve back alone, then her signature of it ([`fold_ask_digest`]):
/// the hub's [`FoldOffer`].
pub const FOLD: &str = "/v1/contracts/openings/{id}/fold";
/// POST a [`FoldAsk`] for the fold of contract `id` that pays her claim as
/// well as her reserve, then her signature of it ([`fold_ask_digest`]):
/// the hub's [`FoldOffer`], its fee and nonce.
pub const FOLD_CLAIM: &str = "/v1/contracts/openings/{id}/fold/claim";
/// POST her partial signature (32 bytes) on the fold last offered, then, of
/// a fold asked at [`FOLD_CLAIM`], the filing of her claim: the fold,
/// signed by both and broadcast, in consensus bytes.
pub const FOLD_SIGN: &str = "/v1/contracts/openings/{id}/fold/sign";
/// POST her signature (64 bytes) as the contract's claim key, over
/// [`evidence_digest`]: what the hub's response to her claim was decided on
/// (`licash::recovery::evidence_to_bytes`), for her to check before she
/// leaves the response uncontested.
pub const EVIDENCE: &str = "/v1/contracts/openings/{id}/evidence";
/// POST her signature (64 bytes) as the contract's claim key, over
/// [`proof_digest`]: π2 (64 bytes) then π3 (32) of the assertion the hub
/// signed, which its leaf does not check, so that one mined with others
/// (a relayer's or a miner's) she checks with the hub's before she
/// challenges it. She challenges as ever if the hub shows none, or none
/// that proves.
pub const PROOF: &str = "/v1/contracts/openings/{id}/proof";

/// What she signs, with her payment key in contract `id`, to be offered
/// its fold: the route asked ([`FOLD`] or [`FOLD_CLAIM`]) and the `body`
/// her 64-byte signature follows. Her nonce is fresh each time, so nobody
/// else replaces the fold offered to her, nor has the hub make one.
pub fn fold_ask_digest(id: &[u8; 32], route: &str, body: &[u8]) -> [u8; 32] {
    licash::crypto::tagged_hash(
        "licash/contracts/fold-ask/v1",
        &[id, route.as_bytes(), body],
    )
}

/// What she signs, as the contract's claim key, to be shown the evidence
/// of the hub's response `response` to contract `id`'s claim.
pub fn evidence_digest(id: &[u8; 32], response: &bitcoin::Txid) -> [u8; 32] {
    use bitcoin::hashes::Hash as _;
    licash::crypto::tagged_hash(
        "licash/contracts/evidence/v1",
        &[id, &response.to_byte_array()],
    )
}

/// What she signs, as the contract's claim key, to be shown the π2 and π3
/// of the hub's assertion `assertion` in contract `id` ([`PROOF`]).
pub fn proof_digest(id: &[u8; 32], assertion: &bitcoin::Txid) -> [u8; 32] {
    use bitcoin::hashes::Hash as _;
    licash::crypto::tagged_hash(
        "licash/contracts/proof/v1",
        &[id, &assertion.to_byte_array()],
    )
}

/// What the hub's refusal of a fold's notes starts with ([`FOLD_CLAIM`]):
/// a note it holds something against. She asks it for its evidence
/// (`licash_api::INQUIRE`), drops what it proves and asks again.
pub const NOTES_REFUSED: &str = "her notes";

/// POST (no body) once F of contract `id` (hex) is buried: her funded
/// notes issued, the hub's [`FundedIssued`]; 409 until it issues them.
pub const FUNDED: &str = "/v1/contracts/openings/{id}/funded";

/// Blocks after a contract's `close_height` at which the deposit that its
/// default pays her reserve to times out, and she may take the coins back
/// herself: some two weeks, in which she must come back for her notes.
pub const CLOSE_BLOCKS: u32 = 2_016;

/// The most bytes a request or an answer of an opening holds.
pub const MAX_BODY: usize = 64 << 20;

pub use licash_contract::reserve;

/// What a hub opens contracts on: its quote, whose checkpoint is a recent
/// block of its chain, and how far beyond it a holder may ask.
#[derive(Clone)]
pub struct Offer {
    pub quote: Quote,
    pub bounds: Bounds,
}

impl Offer {
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer(Vec::new());
        w.quote(&self.quote);
        w.u32(self.bounds.lock);
        w.u16(self.bounds.response_window);
        w.0
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut r = Reader(bytes);
        let quote = r.quote()?;
        let bounds = Bounds {
            lock: r.u32()?,
            response_window: r.u16()?,
        };
        r.end()?;
        Ok(Self { quote, bounds })
    }

    /// The rate her reserve affords a forced close of the most notes a
    /// claim files, in sat/vB ([`licash_contract::reserve`]): what is held
    /// to a floor on mainnet, and what she may weigh anywhere.
    pub fn forced_close_rate(&self) -> f64 {
        licash_contract::reserve::affordable_rate_at_most(&self.quote.graph) as f64 / 1_000.0
    }

    /// What opening on it costs the holder, in sat: her reserve and the
    /// hub's fee, from her deposit.
    pub fn price(&self) -> u64 {
        let q = &self.quote;
        q.graph
            .reserve_alice
            .saturating_add(q.fees.opening_fee_quote)
    }

    /// What she funds of the contract herself, in sat: paid in F beside
    /// the price, and issued her back as notes once F is buried.
    pub fn funded(&self) -> u64 {
        u64::from(self.quote.graph.deposit_units)
    }
}

/// The hub's half of a fold's first round: its public nonce, and the fee
/// it takes from its own share.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FoldOffer {
    pub nonce: [u8; 66],
    pub fee: u64,
}

impl FoldOffer {
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer(Vec::new());
        w.bytes(&self.nonce);
        w.u64(self.fee);
        w.0
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut r = Reader(bytes);
        let offer = Self {
            nonce: r.array()?,
            fee: r.u64()?,
        };
        r.end()?;
        Ok(offer)
    }
}

/// What a holder asks the hub of a fold that pays her claim ([`FOLD_CLAIM`]):
/// her nonce, the amount she claims, in units, and the notes it is made of,
/// each by its identifier. The hub says whether it would retire them; she
/// files them only with her signature.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FoldAsk {
    pub nonce: [u8; 66],
    pub amount: u32,
    pub notes: Vec<licash::crypto::Point>,
}

impl FoldAsk {
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer(Vec::new());
        w.bytes(&self.nonce);
        w.u32(self.amount);
        w.u16(self.notes.len() as u16);
        for note in &self.notes {
            w.bytes(&note.0);
        }
        w.0
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut r = Reader(bytes);
        let nonce = r.array()?;
        let amount = r.u32()?;
        let count = usize::from(r.u16()?);
        if count == 0 || count > licash::claim::MAX_ITEMS {
            bail!("a claim of {count} notes");
        }
        let notes = (0..count)
            .map(|_| Ok(licash::crypto::Point(r.array()?)))
            .collect::<Result<Vec<_>>>()?;
        r.end()?;
        Ok(Self {
            nonce,
            amount,
            notes,
        })
    }
}

/// The hub's own lock, settled, that issued the notes she funded a
/// contract with, and the preimage she claims them with.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FundedIssued {
    pub lock: [u8; 32],
    pub preimage: [u8; 32],
}

impl FundedIssued {
    pub fn encode(&self) -> Vec<u8> {
        [self.lock, self.preimage].concat()
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut r = Reader(bytes);
        let issued = Self {
            lock: r.array()?,
            preimage: r.array()?,
        };
        r.end()?;
        Ok(issued)
    }
}

/// The fold of the contract output of `babe`, funded by `funding`: its
/// cooperative close, paying the holder `b` of her claim and her reserve
/// back, the hub the rest less `fee`.
pub(crate) fn fold(
    babe: &licash_contract::graph::HubProves,
    funding: &bitcoin::Transaction,
    b: bitcoin::Amount,
    fee: bitcoin::Amount,
) -> Result<lichen_contract::Fold> {
    let contract = bitcoin::OutPoint {
        txid: funding.compute_txid(),
        vout: 0,
    };
    babe.core().fold(&babe.tree()?, contract, b, fee)
}

/// What a holder POSTs to open: the quote she opens on, and her Open.
pub struct Opening {
    pub quote: Quote,
    pub open: Vec<u8>,
}

impl Opening {
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer(Vec::new());
        w.quote(&self.quote);
        w.blob(&self.open);
        w.0
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut r = Reader(bytes);
        let quote = r.quote()?;
        let open = r.blob()?.to_vec();
        r.end()?;
        Ok(Self { quote, open })
    }
}

/// What a hub answers a message with, in order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Frame {
    /// One of its messages.
    Message(Vec<u8>),
}

impl Frame {
    pub fn encode_all(frames: &[Frame]) -> Vec<u8> {
        let mut w = Writer(Vec::new());
        w.count(frames.len());
        for frame in frames {
            match frame {
                Frame::Message(bytes) => {
                    w.u8(0);
                    w.blob(bytes);
                }
            }
        }
        w.0
    }

    pub fn decode_all(bytes: &[u8]) -> Result<Vec<Frame>> {
        let mut r = Reader(bytes);
        let n = r.count(1)?;
        let mut frames = Vec::with_capacity(n.min(64));
        for _ in 0..n {
            frames.push(match r.u8()? {
                0 => Frame::Message(r.blob()?.to_vec()),
                tag => bail!("a frame of tag {tag}"),
            });
        }
        r.end()?;
        Ok(frames)
    }
}

/// Who a party of an opening on `profile` trusts for proofs: the mock
/// authority on regtest, labeled as such; on signet and Mutinynet the
/// genuine programs [`SIGNET`], under RISC Zero's shared Groth16 setup.
/// None elsewhere yet.
///
/// The signets' are a trial: their headers are checked by their work alone,
/// not by the network's signature of each block, so headers that fool the
/// programs cost little to make. One program serves both: it reads the
/// profile of the checkpoint it is given (Mutinynet's retargets every
/// 40 320 blocks), which its proof binds, so that a proof for one network
/// is none for the other.
pub fn trust(profile: ChainProfile) -> Result<Trust> {
    match profile {
        ChainProfile::Core30DefaultRegtest => Ok(Trust::mock()),
        ChainProfile::Core30Signet | ChainProfile::Mutinynet => Ok(Trust {
            program: SIGNET,
            mock: false,
            compact: SIGNET_COMPACT,
            lean: SIGNET_LEAN,
            chained: SIGNET_CHAINED.then_some(CHAIN),
            own_claims: SIGNET_OWN_CLAIMS,
        }),
        _ => bail!("contracts are not opened on {profile} yet"),
    }
}

/// The genuine program contracts open under on signet and Mutinynet, as built by
/// `r0/build-guest.sh` with the toolchains it pins, from the commit
/// `docs/r0.md` names. Each program contracts opened under is kept as
/// `r0/programs/<image id>.bin`: the contracts opened under one are
/// proven with it alone, so none named here or in [`SIGNET_BEFORE`] is
/// to go while this build reads their Bases. A contract keeps its program
/// when this one changes. Its notes are of the note format v5, and its
/// hub cites spends by their owners' signatures (graph id
/// [`licash::recovery::SIGNED_FROM`]).
pub const SIGNET: [u8; 32] =
    hex!("1808247519df8436457abfb21a7a5173e0b9948db0b75ee3dce0e93bc9443658");

/// Whether [`SIGNET`] decides the compact filing: true only for a program
/// built from a tree whose `licash::recovery` reads it, and set in the
/// same change as [`SIGNET`]. Hubs quote a graph of the compact filing's
/// id only when it is ([`Trust::compact`]), and holders refuse one that
/// is quoted otherwise.
pub const SIGNET_COMPACT: bool = true;

/// Whether [`SIGNET`] decides the lean filing, as [`SIGNET_COMPACT`] says of
/// the compact one: set in the same change as the program that does. Hubs
/// quote a graph of id [`licash::recovery::LEAN_FROM`] only when it is.
pub const SIGNET_LEAN: bool = true;

/// Whether [`SIGNET`] reads a contract's exit on the hub's header chain, as
/// [`SIGNET_LEAN`] says of the lean filing: set in the same change as the
/// program that does, which verifies receipts of [`CHAIN`] alone. Hubs quote a
/// graph of id [`licash::recovery::CHAINED_FROM`] only when it is.
pub const SIGNET_CHAINED: bool = true;

/// Whether [`SIGNET`] leaves a claim of the same contract no evidence
/// against another ([`licash::recovery::own_claims_void`]), as
/// [`SIGNET_CHAINED`] says of the chain: set in the same change as the
/// program that does, rebuilt from a tree whose `licash::recovery` has the
/// rule, and the old program moved to [`SIGNET_BEFORE`]. Hubs quote a graph
/// of id [`licash::recovery::OWN_CLAIMS_FROM`] only when it is. It reads the
/// chain program [`CHAIN`], kept as it was: that program's sources did not
/// change, only the bytes it builds to, and a hub keeps one chain.
pub const SIGNET_OWN_CLAIMS: bool = true;

/// The chain program (`r0/chain-guest`) whose receipts [`SIGNET`]'s statement
/// verifies: the image id kept in `r0/hp-guest/chain.id`, which a build of it
/// must give (`r0/build-guest.sh chain`). The hub proves the header chain with
/// it, and keeps the program in `r0/programs/` as it keeps the statements.
pub const CHAIN: [u8; 32] =
    hex!("67ace32269c9edb8882aefa75f81b974b506d74a1b11bcff1879197a4c61e77e");

/// The programs signet's (and Mutinynet's) contracts opened under before [`SIGNET`], newest
/// first: no contract opens under them, and those that did are played still
/// if of a Base this build reads. None since the note format v3: every
/// earlier Base embeds a keyset of the format before, which this build does
/// not read, so the programs of those contracts (`493d2f79…` and the nine
/// before it, kept in `r0/programs/` up to commit 5904ef57) are played by
/// the release before alone, whose hubs and wallets serve them to their end.
pub const SIGNET_BEFORE: [[u8; 32]; 0] = [];

/// The programs contracts on `profile` opened under before the one they
/// open under now ([`trust`]): played still, of a Base this build reads.
pub fn programs_before(profile: ChainProfile) -> &'static [[u8; 32]] {
    match profile {
        ChainProfile::Core30Signet | ChainProfile::Mutinynet => &SIGNET_BEFORE,
        _ => &[],
    }
}

/// Whether a contract on `profile` opened under `program` is played,
/// recovered from and proved: any under the mock authority, else one
/// under the program contracts open under now or one they did before.
pub fn plays(profile: ChainProfile, program: &[u8; 32]) -> bool {
    trust(profile).is_ok_and(|t| {
        t.mock || t.program == *program || programs_before(profile).contains(program)
    })
}

/// The hub's database in its data directory `data`: where the hub's
/// ledger and the tables of its modules are.
pub fn hub_db(data: &std::path::Path) -> std::path::PathBuf {
    data.join("hub.sqlite")
}

/// Seconds since 1970.
pub(crate) fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64)
}

/// `id` in hex, as paths name an opening.
pub fn hex_id(id: &[u8; 32]) -> String {
    hex::encode(id)
}

/// The opening `hex` names.
pub fn parse_id(hex: &str) -> Result<[u8; 32]> {
    let mut id = [0; 32];
    hex::decode_to_slice(hex, &mut id)?;
    Ok(id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_fold_offer_reads_as_written_and_nothing_else() {
        let offer = FoldOffer {
            nonce: [3; 66],
            fee: 1_234,
        };
        let bytes = offer.encode();
        assert_eq!(bytes.len(), 74);
        assert_eq!(FoldOffer::decode(&bytes).unwrap(), offer);
        assert!(FoldOffer::decode(&bytes[..73]).is_err());
        assert!(FoldOffer::decode(&[bytes.as_slice(), &[0]].concat()).is_err());
    }

    #[test]
    fn a_fold_ask_reads_as_written_and_nothing_else() {
        let ask = FoldAsk {
            nonce: [3; 66],
            amount: 12,
            notes: vec![
                licash::crypto::Point([4; 33]),
                licash::crypto::Point([5; 33]),
            ],
        };
        let bytes = ask.encode();
        assert_eq!(bytes.len(), 66 + 4 + 2 + 2 * 33);
        assert_eq!(FoldAsk::decode(&bytes).unwrap(), ask);
        assert!(FoldAsk::decode(&bytes[..bytes.len() - 1]).is_err());
        assert!(FoldAsk::decode(&[bytes.as_slice(), &[0]].concat()).is_err());
        // Of no notes, or more than a claim holds.
        let none = FoldAsk {
            notes: vec![],
            ..ask.clone()
        };
        assert!(FoldAsk::decode(&none.encode()).is_err());
        let many = FoldAsk {
            notes: vec![licash::crypto::Point([4; 33]); licash::claim::MAX_ITEMS + 1],
            ..ask
        };
        assert!(FoldAsk::decode(&many.encode()).is_err());
    }

    #[test]
    fn a_funded_issuance_reads_as_written_and_nothing_else() {
        let issued = FundedIssued {
            lock: [4; 32],
            preimage: [5; 32],
        };
        let bytes = issued.encode();
        assert_eq!(bytes.len(), 64);
        assert_eq!(FundedIssued::decode(&bytes).unwrap(), issued);
        assert!(FundedIssued::decode(&bytes[..63]).is_err());
        assert!(FundedIssued::decode(&[bytes.as_slice(), &[0]].concat()).is_err());
    }

    #[test]
    fn the_hub_statement_image_is_pinned() {
        assert_eq!(
            SIGNET,
            hex!("1808247519df8436457abfb21a7a5173e0b9948db0b75ee3dce0e93bc9443658"),
            "keep every funded contract's pinned guest available when changing opening trust"
        );
        // Emptied at the note format v3, v4 and v5, whose builds read no earlier Base:
        // otherwise a program contracts opened under is never to go.
        assert_eq!(SIGNET_BEFORE, [[0; 32]; 0]);
    }

    #[test]
    fn frames_read_back_as_written() {
        let frames = vec![
            Frame::Message(vec![1, 2, 3]),
            Frame::Message(vec![4, 5]),
            Frame::Message(Vec::new()),
        ];
        let bytes = Frame::encode_all(&frames);
        assert_eq!(Frame::decode_all(&bytes).unwrap(), frames);
        assert!(Frame::decode_all(&bytes[..bytes.len() - 1]).is_err());
        let mut tagged = bytes.clone();
        // The second frame's tag.
        let at = 4 + 1 + 4 + 3;
        tagged[at] = 7;
        assert!(Frame::decode_all(&tagged).is_err());
    }

    #[test]
    fn mock_proofs_are_for_regtest_only() {
        assert!(trust(ChainProfile::Core30DefaultRegtest).unwrap().mock);
        // The signets' are genuine, and one program's; none elsewhere yet.
        for profile in [ChainProfile::Core30Signet, ChainProfile::Mutinynet] {
            let trusted = trust(profile).unwrap();
            assert!(!trusted.mock);
            assert_eq!(trusted.program, SIGNET);
            assert_eq!(
                (trusted.compact, trusted.lean),
                (SIGNET_COMPACT, SIGNET_LEAN)
            );
            assert_eq!(trusted.chained, SIGNET_CHAINED.then_some(CHAIN));
        }
        assert!(trust(ChainProfile::Core30Mainnet).is_err());
        assert_eq!(
            trust(ChainProfile::Core30DefaultRegtest).unwrap().chained,
            None
        );
    }

    /// The statement verifies receipts of the chain program by the id kept
    /// in its guest's directory, compiled in: the hub proves the chain with
    /// the program of that id alone, kept as the statements are.
    #[test]
    fn the_chain_program_is_the_one_the_statements_are_built_with() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../r0");
        let kept = std::fs::read_to_string(root.join("hp-guest/chain.id")).unwrap();
        assert_eq!(kept.trim().len(), 64, "an image id");
        if SIGNET_CHAINED {
            assert_eq!(hex::encode(CHAIN), kept.trim());
            let program = root.join(format!("programs/{}.bin", kept.trim()));
            assert!(std::fs::metadata(&program).is_ok_and(|m| m.len() > 0));
        }
    }

    #[test]
    fn the_programs_contracts_open_under_are_kept_by_image_id() {
        let kept = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../r0/programs");
        for id in std::iter::once(&SIGNET).chain(&SIGNET_BEFORE) {
            let program = kept.join(format!("{}.bin", hex::encode(id)));
            let size = std::fs::metadata(&program).map_or(0, |m| m.len());
            assert!(size > 0, "{} is not kept", program.display());
        }
    }

    #[test]
    fn contracts_of_the_programs_before_are_played_but_none_opens_under_them() {
        for signet in [ChainProfile::Core30Signet, ChainProfile::Mutinynet] {
            assert!(plays(signet, &SIGNET));
            for before in SIGNET_BEFORE {
                assert!(plays(signet, &before) && before != SIGNET);
            }
            assert!(!plays(signet, &[9; 32]));
        }
        assert!(plays(ChainProfile::Core30DefaultRegtest, &[9; 32]));
        assert!(!plays(ChainProfile::Core30Mainnet, &SIGNET));
    }

    #[test]
    fn signet_proofs_answer_risc_zeros_key_for_the_hub_statement() {
        use lichen_babe::statement::Kind;
        let journal = [5; 68];
        let trusted = trust(ChainProfile::Core30Signet).unwrap();
        let statement = Kind::Risc0(trusted.program);
        let pinned = Kind::Risc0(SIGNET);
        assert_eq!(
            statement.public_inputs(&journal),
            pinned.public_inputs(&journal)
        );
        assert_eq!(statement.verifying_key(), pinned.verifying_key());
        assert_ne!(statement.verifying_key(), Kind::Mock.verifying_key());
        let another = Kind::Risc0([9; 32]);
        assert_ne!(
            statement.public_inputs(&journal),
            another.public_inputs(&journal)
        );
    }
}
