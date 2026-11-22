//! Unsigned claim composition and its digest E, not a recovery or counter
//! predicate.
//!
//! Public construction checks metadata consistency and the exact Q-authorization
//! union. It does not prove issuance, ownership, source-output openings,
//! source-body matching, positive activation, publication or final-D authority.

use crate::{
    chain::ActivationRef,
    crypto::{tagged_hash, Point, ScalarBytes},
    hold,
    note::{Keyset, Message},
    source::{self, Certificate},
    spend::{ProposalId, TimedTerms},
    Error,
};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

pub const MAX_ITEMS: usize = 32;
fn bad(reason: &str) -> Error {
    Error::Protocol(reason.into())
}
fn count(n: usize) -> Result<[u8; 4], Error> {
    Ok(u32::try_from(n)
        .map_err(|_| bad("claim component count overflow"))?
        .to_be_bytes())
}

/// Externally authenticated opening context. Merely naming these values does
/// not authorize them; the complete predicate must verify the actual opening.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Context {
    /// The opening's Base digest ([`crate::base::Base::digest`]).
    pub base: [u8; 32],
    pub deposit: [u8; 36],
    pub cap: u32,
}
impl std::fmt::Debug for Context {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ClaimContext(..)")
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Branch {
    Pay,
    Refund,
}
impl Branch {
    fn tag(self) -> u8 {
        match self {
            Self::Pay => 0,
            Self::Refund => 1,
        }
    }
}

/// Source inputs are public Ys, never private payer note openings. Source
/// classes are explicit, not inferred from absent persisted admission data.
#[derive(Clone)]
pub enum Source {
    Plain {
        id: ProposalId,
        inputs: Vec<Point>,
    },
    OwnInputs {
        id: ProposalId,
        inputs: Vec<Point>,
        terms: TimedTerms,
    },
    Admitted(Certificate),
}
impl std::fmt::Debug for Source {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ClaimSource(..)")
    }
}
impl Source {
    pub fn id(&self) -> ProposalId {
        match self {
            Self::Plain { id, .. } | Self::OwnInputs { id, .. } => *id,
            Self::Admitted(cert) => cert.metadata().source_id(),
        }
    }
    pub fn inputs(&self) -> &[Point] {
        match self {
            Self::Plain { inputs, .. } | Self::OwnInputs { inputs, .. } => inputs,
            Self::Admitted(cert) => cert.metadata().inputs(),
        }
    }
    pub fn terms(&self) -> Option<&TimedTerms> {
        match self {
            Self::Plain { .. } => None,
            Self::OwnInputs { terms, .. } => Some(terms),
            Self::Admitted(cert) => Some(cert.metadata().terms()),
        }
    }
    fn reference_bytes(&self) -> Result<Vec<u8>, Error> {
        source::input_root(self.inputs())?;
        let mut bytes = vec![match self {
            Self::Plain { .. } => 0,
            Self::OwnInputs { .. } => 1,
            Self::Admitted(_) => 2,
        }];
        bytes.extend(self.id().as_bytes());
        // Admitted metadata lives in the separately counted certificate root.
        if !matches!(self, Self::Admitted(_)) {
            bytes.extend(count(self.inputs().len())?);
            for input in self.inputs() {
                bytes.extend(input.0);
            }
            if let Some(terms) = self.terms() {
                bytes.extend(terms.to_bytes());
            }
        }
        Ok(bytes)
    }
    fn same_unsigned(&self, other: &Self) -> Result<bool, Error> {
        if self.reference_bytes()? != other.reference_bytes()? {
            return Ok(false);
        }
        Ok(match (self, other) {
            (Self::Admitted(a), Self::Admitted(b)) => a.metadata() == b.metadata(),
            _ => true,
        })
    }
}

/// Actual claim positions, including fallbacks, remain the mask bit positions.
#[derive(Clone)]
pub enum Item {
    Settled(Message),
    Pending {
        message: Message,
        source: ProposalId,
        branch: Branch,
        index: u32,
        blinding: ScalarBytes,
        preimage: Option<[u8; 32]>,
    },
    /// A note the holder funded the contract with herself, of a v5 Base:
    /// it opens output `index` of the outputs the Base commits to, with
    /// `blinding`. Never a settled note, though worth its face: only its
    /// spend or a second claim of it voids it.
    Funded {
        message: Message,
        index: u32,
        blinding: ScalarBytes,
    },
}
impl std::fmt::Debug for Item {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ClaimItem(..)")
    }
}
impl Item {
    pub fn message(&self) -> &Message {
        match self {
            Self::Settled(message)
            | Self::Pending { message, .. }
            | Self::Funded { message, .. } => message,
        }
    }
    fn encode(&self, bytes: &mut Vec<u8>) {
        bytes.push(match self {
            Self::Settled(_) => 0,
            Self::Pending { .. } => 1,
            Self::Funded { .. } => 2,
        });
        bytes.extend(self.message().public_fields());
        match self {
            Self::Settled(_) => {}
            Self::Pending {
                source,
                branch,
                index,
                blinding,
                preimage,
                ..
            } => {
                bytes.extend(source.as_bytes());
                bytes.push(branch.tag());
                bytes.extend(index.to_be_bytes());
                bytes.extend(blinding.0);
                bytes.push(u8::from(preimage.is_some()));
                if let Some(z) = preimage {
                    bytes.extend(z);
                }
            }
            Self::Funded {
                index, blinding, ..
            } => {
                bytes.extend(index.to_be_bytes());
                bytes.extend(blinding.0);
            }
        }
    }
}

/// Metadata only: a reference earns no activation immunity until its exact
/// inclusion/header witness is positively verified against certified terms.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ActivationRecord {
    pub source: ProposalId,
    pub reference: ActivationRef,
}

#[derive(Clone)]
pub struct Parts {
    pub items: Vec<Item>,
    pub sources: Vec<Source>,
    pub activations: Vec<ActivationRecord>,
    pub authorizations: Vec<Message>,
}

/// Exact counted public identity. Certificate signatures are verified but never
/// hashed into E; Q signatures and proof witnesses are separate as well.
#[derive(Clone)]
pub struct UnsignedClaim {
    context: Context,
    keyset: [u8; 32],
    amount: u32,
    parts: Parts,
    hold_root: [u8; 32],
    digest: [u8; 32],
}
impl std::fmt::Debug for UnsignedClaim {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("UnsignedClaim(..)")
    }
}
impl UnsignedClaim {
    pub fn new(
        context: Context,
        keyset: &Keyset,
        amount: u32,
        mut parts: Parts,
        authorization_limit: usize,
    ) -> Result<Self, Error> {
        if amount == 0
            || amount > context.cap
            || parts.items.is_empty()
            || parts.items.len() > MAX_ITEMS
        {
            return Err(bad("claim amount or item count"));
        }
        let mut sources: BTreeMap<ProposalId, Source> = BTreeMap::new();
        for source in parts.sources {
            source.reference_bytes()?;
            if let Source::Admitted(cert) = &source {
                cert.verify(keyset)?;
            }
            if let Some(previous) = sources.get(&source.id()) {
                if !previous.same_unsigned(&source)? {
                    return Err(bad("conflicting claim source metadata"));
                }
            } else {
                sources.insert(source.id(), source);
            }
        }
        let mut identifiers = BTreeSet::new();
        let mut settled = BTreeSet::new();
        for item in &parts.items {
            keyset.key(item.message().denomination())?;
            let y = item.message().identifier()?;
            if !identifiers.insert(y) {
                return Err(bad("duplicate claim item"));
            }
            if matches!(item, Item::Settled(_)) {
                settled.insert(y);
            }
        }
        let mut required = identifiers.clone();
        let mut branches = BTreeMap::new();
        let mut positions = BTreeSet::new();
        let mut funded = BTreeSet::new();
        let mut value = 0u128;
        for item in &parts.items {
            let fallback = match item {
                Item::Settled(_) => false,
                Item::Funded {
                    index, blinding, ..
                } => {
                    blinding.to_scalar()?;
                    if !funded.insert(*index) {
                        return Err(bad("duplicate claimed funded output"));
                    }
                    false
                }
                Item::Pending {
                    source,
                    branch,
                    index,
                    blinding,
                    preimage,
                    ..
                } => {
                    blinding.to_scalar()?;
                    let metadata = sources
                        .get(source)
                        .ok_or_else(|| bad("missing claim source metadata"))?;
                    if branches
                        .insert(*source, *branch)
                        .is_some_and(|old| old != *branch)
                    {
                        return Err(bad("opposite claim branches for one source"));
                    }
                    if !positions.insert((*source, *branch, *index)) {
                        return Err(bad("duplicate claimed source output"));
                    }
                    match (metadata.terms(), branch, preimage) {
                        (None, Branch::Pay, None) => {
                            if metadata.inputs().iter().any(|y| !settled.contains(y)) {
                                return Err(bad(
                                    "fallback source input missing from settled items",
                                ));
                            }
                        }
                        (Some(terms), Branch::Pay, Some(z))
                            if <[u8; 32]>::from(Sha256::digest(z)) == *terms.hash() => {}
                        (Some(_), Branch::Refund, None) => {}
                        _ => return Err(bad("claim branch/preimage metadata")),
                    }
                    if matches!(metadata, Source::OwnInputs { .. }) {
                        required.extend(metadata.inputs().iter().copied());
                    }
                    metadata.terms().is_none()
                }
            };
            if !fallback {
                value += u128::from(item.message().denomination());
            }
        }
        if u128::from(amount) > value {
            return Err(bad("claim amount exceeds nonfallback face value"));
        }
        if branches.len() != sources.len() {
            return Err(bad("unreferenced claim source"));
        }
        // Timed outputs are not additive
        // with their source inputs or a second lock of those same inputs.
        // Plain fallbacks deliberately use the opposite linking rule above.
        let mut timed_inputs = BTreeSet::new();
        for source in sources.values().filter(|source| source.terms().is_some()) {
            for input in source.inputs() {
                if identifiers.contains(input) || !timed_inputs.insert(*input) {
                    return Err(bad("overlapping timed claim value"));
                }
            }
        }
        let mut activation_bytes = count(parts.activations.len())?.to_vec();
        let mut previous = None;
        for activation in &parts.activations {
            if previous.is_some_and(|id| id >= activation.source)
                || !matches!(sources.get(&activation.source), Some(Source::Admitted(_)))
                || branches.get(&activation.source) != Some(&Branch::Pay)
            {
                return Err(bad("noncanonical or ineligible activation reference"));
            }
            previous = Some(activation.source);
            activation_bytes.extend(activation.source.as_bytes());
            activation_bytes.extend(activation.reference.to_bytes());
        }
        let hold_root = hold::authorization_root(&parts.authorizations, authorization_limit)?;
        let held: BTreeMap<_, _> = parts
            .authorizations
            .iter()
            .map(|message| Ok((message.identifier()?, message)))
            .collect::<Result<_, Error>>()?;
        if held.keys().copied().collect::<BTreeSet<_>>() != required {
            return Err(bad("claim Q-authorization set mismatch"));
        }
        for item in &parts.items {
            if held.get(&item.message().identifier()?).copied() != Some(item.message()) {
                return Err(bad("claim authorization opening mismatch"));
            }
        }
        let mut item_bytes = count(parts.items.len())?.to_vec();
        for item in &parts.items {
            item.encode(&mut item_bytes);
        }
        let mut source_bytes = count(sources.len())?.to_vec();
        let mut certificates = Vec::new();
        for source in sources.values() {
            source_bytes.extend(source.reference_bytes()?);
            if let Source::Admitted(cert) = source {
                certificates.push(cert.clone());
            }
        }
        let body_root = tagged_hash(
            "licash/claim-body/v2",
            &[
                &context.base,
                &context.deposit,
                keyset.id(),
                &amount.to_be_bytes(),
                &tagged_hash("licash/claim-items/v2", &[&item_bytes]),
                &tagged_hash("licash/claim-source-references/v2", &[&source_bytes]),
                &source::metadata_root(keyset, &certificates)?,
                &tagged_hash("licash/claim-activations/v2", &[&activation_bytes]),
            ],
        );
        let digest = tagged_hash("licash/claim/v3", &[&body_root, &hold_root]);
        parts.sources = sources.into_values().collect();
        Ok(Self {
            context,
            keyset: *keyset.id(),
            amount,
            parts,
            hold_root,
            digest,
        })
    }
    pub fn context(&self) -> &Context {
        &self.context
    }
    pub fn keyset_id(&self) -> &[u8; 32] {
        &self.keyset
    }
    pub fn amount(&self) -> u32 {
        self.amount
    }
    pub fn parts(&self) -> &Parts {
        &self.parts
    }
    pub fn digest(&self) -> &[u8; 32] {
        &self.digest
    }
    pub fn hold_root(&self) -> &[u8; 32] {
        &self.hold_root
    }
    pub fn hold_context(&self) -> hold::Context {
        hold::Context {
            base: self.context.base,
            deposit: self.context.deposit,
            amount: self.amount,
            claim_digest: self.digest,
        }
    }
}
