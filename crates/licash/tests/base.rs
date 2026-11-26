use k256::Scalar;
use licash::{
    base::{Base, ChainTerms, Close, Fees, GraphTerms, Limits, Parts, Party, Recipe},
    chain::Checkpoint,
    crypto::{self, tagged_hash, Point},
    note::IssuerKeys,
    spend::ChainProfile,
};

#[test]
fn complete_checkpoint_codec_preserves_the_existing_commitment_preimage() {
    for (profile, tag) in [
        (ChainProfile::Core30Mainnet, 0),
        (ChainProfile::Core30DefaultRegtest, 1),
    ] {
        let cp = Checkpoint::genesis(profile).unwrap();
        let time = u32::from_le_bytes(cp.header()[68..72].try_into().unwrap());
        let mut old = vec![tag];
        old.extend(0u32.to_be_bytes());
        old.extend(cp.header());
        old.extend(1u32.to_be_bytes());
        old.extend(time.to_be_bytes());
        if tag == 0 {
            old.push(1);
            old.extend(time.to_be_bytes());
        } else {
            old.push(0);
        }
        assert_eq!(
            cp.commitment(),
            tagged_hash("licash/header-checkpoint/v2", &[&old])
        );
        let mut expected = b"LICASH-CP\x02".to_vec();
        expected.extend(old);
        assert_eq!(cp.to_bytes(), expected);
        let restored = Checkpoint::from_bytes(&cp.to_bytes()).unwrap();
        assert_eq!(restored.commitment(), cp.commitment());
        assert_eq!(restored.profile(), profile);
        assert_eq!(restored.height(), 0);
        assert_eq!(restored.header(), cp.header());
    }
}

#[test]
fn the_signets_share_a_genesis_block_but_not_a_checkpoint() {
    let signet = Checkpoint::genesis(ChainProfile::Core30Signet).unwrap();
    let mutinynet = Checkpoint::genesis(ChainProfile::Mutinynet).unwrap();
    assert_eq!(signet.header(), mutinynet.header());
    assert_ne!(signet.commitment(), mutinynet.commitment());
    let at = b"LICASH-CP\x02".len();
    for (cp, tag) in [(&signet, 3), (&mutinynet, 4)] {
        let bytes = cp.to_bytes();
        assert_eq!(bytes[at], tag);
        let restored = Checkpoint::from_bytes(&bytes).unwrap();
        assert_eq!(restored.profile(), cp.profile());
        assert_eq!(restored.commitment(), cp.commitment());
        // A signet's genesis under mainnet's tag is refused.
        let mut changed = bytes.clone();
        changed[at] = 0;
        assert!(Checkpoint::from_bytes(&changed).is_err());
    }
    // Both retarget, from the genesis block's time on.
    let start = [&[1][..], &1_598_918_400u32.to_be_bytes()].concat();
    assert!(signet.to_bytes().ends_with(&start));
    assert!(mutinynet.to_bytes().ends_with(&start));
}

#[test]
fn a_chains_day_and_year_in_blocks_follow_its_block_time() {
    let days = ChainProfile::ALL.map(|p| (p, p.blocks_a_day(), p.blocks_a_year()));
    for (profile, day, year) in days {
        assert_eq!(day * profile.block_seconds(), 86_400, "{profile}");
        assert_eq!(year, day * 365, "{profile}");
    }
    // 144 a day where blocks take 10 minutes, 2 880 on Mutinynet.
    assert_eq!(ChainProfile::Core30Mainnet.blocks_a_day(), 144);
    assert_eq!(ChainProfile::Core30DefaultRegtest.blocks_a_day(), 144);
    assert_eq!(ChainProfile::Core30Signet.blocks_a_year(), 52_560);
    assert_eq!(ChainProfile::Mutinynet.blocks_a_day(), 2_880);
    assert_eq!(ChainProfile::Mutinynet.blocks_a_year(), 1_051_200);
}

#[test]
fn checkpoint_codec_has_no_missing_timestamp_or_retarget_context_fallback() {
    let bytes = Checkpoint::genesis(ChainProfile::Core30Mainnet)
        .unwrap()
        .to_bytes();
    for n in 0..bytes.len() {
        assert!(Checkpoint::from_bytes(&bytes[..n]).is_err());
    }
    let at = b"LICASH-CP\x02".len();
    for field in 0..6 {
        let mut changed = bytes.clone();
        match field {
            0 => changed.push(0),
            1 => changed[0] ^= 1,
            2 => changed[at] = 2,
            3 => changed[at + 85..at + 89].copy_from_slice(&12u32.to_be_bytes()),
            4 => changed[at + 85..at + 89].fill(0),
            _ => {
                let n = changed.len();
                changed[n - 4] ^= 1;
            }
        }
        assert!(Checkpoint::from_bytes(&changed).is_err());
    }
}

fn point(value: u64) -> Point {
    Point::from_projective(&crypto::generator_mul(&Scalar::from(value)))
}
fn party(value: u64) -> Party {
    let mut script = vec![0x51, 0x20];
    script.extend(point(value + 3).x_only());
    Party {
        funding: point(value).x_only(),
        payment: point(value + 1).x_only(),
        delayed: point(value + 2).x_only(),
        payout_script: script,
    }
}
fn parts() -> Parts {
    let mut deposit = [31; 36];
    deposit[32..].copy_from_slice(&7u32.to_le_bytes());
    Parts {
        nonce: [53; 32],
        holder_wots: [9; 32],
        funded: [7; 32],
        claim_key: point(19).x_only(),
        keyset: IssuerKeys::random(2).unwrap().keyset().unwrap(),
        deposit,
        cap: 128,
        parties: [party(23), party(29)],
        graph: GraphTerms {
            id: 7,
            unit_sats: 1,
            bits: 21,
            low_bits: 9,
            deposit_units: 100,
            close_height: 1_000,
            reserve_alice: 20_000,
            reserve_hub: 100_000,
            to_self_delay: 6,
            commit_fee: 1_000,
            presign_fee: 1_000,
            dust: 330,
            delta: 6,
            delta_prime: 6,
            deadline_margin: 8,
            request_height: 800,
            response_window: 12,
            publication_window: 3,
            contest_window: 12,
            assert_window: 12,
            challenge_window: 24,
            answer_window: 12,
        },
        recipe: Recipe {
            graph_version: 2,
            program: [11; 32],
            instances: 4,
            kept: 2,
        },
        chain: ChainTerms {
            checkpoint: Checkpoint::genesis(ChainProfile::Core30DefaultRegtest).unwrap(),
            funding_depth: 1,
            work_depth: 6,
            max_headers: 1_000,
        },
        limits: Limits {
            max_transaction_bytes: 100_000,
            max_publication_bytes: 64_000,
            max_authorizations: 128,
            max_source_inputs: 128,
        },
        fees: Fees {
            max_rate_sat_per_kvb: 10_000,
            opening_fee_quote: 3_000,
        },
        close: Close {
            script: vec![0x51, 0x20, 3, 3, 3],
            fee: 1_000,
        },
    }
}

#[test]
fn complete_base_roundtrips_with_explicit_keyset_checkpoint_and_fee_preimages() {
    let base = Base::new(parts()).unwrap();
    let bytes = base.to_bytes();
    assert!(bytes.len() < licash::base::MAX_BASE_BYTES);
    let restored = Base::from_bytes(&bytes).unwrap();
    assert_eq!(restored.to_bytes(), bytes);
    assert_eq!(restored.digest(), tagged_hash("licash/base/v6", &[&bytes]));
    assert_eq!(restored.parts().keyset.id(), base.parts().keyset.id());
    assert_eq!(
        restored.parts().chain.checkpoint.commitment(),
        base.parts().chain.checkpoint.commitment()
    );
    assert_eq!(restored.parts().fees, base.parts().fees);
    assert_eq!(restored.deposit_outpoint().index, 7);
    assert_eq!(format!("{restored:?}"), "Base(..)");
    for n in (0..128).chain(bytes.len() - 512..bytes.len()) {
        assert!(Base::from_bytes(&bytes[..n]).is_err());
    }
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert!(Base::from_bytes(&trailing).is_err());
    let mut flipped = bytes;
    flipped[0] ^= 1;
    assert!(Base::from_bytes(&flipped).is_err());
}

/// A Base carries her request keys' digest, her funded outputs' root and the
/// script the default returns her reserve to with what the Hub keeps of it
/// for the swap, after the terms, under its tag and digest domain.
#[test]
fn a_base_commits_to_her_keys_her_funded_part_and_where_the_default_pays_her_reserve() {
    let p = parts();
    let base = Base::new(p.clone()).unwrap();
    let bytes = base.to_bytes();
    assert!(bytes.starts_with(b"LICASH-BASE\x06"));
    assert_eq!(base.digest(), tagged_hash("licash/base/v6", &[&bytes]));
    let restored = Base::from_bytes(&bytes).unwrap();
    assert_eq!(restored.parts().holder_wots, [9; 32]);
    assert_eq!(restored.parts().funded, [7; 32]);
    assert_eq!(restored.parts().close, p.close);
    assert_eq!(restored.to_bytes(), bytes);
    // Each is part of the contract.
    for change in 0..4 {
        let mut other = p.clone();
        match change {
            0 => other.holder_wots[0] ^= 1,
            1 => other.funded[0] ^= 1,
            2 => other.close.script[2] ^= 1,
            _ => other.close.fee += 1,
        }
        assert_ne!(Base::new(other).unwrap().digest(), base.digest());
    }
    // Truncated or extended bytes are refused, and so is any other tag: the
    // forms of a Base before this one are no longer read.
    assert!(Base::from_bytes(&bytes[..bytes.len() - 1]).is_err());
    let mut longer = bytes.clone();
    longer.push(0);
    assert!(Base::from_bytes(&longer).is_err());
    for tag in 3..6u8 {
        let mut old = bytes.clone();
        old[11] = tag;
        assert!(Base::from_bytes(&old).is_err(), "tag {tag}");
    }
    // Her keys and funded part are bound, and she funds some.
    let mut unbound = p.clone();
    unbound.holder_wots = [0; 32];
    assert!(Base::new(unbound).is_err());
    let mut unfunded = p.clone();
    unfunded.funded = [0; 32];
    assert!(Base::new(unfunded).is_err());
    let mut none = p.clone();
    none.graph.deposit_units = 0;
    assert!(Base::new(none).is_err());
    let mut over = p.clone();
    over.graph.deposit_units = over.cap + 1;
    assert!(Base::new(over).is_err());
    // The default's script is never her payout script, and the swap's fee
    // leaves the notes worth a dust output at least.
    let mut payout = p.clone();
    payout.close.script = payout.parties[0].payout_script.clone();
    assert!(Base::new(payout).is_err());
    for fee in [20_000 - 329, 20_001, u64::MAX] {
        let mut dear = p.clone();
        dear.close.fee = fee;
        assert!(Base::new(dear).is_err(), "a fee of {fee}");
    }
    let mut cheapest = p.clone();
    cheapest.close.fee = 20_000 - 330;
    assert!(Base::new(cheapest).is_ok());
}

#[test]
fn every_agreed_base_field_changes_the_independent_key_context() {
    let original = parts();
    let digest = Base::new(original.clone()).unwrap().digest();
    for field in 0..59 {
        let mut p = original.clone();
        match field {
            0 => p.nonce[0] ^= 1,
            2 => p.claim_key = point(41).x_only(),
            3 => p.keyset = IssuerKeys::random(2).unwrap().keyset().unwrap(),
            4 => p.deposit[0] ^= 1,
            5 => p.cap -= 1,
            1 => p.graph.publication_window += 1,
            7 => p.parties[0].funding = point(43).x_only(),
            8 => p.parties[1].payment = point(47).x_only(),
            9 => p.parties[0].delayed = point(53).x_only(),
            10 => p.parties[0].payout_script[2] ^= 1,
            11 => p.graph.id += 1,
            12 => p.graph.bits += 1,
            13 => p.graph.low_bits += 1,
            14 => p.graph.deposit_units += 1,
            15 => p.graph.close_height += 1,
            16 => p.graph.reserve_alice += 1,
            17 => p.graph.reserve_hub += 1,
            18 => p.graph.to_self_delay += 1,
            19 => p.graph.commit_fee += 1,
            20 => p.graph.presign_fee += 1,
            21 => p.graph.delta += 1,
            22 => p.graph.delta_prime += 1,
            23 => p.graph.deadline_margin += 1,
            24 => p.graph.response_window += 1,
            25 => p.graph.request_height += 1,
            26 => p.graph.challenge_window += 1,
            27 => p.graph.answer_window += 1,
            28 => p.recipe.program[0] ^= 1,
            29 => p.graph.assert_window += 1,
            30 => p.recipe.instances += 1,
            31 => p.recipe.kept -= 1,
            32 => p.chain.work_depth += 1,
            34 => p.chain.funding_depth += 1,
            38 => p.chain.max_headers += 1,
            39 => p.limits.max_authorizations += 1,
            40 => p.limits.max_source_inputs += 1,
            43 => p.fees.max_rate_sat_per_kvb += 1,
            44 => p.fees.opening_fee_quote += 1,
            // fields of the old graph's terms, removed
            6 | 33 | 35..=37 | 41 | 42 | 45 => continue,
            46 => p.limits.max_transaction_bytes += 1,
            47 => p.limits.max_publication_bytes += 1,
            48 => p.chain.checkpoint = Checkpoint::genesis(ChainProfile::Core30Mainnet).unwrap(),
            49 => p.parties[1].funding = point(59).x_only(),
            50 => p.parties[0].payment = point(61).x_only(),
            51 => p.parties[1].delayed = point(67).x_only(),
            52 => p.parties[1].payout_script[2] ^= 1,
            53 => p.graph.contest_window += 1,
            55 => p.holder_wots[0] ^= 1,
            56 => p.funded[0] ^= 1,
            57 => p.close.script[2] ^= 1,
            58 => p.close.fee += 1,
            _ => p.deposit[32..].copy_from_slice(&8u32.to_le_bytes()),
        }
        let changed = Base::new(p).unwrap();
        assert_ne!(changed.digest(), digest, "field {field}");
        assert_eq!(
            Base::from_bytes(&changed.to_bytes()).unwrap().digest(),
            changed.digest()
        );
    }
}

#[test]
fn absent_or_unsupported_base_terms_are_rejected_not_defaulted() {
    for field in 0..18 {
        let mut p = parts();
        match field {
            0 => p.nonce = [0; 32],
            1 => p.graph.response_window = p.graph.publication_window + 1,
            2 => p.claim_key = [255; 32],
            3 => p.graph.unit_sats = 512,
            4 => p.graph.low_bits = 0,
            5 => p.graph.bits = 33,
            6 => p.graph.reserve_hub = 329,
            7 => p.graph.reserve_alice = u64::MAX,
            8 => p.graph.to_self_delay = 0,
            9 => p.graph.request_height = p.graph.close_height,
            10 => p.chain.work_depth = 0,
            11 => p.chain.work_depth = u32::from(p.graph.assert_window) - 1,
            12 => p.recipe.graph_version = 1,
            13 => p.recipe.kept = p.recipe.instances,
            14 => p.recipe.program = [0; 32],
            15 => p.limits.max_authorizations = 31,
            16 => p.graph.contest_window = 1,
            _ => p.fees.max_rate_sat_per_kvb = 0,
        }
        assert!(Base::new(p).is_err(), "field {field}");
    }
}

/// A Base reads, of one spend or claim, at least the notes of any spend a
/// proposal may be and a claim of every item beside her lock's refund.
#[test]
fn a_base_reads_every_spend_a_proposal_may_be() {
    let least = licash::base::MIN_AUTHORIZATIONS;
    assert!(least as usize >= licash::spend::MAX_INPUTS + licash::claim::MAX_ITEMS);
    let mut p = parts();
    p.limits.max_authorizations = least - 1;
    assert!(Base::new(p).is_err());
    let mut p = parts();
    p.limits.max_authorizations = least;
    assert!(Base::new(p).is_ok());
}

/// A work depth at the most a field holds is refused, never overflowed.
#[test]
fn a_work_depth_at_the_most_is_refused_without_overflow() {
    let mut p = parts();
    p.chain.work_depth = u32::MAX;
    assert!(Base::new(p).is_err());
}

#[test]
fn a_party_checks_the_program_it_trusts_and_the_time_left_to_request() {
    let base = Base::new(parts()).unwrap();
    // F buried, the request's delay and the margin: 1 + 6 + 8 blocks
    base.check(&[11; 32], 800 - 15).unwrap();
    assert!(base.check(&[11; 32], 800 - 14).is_err());
    assert!(base.check(&[12; 32], 0).is_err());
    // A fresh nonce is explicit local action, not a migration or a claim that
    // stale signed contexts can be silently re-keyed.
    assert_ne!(Base::fresh_nonce(), Base::fresh_nonce());
}

/// The windows after the latest request end by `close_height`: the
/// default leaf can't race a dispute.
#[test]
fn the_dispute_windows_end_by_the_close() {
    let mut p = parts();
    let g = &p.graph;
    let span = [
        g.response_window,
        g.contest_window,
        g.assert_window,
        g.challenge_window,
        g.answer_window,
    ]
    .into_iter()
    .map(u32::from)
    .sum::<u32>();
    p.graph.request_height = p.graph.close_height - span;
    Base::new(p.clone()).unwrap();
    p.graph.request_height += 1;
    assert!(Base::new(p).is_err());
}

/// The header budget counts from the checkpoint and must reach the work on
/// the Hub's response to the latest request: the statement reads the exit
/// there.
#[test]
fn header_budget_must_reach_the_work_on_the_latest_response() {
    let mut p = parts();
    let span = p.graph.request_height + u32::from(p.graph.response_window) + p.chain.work_depth
        - p.chain.checkpoint.height();
    p.chain.max_headers = span;
    Base::new(p.clone()).unwrap();
    p.chain.max_headers = span - 1;
    assert!(Base::new(p).is_err());
}

/// A cap past the binary outputs' `2^bits - 1` units is paid by a rest
/// output of the units past them, at least `2^low_bits` and below
/// `2^bits`, so the pool is the cap exactly; a cap of at most `2^bits - 1`
/// has none, and its pool is those, as before there was a rest.
#[test]
fn a_cap_past_the_graphs_bits_is_paid_by_a_rest() {
    let mut p = parts();
    assert_eq!((p.rest().unwrap(), p.pool().unwrap()), (0, (1 << 21) - 1));
    assert_eq!(p.graph_value().unwrap(), (1 << 21) - 1 + 120_000);
    p.graph.bits = 17;
    for (cap, rest) in [
        (131_071, 0),
        (131_071 + 512, 512),
        (200_000, 200_000 - 131_071),
        (262_142, 131_071),
    ] {
        p.cap = cap;
        let base = Base::new(p.clone()).unwrap();
        let restored = Base::from_bytes(&base.to_bytes()).unwrap();
        assert_eq!(restored.parts().rest().unwrap(), rest, "{cap}");
        assert_eq!(restored.parts().pool().unwrap(), cap);
        assert_eq!(
            restored.parts().graph_value().unwrap(),
            u64::from(cap) + 120_000
        );
    }
    // Her deposit may be past the binary outputs too, not past the cap.
    p.graph.deposit_units = 200_000;
    assert!(Base::new(p.clone()).is_ok());
    p.graph.deposit_units = 100;
    // A rest below 2^low_bits, or not below 2^bits.
    for cap in [131_072, 131_071 + 511, 262_143, u32::MAX] {
        p.cap = cap;
        assert!(Base::new(p.clone()).is_err(), "{cap}");
    }
    // The rest's bit is the word's 32nd at most.
    p.graph.bits = 31;
    p.cap = u32::MAX - 1;
    assert_eq!(
        Base::new(p.clone()).unwrap().parts().rest().unwrap(),
        (1 << 31) - 1
    );
    p.cap = u32::MAX;
    assert!(Base::new(p.clone()).is_err());
    p.graph.bits = 32;
    assert_eq!(Base::new(p).unwrap().parts().rest().unwrap(), 0);
}
