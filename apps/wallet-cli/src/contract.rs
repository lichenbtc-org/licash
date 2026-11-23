//! `licash-wallet open-contract` and `contracts`: recovery contracts at
//! the wallet's hubs, kept beside its file, each paid from a coin of the
//! wallet's on Bitcoin. `approve-fees`: more than a hub charged as they
//! opened, agreed to. `force-close`, `recoveries` and
//! `give-up-recovery`, `allow-publication-fee`: one its hub left silent, closed by the wallet.
//! `recovery-statement` and `import-proof`: one its hub answered, proved
//! on another machine.

use std::path::Path;

use anyhow::Context;
use licash_contracts::holder::activation;
use licash_contracts::holder::recovery::{self, Recovery};
use licash_contracts::holder::{self, Ask, Contract, Node};
use licash_transport::Http;
use licash_wallet::{Blocks as _, Wallet};
use serde_json::json;

use crate::payout::Provider;
use crate::show;

fn node(chain: Option<&str>) -> anyhow::Result<Node> {
    let chain = chain.context(
        "--chain: Bitcoin Core as http://user:password@127.0.0.1:8332, \
         or Esplora as esplora+https://esplora.example/api",
    )?;
    Ok(Node(chain.parse().context("--chain")?))
}

/// Hold each hub to the fees the wallet's contracts there opened under,
/// or its owner approved since. A wallet whose contracts cannot be read
/// holds no hub to any, as one with none.
pub fn agree(wallet: &Wallet<Http>, path: &Path) {
    if let Err(e) = holder::fees::agree(wallet, path, None) {
        tracing::warn!("what the contracts' hubs may charge: {e:#}");
    }
}

/// What `hub` charges now beside what the wallet agreed to there, asked
/// again; with `yes`, agreed to as the wallet last heard it, without
/// asking: what was shown.
pub async fn approve_fees(
    wallet: &Wallet<Http>,
    path: &Path,
    hub: &str,
    yes: bool,
    json: bool,
) -> anyhow::Result<()> {
    let hub = hub.trim_end_matches('/');
    let agreed = wallet.fee_ceilings(hub)?;
    let charged = match yes {
        true => {
            let hubs = wallet.hubs()?;
            let known = hubs.iter().find(|(url, _)| url == hub);
            let (_, info) = known.with_context(|| format!("{hub} is no hub this wallet trusts"))?;
            info.fees
        }
        false => wallet.add_hub(hub).await?.fees,
    };
    let raised = agreed.is_some_and(|agreed| charged.above(&agreed));
    if yes && raised {
        holder::fees::approve(wallet, path, hub, &charged, None)?;
    }
    let now = wallet.fee_ceilings(hub)?;
    let said = |fees: &licash_api::Fees| crate::say::fees(fees);
    let line = match (agreed, raised, yes) {
        (None, ..) => format!(
            "nothing to approve: no contract holds {hub} to its fees\ncharges  {}",
            said(&charged)
        ),
        (Some(agreed), false, _) => format!(
            "nothing to approve: {hub} charges no more than agreed\ncharges  {}\nagreed   {}",
            said(&charged),
            said(&agreed)
        ),
        (Some(agreed), true, false) => format!(
            "{hub} charges more than agreed: `approve-fees {hub} --yes` agrees to it\ncharges  {}\nagreed   {}",
            said(&charged),
            said(&agreed)
        ),
        (Some(agreed), true, true) => format!(
            "approved\ncharges  {}\nagreed   {}\nbefore   {}",
            said(&charged),
            now.as_ref().map_or_else(|| "nothing".into(), said),
            said(&agreed)
        ),
    };
    show(
        json,
        json!({
            "hub": hub, "charged": charged, "agreed_before": agreed, "agreed": now,
            "raised": raised, "approved": yes && raised,
        }),
        line,
    );
    Ok(())
}

/// What `open-contract` asks of a hub, as given.
pub struct Asked {
    pub blocks: Option<u32>,
    pub max_price: Option<u64>,
    pub cap: Option<u32>,
    pub coin: Option<bitcoin::OutPoint>,
    /// At a hub charging more than is sane too.
    pub any_fees: bool,
}

/// Open a contract at `hub` closing `blocks` from now [default: as late
/// as the hub allows], paying at most `max_price` [default: no ceiling
/// beyond sane fees], protecting at least `cap` sat if chosen [default: the
/// smallest contract that takes the coin whole], paid from `coin` [default:
/// the smallest free that a contract takes whole]. Her coin is spent whole:
/// what the reserve and the hub's fee leave of it is her part of the
/// contract, issued back to her as notes.
pub async fn open(
    wallet: &Wallet<Http>,
    path: &Path,
    chain: Option<&str>,
    hub: &str,
    asked: Asked,
    json: bool,
) -> anyhow::Result<()> {
    let chain = node(chain)?;
    let hub = hub.trim_end_matches('/');
    let hubs = wallet.hubs()?;
    let (_, info) = hubs
        .iter()
        .find(|(url, _)| url == hub)
        .with_context(|| format!("{hub} is no hub this wallet trusts: add-hub first"))?;
    let offered = info
        .contracts
        .with_context(|| format!("{hub} opens no contracts"))?;
    let blocks = asked.blocks.unwrap_or(offered.blocks);
    let ask = Ask {
        blocks,
        max_price: asked.max_price.unwrap_or(u64::MAX),
        cap: asked.cap,
        deposit: asked.coin,
    };
    let contract = match asked.any_fees {
        true => holder::open_anyway(wallet, &chain, path, hub, ask).await,
        false => holder::open_with(wallet, &chain, path, hub, ask).await,
    }?;
    // Its terms as they came of her coin: the cap and her part.
    let chosen = offered.range.map(|_| contract.cap);
    let funded = u32::try_from(contract.funded).unwrap_or(u32::MAX);
    let terms = Terms::of(hub, &offered, chosen, Some(blocks), funded)?;
    let mut value = contract_json(&contract);
    value["terms"] = terms.json();
    let day = wallet.network().blocks_a_day();
    let line = format!("{}\n{}", terms.lines(day), contract_line(&contract));
    show(json, value, line);
    Ok(())
}

/// Pay for a contract at `hub` as `asked`, its deposit a coin paid to the
/// wallet for notes at the hub `from` through `provider` (at its URL, or
/// announced on relays) ([`holder::paid`]), the claim's, provider's and
/// lock fees `max_fee` at most [default: 1% of the coin and 2000], the
/// claim budgeted at `fee_rate`. Opened once the coin is the wallet's, as
/// [`list`] with a chain carries it on: at once if it already is.
pub async fn open_paid(
    wallet: &Wallet<Http>,
    path: &Path,
    chain: Option<&str>,
    hub: &str,
    asked: Asked,
    (provider, from, max_fee, fee_rate): (Provider, String, Option<u64>, Option<u64>),
    json: bool,
) -> anyhow::Result<()> {
    let node = node(chain)?;
    let hub = hub.trim_end_matches('/');
    let hubs = wallet.hubs()?;
    let (_, info) = hubs
        .iter()
        .find(|(url, _)| url == hub)
        .with_context(|| format!("{hub} is no hub this wallet trusts: add-hub first"))?;
    let offered = info
        .contracts
        .with_context(|| format!("{hub} opens no contracts"))?;
    let ask = Ask {
        blocks: asked.blocks.unwrap_or(offered.blocks),
        max_price: asked.max_price.unwrap_or(u64::MAX),
        cap: asked.cap,
        deposit: None,
    };
    let coin = holder::paid::coin(wallet, hub, ask).await?;
    let source = crate::payout::source(chain.unwrap_or_default())?;
    let rate = crate::onchain::rate(&source, fee_rate).await?;
    let max_fee = max_fee.unwrap_or(coin.value / 100 + crate::payout::USUAL_MAX_FEE);
    let pair = (from.as_str(), coin.to.as_str());
    let quote = crate::payout::quote(wallet, provider, pair, coin.value, (max_fee, rate), json);
    let quote = quote.await?;
    let paid = holder::paid::pay(wallet, path, &coin, &quote).await?;
    // Its coin perhaps confirmed already: opened if so.
    let contracts = holder::resume(wallet, &node, path).await?;
    let payouts = wallet.payouts()?;
    let claim = payouts
        .iter()
        .find(|p| p.hash == paid.ticket)
        .and_then(|p| p.claim);
    let opened = claim.and_then(|claim| contracts.iter().find(|c| c.deposit.txid == claim));
    let coin = opened.map(|c| c.deposit);
    let value = json!({
        "ticket": paid.ticket,
        "hub": hub,
        "provider": quote.provider,
        "from": quote.from,
        "value": paid.value,
        "price": paid.price,
        "cap": paid.fit.cap,
        "funded": paid.fit.funded,
        "coin": coin.map(|c| c.to_string()),
        "contract": opened.map(contract_json),
    });
    let line = match opened {
        Some(contract) => contract_line(contract),
        None => format!(
            "paying for a coin of {} sat (the price {} and {} yours) to open a contract of {} sat \
             at {hub}: it opens once the coin is the wallet's, as `contracts --chain` carries it on",
            paid.value, paid.price, paid.fit.funded, paid.fit.cap,
        ),
    };
    show(json, value, line);
    Ok(())
}

/// What a contract at `hub` costs, itemized, before it is opened: `cap`
/// sat over `blocks` [default: the hub's fixed terms], `funded` of it hers,
/// and the sizes it lets holders choose.
pub fn terms(
    wallet: &Wallet<Http>,
    hub: &str,
    chosen: (Option<u32>, Option<u32>),
    funded: u32,
    json: bool,
) -> anyhow::Result<()> {
    let hub = hub.trim_end_matches('/');
    let hubs = wallet.hubs()?;
    let (_, info) = hubs
        .iter()
        .find(|(url, _)| url == hub)
        .with_context(|| format!("{hub} is no hub this wallet trusts: add-hub first"))?;
    let offered = info
        .contracts
        .with_context(|| format!("{hub} opens no contracts"))?;
    let (cap, blocks) = chosen;
    let terms = Terms::of(hub, &offered, cap, blocks, funded)?;
    let mut value = terms.json();
    let mut lines = terms.lines(wallet.network().blocks_a_day());
    if let Some(range) = offered.range {
        let sizes = range.sizes();
        value["sizes"] = json!(sizes);
        value["min_blocks"] = json!(range.min_blocks);
        value["max_blocks"] = json!(range.max_blocks);
        value["per_coin"] = json!(range.per_coin);
        let sizes: Vec<_> = sizes
            .iter()
            .map(|&s| crate::say::grouped(s.into()))
            .collect();
        // A bound by the coin paying, of hubs before none was: none said of those since.
        let per_coin = match range.per_coin {
            u32::MAX => String::new(),
            times => format!(", at most {times} times the coin paying it"),
        };
        lines.push_str(&format!(
            "\nsizes        {} sat{per_coin}\nblocks       {} to {}",
            sizes.join(", "),
            crate::say::grouped(range.min_blocks.into()),
            crate::say::grouped(range.max_blocks.into()),
        ));
    }
    show(json, value, lines);
    Ok(())
}

/// A contract's terms and what opening it costs, itemized: the hub's
/// opening fee, its interest by the year on the part it funds and on
/// hers, her reserve (returned as it closes) and her part (issued back to
/// her as notes). Of a hub offering fixed terms only, its fee in one.
struct Terms {
    cap: u32,
    blocks: u32,
    funded: u32,
    reserve: u64,
    price: u64,
    /// The fee itemized, of a hub that lets holders choose.
    fee: Option<(licash_api::ContractRange, licash_api::ContractFee)>,
}

/// Refused unless `funded` sat of a contract of `cap` sat are within it.
fn funds_at_most(funded: u32, cap: u32) -> anyhow::Result<()> {
    anyhow::ensure!(
        funded <= cap,
        "{} sat funded is more than the contract's {}",
        crate::say::grouped(funded.into()),
        crate::say::sat(cap.into())
    );
    Ok(())
}

impl Terms {
    fn of(
        hub: &str,
        offered: &licash_api::Contracts,
        cap: Option<u32>,
        blocks: Option<u32>,
        funded: u32,
    ) -> anyhow::Result<Self> {
        // Its fixed terms are priced over its blocks, whatever the close
        // she wants.
        let blocks = match cap {
            Some(_) => blocks.unwrap_or(offered.blocks),
            None => offered.blocks,
        };
        let Some(range) = offered.range else {
            anyhow::ensure!(
                cap.is_none(),
                "{hub} offers no contracts but of {} sat",
                crate::say::grouped(offered.cap.into()),
            );
            funds_at_most(funded, offered.cap)?;
            return Ok(Self {
                cap: offered.cap,
                blocks,
                funded,
                reserve: offered.reserve,
                price: offered.price,
                fee: None,
            });
        };
        let cap = cap.unwrap_or(offered.cap);
        let sizes = range.sizes();
        anyhow::ensure!(
            sizes.contains(&cap),
            "{hub} offers no contracts of {} sat: choose one of {} sat",
            crate::say::grouped(cap.into()),
            (sizes.iter().map(|&s| crate::say::grouped(s.into())))
                .collect::<Vec<_>>()
                .join(", ")
        );
        funds_at_most(funded, cap)?;
        Ok(Self {
            cap,
            blocks,
            funded,
            reserve: range.reserve,
            price: range.price(cap, blocks, funded),
            fee: Some((range, range.fee(cap, blocks, funded))),
        })
    }

    fn json(&self) -> serde_json::Value {
        let mut value = json!({
            "cap": self.cap,
            "blocks": self.blocks,
            "funded": self.funded,
            "reserve": self.reserve,
            "fee": self.price - self.reserve,
            "price": self.price,
            "pays": self.price + u64::from(self.funded),
        });
        if let Some((range, fee)) = self.fee {
            value["opening_fee"] = json!(fee.opening);
            value["ppm_year"] = json!(range.ppm_year);
            value["interest"] = json!(fee.interest);
            value["ppm_year_funded"] = json!(range.ppm_year_funded);
            value["interest_funded"] = json!(fee.interest_funded);
        }
        value
    }

    /// The terms in words, a day being `blocks_a_day` blocks of the
    /// wallet's network ([`licash::spend::ChainProfile::blocks_a_day`]).
    fn lines(&self, blocks_a_day: u32) -> String {
        use crate::say::{grouped, percent, sat};
        let hubs = self.cap - self.funded;
        let mut lines = vec![
            format!(
                "covers       {}{}",
                sat(self.cap.into()),
                match self.funded {
                    0 => String::new(),
                    f => format!(
                        ", {} funded by the hub, {} by you",
                        grouped(hubs.into()),
                        grouped(f.into())
                    ),
                }
            ),
            format!(
                "over         {} blocks (about {} days)",
                grouped(self.blocks.into()),
                grouped(u64::from(self.blocks).div_ceil(blocks_a_day.max(1).into()))
            ),
        ];
        let fee = self.price - self.reserve;
        match self.fee {
            Some((range, f)) => {
                lines.push(format!("opening fee  {}", sat(f.opening)));
                lines.push(format!(
                    "interest     {}, {} a year on the hub's {}",
                    sat(f.interest),
                    percent(range.ppm_year.into()),
                    grouped(hubs.into())
                ));
                if self.funded > 0 {
                    lines.push(format!(
                        "interest     {}, {} a year on your {}",
                        sat(f.interest_funded),
                        percent(range.ppm_year_funded.into()),
                        grouped(self.funded.into())
                    ));
                }
            }
            None => lines.push(format!("hub's fee    {}", sat(fee))),
        }
        lines.push(format!(
            "reserve      {}, returned as it closes",
            sat(self.reserve)
        ));
        lines.push(format!(
            "price        {}: fee {}{}",
            sat(self.price),
            sat(fee),
            crate::say::share(fee, self.cap.into())
                .map(|s| format!(" ({s} of what it covers)"))
                .unwrap_or_default()
        ));
        if self.funded > 0 {
            lines.push(format!(
                "your part    {}, issued back to you as notes once its funding is buried",
                sat(self.funded.into())
            ));
            lines.push(format!(
                "paid         {} from your coin, and the transaction's fee",
                sat(self.price + u64::from(self.funded))
            ));
        }
        lines.join("\n")
    }
}

/// The wallet's contracts, those under way carried on and their F watched.
pub async fn list(
    wallet: &Wallet<Http>,
    path: &Path,
    chain: Option<&str>,
    json: bool,
) -> anyhow::Result<()> {
    let (contracts, claims) = match chain {
        Some(_) => {
            let node = node(chain)?;
            let contracts = holder::resume(wallet, &node, path).await?;
            let tip = node.height().await.map_err(|e| anyhow::anyhow!(e))?;
            let each = holder::coverage(wallet, path, &contracts, tip)?;
            let claims = |c: &Contract| c.live(tip).then(|| each.get(&c.id).copied().unwrap_or(0));
            let claims: Vec<_> = contracts.iter().map(claims).collect();
            (contracts, claims)
        }
        None => {
            let contracts = holder::list(path)?;
            let none = vec![None; contracts.len()];
            (contracts, none)
        }
    };
    let lines: Vec<String> = (contracts.iter().zip(&claims))
        .map(|(c, claims)| match claims {
            Some(sat) => format!("{}  claims {} now", contract_line(c), crate::say::sat(*sat)),
            None => contract_line(c),
        })
        .collect();
    let values: serde_json::Value = (contracts.iter().zip(&claims))
        .map(|(c, claims)| {
            let mut value = contract_json(c);
            value["claims"] = json!(claims);
            value
        })
        .collect();
    show(json, values, lines.join("\n"));
    Ok(())
}

/// The hubs the wallet's codes name, preferred first
/// ([`holder::code_hubs`]): its contracts judged live at the highest tip
/// its hubs last said.
pub fn code_hubs(wallet: &Wallet<Http>, path: &Path) -> anyhow::Result<Vec<String>> {
    let hubs = wallet.hubs()?;
    let tips = hubs.iter().filter_map(|(_, info)| info.locks.as_ref());
    let tip = tips.map(|l| l.height).max().unwrap_or(0);
    holder::code_hubs(wallet, path, tip)
}

/// What is not protected at a hub: `held` there, of which its live
/// contracts cover `covered`.
pub struct Unprotected {
    pub hub: String,
    pub held: u64,
    pub covered: u64,
}

impl Unprotected {
    pub fn missing(&self) -> u64 {
        self.held.saturating_sub(self.covered)
    }
}

/// The hubs holding more than their live contracts cover, by at least the
/// least a contract there protects: worth protecting or cashing part out.
/// Judged at the tip each hub last said, read from the contracts kept by
/// the wallet at `path`, never driving them.
pub fn unprotected(wallet: &Wallet<Http>, path: &Path) -> anyhow::Result<Vec<Unprotected>> {
    let contracts = holder::list(path)?;
    let mut found = Vec::new();
    for (url, info) in wallet.hubs()? {
        let Some(terms) = &info.contracts else {
            continue;
        };
        let smallest = u64::from(terms.range.map_or(terms.cap, |r| r.min_cap));
        let held: u64 = wallet
            .balance()?
            .iter()
            .filter(|b| b.hub == url)
            .map(|b| b.available + b.pending)
            .sum();
        let tip = info.locks.as_ref().map_or(0, |l| l.height);
        let urls = wallet.hub_urls(&url)?;
        let here: Vec<Contract> = contracts.iter().filter(|c| c.at(&urls)).cloned().collect();
        let covered: u64 = holder::coverage(wallet, path, &here, tip)?.values().sum();
        let one = Unprotected {
            hub: url,
            held,
            covered: covered.min(held),
        };
        if one.missing() >= smallest {
            found.push(one);
        }
    }
    Ok(found)
}

fn state(c: &Contract) -> String {
    if let Some(fold) = c.folded {
        return format!("closed early ({fold})");
    }
    match (&c.abandoned, c.fate) {
        (Some(why), _) => format!("given up ({why})"),
        (None, Some(fate)) => format!("{fate:?}").to_lowercase(),
        (None, None) => format!("opening ({:?})", c.phase).to_lowercase(),
    }
}

fn contract_line(c: &Contract) -> String {
    let mock = if c.mock {
        "  MOCK, protects nothing"
    } else {
        ""
    };
    format!(
        "{}  {}  {}  covers {}  until block {}  closes at block {}  deposit {}  price {}{share}{funded}{mock}",
        &licash_contracts::hex_id(&c.id)[..16],
        c.hub,
        state(c),
        crate::say::sat(c.cap.into()),
        c.assert_height,
        c.close_height,
        crate::say::sat(c.value),
        crate::say::sat(c.price),
        share = crate::say::share(c.price, c.cap.into())
            .map(|s| format!(" ({s} of what it covers)"))
            .unwrap_or_default(),
        funded = match (c.funded, c.funded_received) {
            (0, _) => String::new(),
            (f, true) => format!("  funded {} (notes received)", crate::say::sat(f)),
            (f, false) => format!("  funded {} (notes owed)", crate::say::sat(f)),
        },
    )
}

fn contract_json(c: &Contract) -> serde_json::Value {
    json!({
        "id": licash_contracts::hex_id(&c.id),
        "hub": c.hub,
        "state": state(c),
        "phase": format!("{:?}", c.phase).to_lowercase(),
        "fate": c.fate.map(|f| format!("{f:?}").to_lowercase()),
        "mock": c.mock,
        "cap": c.cap,
        "assert_height": c.assert_height,
        "close_height": c.close_height,
        "deposit": c.deposit.to_string(),
        "value": c.value,
        "price": c.price,
        "funded": c.funded,
        "funded_received": c.funded_received,
        "funding": c.funding.map(|t| t.to_string()),
        "abandoned": c.abandoned,
        "folded": c.folded.map(|t| t.to_string()),
        "created_at": c.created_at,
    })
}

/// The contract of the wallet's whose id is or starts with `id`, in hex.
fn contract_id(path: &Path, id: &str) -> anyhow::Result<[u8; 32]> {
    let id = id.to_lowercase();
    let mut found = holder::list(path)?
        .into_iter()
        .map(|c| c.id)
        .filter(|c| licash_contracts::hex_id(c).starts_with(&id));
    let one = found.next().with_context(|| format!("no contract {id}"))?;
    anyhow::ensure!(found.next().is_none(), "more than one contract starts {id}");
    Ok(one)
}

/// Force contract `id` closed, its hub silent: the wallet's notes at the
/// hub claimed on Bitcoin, paid back on Bitcoin once the hub's window
/// passed, its fees at `fee_rate` sat/vB [default: the chain's estimate].
pub async fn force_close(
    wallet: &Wallet<Http>,
    path: &Path,
    chain: Option<&str>,
    id: &str,
    fee_rate: Option<u64>,
    json: bool,
) -> anyhow::Result<()> {
    let chain = node(chain)?;
    let id = contract_id(path, id)?;
    let rate = crate::onchain::rate(&chain.0, fee_rate).await?;
    let forcing = recovery::recoveries(path)?.iter().all(|r| r.id != id);
    if forcing {
        if let Some(need) = recovery::challenge_shortfall(wallet, path, rate)? {
            eprintln!(
                "warning: no coin of {} sat on Bitcoin besides the others to set aside for a \
                 challenge's fee: should the hub prove falsely, a challenge pays what the \
                 coins hold, and may come too late",
                need.to_sat()
            );
        }
    }
    let forced = recovery::force_close(wallet, &chain, path, &id, rate).await?;
    show(json, recovery_json(&forced), recovery_line(&forced));
    Ok(())
}

/// Close contract `id` early with its hub, cooperatively: the wallet's
/// notes there, its cap at most, and its reserve back on Bitcoin in the
/// hub's fold, the protection over.
pub async fn close(
    wallet: &Wallet<Http>,
    path: &Path,
    chain: Option<&str>,
    id: &str,
    json: bool,
) -> anyhow::Result<()> {
    let chain = node(chain)?;
    let id = contract_id(path, id)?;
    let txid = licash_contracts::holder::close(wallet, &chain, path, &id).await?;
    let hex = licash_contracts::hex_id(&id);
    show(
        json,
        json!({"id": hex, "fold": txid.to_string()}),
        format!("{}  closed early by {txid}", &hex[..16]),
    );
    Ok(())
}

/// Tell `wallet` the height of `chain`, which its protected locks'
/// preimages are revealed against ([`Wallet::saw_tip`]).
pub async fn saw_tip(wallet: &Wallet<Http>, chain: &str) -> anyhow::Result<()> {
    let tip = node(Some(chain))?.height().await;
    wallet.saw_tip(tip.map_err(|e| anyhow::anyhow!(e))?);
    Ok(())
}

/// An invoice paying the wallet `amount` through `hub`, protected where a
/// contract of the wallet's at the hub would claim its lock's notes should
/// the hub keep them, and a coin of the wallet's activates the lock on
/// `chain` for less ([`activation::protects`]); else trusting the hub.
/// Saying `memo` to its payer, if given.
pub async fn invoice(
    wallet: &Wallet<Http>,
    path: &Path,
    chain: &str,
    hub: &str,
    amount: u64,
    memo: Option<&str>,
) -> anyhow::Result<licash_wallet::Invoice> {
    let node = node(Some(chain))?;
    let tip = node.height().await.map_err(|e| anyhow::anyhow!(e))?;
    let rate = crate::onchain::rate(&node.0, None).await?;
    let protected = activation::protects(wallet, path, hub, amount, rate, tip)?;
    if protected {
        wallet.saw_tip(tip);
    } else {
        tracing::info!(%hub, amount, "no contract at the hub protects the invoice's lock");
    }
    Ok(wallet.invoice_saying(hub, amount, memo, protected).await?)
}

/// The contracts the wallet forced closed: with --chain, each carried on
/// as far as the chain lets it, the payouts followed and the wallet's
/// coins looked for first, and the coins they need for their fees paid out
/// of notes to the wallet's own address, through a provider found through
/// `route` ([`recovery::fee_needs`]).
pub async fn recoveries(
    wallet: &Wallet<Http>,
    path: &Path,
    (chain, route): (Option<&str>, &licash_nostr::Route),
    fee_rate: Option<u64>,
    json: bool,
) -> anyhow::Result<()> {
    let mut paying = Vec::new();
    let all = match chain {
        Some(_) => {
            let chain = node(chain)?;
            let rate = crate::onchain::rate(&chain.0, fee_rate).await?;
            if recovery::recoveries(path)?.iter().any(|r| !r.stage.over()) {
                paying = fund(wallet, path, &chain, route, rate).await;
            }
            recovery::advance(wallet, &chain, path, rate).await?
        }
        None => recovery::recoveries(path)?,
    };
    let mut lines: Vec<String> = all.iter().map(recovery_line).collect();
    lines.extend(paying);
    show(
        json,
        all.iter().map(recovery_json).collect(),
        lines.join("\n"),
    );
    Ok(())
}

/// Follow the payouts and look for the wallet's coins, then pay out of
/// notes each coin the forced closes need for their fees: what is paid
/// out, as lines to show. Nothing here holds the recoveries up.
async fn fund(
    wallet: &Wallet<Http>,
    path: &Path,
    chain: &Node,
    route: &licash_nostr::Route,
    rate: bitcoin::FeeRate,
) -> Vec<String> {
    if let Err(e) = crate::payout::follow_all(wallet, &chain.0).await {
        tracing::warn!("payouts not followed: {e:#}");
    }
    if let Err(e) = crate::onchain::catch_up(wallet, &chain.0, None).await {
        tracing::warn!("coins not looked for: {e:#}");
    }
    let needs = match recovery::fee_needs(wallet, chain, path, rate).await {
        Ok(needs) => needs,
        Err(e) => {
            tracing::warn!("forced closes' fees not looked at: {e:#}");
            return Vec::new();
        }
    };
    let mut lines = Vec::new();
    for need in needs {
        let id = licash_contracts::hex_id(&need.id);
        let amount = need.amount.to_sat().max(FEE_PAYOUT_FLOOR);
        // Recorded as awaited before it is made: one made is never asked
        // for again.
        let record = |hash: &str| recovery::expect_fee(path, &need.id, need.purpose, hash);
        match crate::payout::for_fees(wallet, route, amount, rate, record).await {
            Ok(payout) => {
                lines.push(format!(
                    "{}  fees: {} paid out of notes to the wallet by payout {}",
                    &id[..16],
                    crate::say::sat(amount),
                    payout.hash
                ));
            }
            Err(e) => eprintln!(
                "warning: {}: no payout of {} for its fees ({e:#}): its coins pay as they can",
                &id[..16],
                crate::say::sat(amount)
            ),
        }
    }
    lines
}

/// The least a payout for a forced close's fees asks: swap providers pay
/// out no smaller coin by default (`licash-swaps --payout-min`), and what
/// it holds beyond the fees comes back as change.
const FEE_PAYOUT_FLOOR: u64 = 10_000;

/// Give up forcing contract `id` closed, the wallet's notes back to it:
/// only before its request is signed.
pub fn give_up(wallet: &Wallet<Http>, path: &Path, id: &str) -> anyhow::Result<()> {
    let id = contract_id(path, id)?;
    recovery::give_up(wallet, path, &id)
}

pub fn allow_publication_fee(path: &Path, id: &str, sats: u64) -> anyhow::Result<()> {
    let id = contract_id(path, id)?;
    recovery::allow_publication_fee(path, &id, sats)
}

fn recovery_line(r: &Recovery) -> String {
    let mut line = format!(
        "{}  {}  claims {} sat in {} notes",
        &licash_contracts::hex_id(&r.id)[..16],
        r.stage.as_str(),
        r.claimed,
        r.notes,
    );
    if let Some(at) = r.next_at {
        line.push_str(&format!("  next step at block {at}"));
    }
    if r.stage == recovery::Stage::Answered {
        let by = r
            .deadline
            .map_or_else(String::new, |d| format!(" by block {d}"));
        let owed = r
            .corrected
            .map_or_else(String::new, |c| format!(" {c} sat owed,"));
        line.push_str(&format!("  the hub says{owed} to prove{by}"));
    }
    if let Some(error) = &r.error {
        line.push_str(&format!("  ({error})"));
    }
    line
}

fn recovery_json(r: &Recovery) -> serde_json::Value {
    let txid = |t: Option<bitcoin::Txid>| t.map(|t| t.to_string());
    json!({
        "id": licash_contracts::hex_id(&r.id),
        "stage": r.stage.as_str(),
        "irrevocable": r.irrevocable,
        "claimed": r.claimed,
        "notes": r.notes,
        "request": txid(r.request),
        "publication": txid(r.publication),
        "requested_at": r.requested_at,
        "timeout": txid(r.timeout),
        "timed_out_at": r.timed_out_at,
        "sweep": txid(r.sweep),
        "swept_at": r.swept_at,
        "next_at": r.next_at,
        "error": r.error,
        "response": txid(r.response),
        "deadline": r.deadline,
        "proved": r.proved,
        "assertion": txid(r.assertion),
        "asserted_at": r.asserted_at,
        "challenge": txid(r.challenge),
        "payout": txid(r.payout),
        "paid_at": r.paid_at,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use licash::spend::ChainProfile;

    fn offered(range: Option<licash_api::ContractRange>) -> licash_api::Contracts {
        licash_api::Contracts {
            cap: 131_071,
            price: 23_002,
            reserve: 20_000,
            blocks: 1_000,
            mock: true,
            range,
        }
    }

    fn range() -> licash_api::ContractRange {
        licash_api::ContractRange {
            min_cap: 131_071,
            max_cap: 1_048_575,
            min_blocks: 300,
            max_blocks: 52_560,
            per_coin: 4,
            reserve: 20_000,
            fee: 3_000,
            ppm_year: 20_000,
            ppm_year_funded: 5_000,
            year_blocks: licash_api::YEAR_BLOCKS,
        }
    }

    #[test]
    fn a_co_funded_contract_is_itemized_its_interest_on_each_part() {
        let t = Terms::of(
            "hub",
            &offered(Some(range())),
            Some(262_143),
            Some(52_560),
            62_143,
        )
        .unwrap();
        // 2% of the hub's 200 000 and 0.5% of her 62 143, over a year.
        let value = t.json();
        assert_eq!(value["opening_fee"], 3_000);
        assert_eq!(value["interest"], 4_000);
        assert_eq!(value["interest_funded"], 310);
        assert_eq!(value["fee"], 7_310);
        assert_eq!(value["price"], 27_310);
        assert_eq!(value["pays"], 27_310 + 62_143);
        let lines = t.lines(144);
        for said in [
            "covers       262,143 sat, 200,000 funded by the hub, 62,143 by you",
            "opening fee  3,000 sat",
            "interest     4,000 sat, 2% a year on the hub's 200,000",
            "interest     310 sat, 0.5% a year on your 62,143",
            "reserve      20,000 sat, returned as it closes",
            "price        27,310 sat: fee 7,310 sat",
            "your part    62,143 sat",
            "paid         89,453 sat from your coin",
        ] {
            assert!(lines.contains(said), "{said} not in\n{lines}");
        }
    }

    #[test]
    fn more_funded_than_a_fixed_contract_holds_is_refused() {
        let offered = offered(None);
        let over = Terms::of("hub", &offered, None, None, offered.cap + 1);
        let e = over.err().expect("refused").to_string();
        assert!(e.contains("more than the contract's"), "{e}");
    }

    #[test]
    fn fixed_terms_are_priced_over_the_hubs_blocks_and_only_sizes_are_chosen() {
        let fixed = Terms::of("hub", &offered(Some(range())), None, Some(300), 0).unwrap();
        assert_eq!((fixed.cap, fixed.blocks), (131_071, 1_000));
        assert_eq!(fixed.price, range().price(131_071, 1_000, 0));
        let odd = Terms::of("hub", &offered(Some(range())), Some(200_000), Some(300), 0);
        let odd = format!("{:#}", odd.err().unwrap());
        assert!(
            odd.contains("131,071, 262,143, 524,287, 1,048,575 sat"),
            "{odd}"
        );
        let over = Terms::of("hub", &offered(Some(range())), Some(131_071), None, 131_072);
        assert!(over.is_err());
        // A hub of fixed terms only: its fee in one.
        let only = Terms::of("hub", &offered(None), None, None, 0).unwrap();
        assert!(
            only.lines(144).contains("hub's fee    3,002 sat"),
            "{}",
            only.lines(144)
        );
        // Her part of its one contract changes its price not at all.
        let part = Terms::of("hub", &offered(None), None, None, 1).unwrap();
        assert_eq!((part.price, part.funded), (only.price, 1));
        assert!(Terms::of("hub", &offered(None), Some(131_071), Some(9), 0).is_err());
    }

    #[test]
    fn a_contracts_length_is_told_in_the_days_of_its_network() {
        let t = Terms::of(
            "hub",
            &offered(Some(range())),
            Some(131_071),
            Some(5_760),
            0,
        )
        .unwrap();
        let (bitcoin, mutinynet) = (ChainProfile::Core30Signet, ChainProfile::Mutinynet);
        assert!(t
            .lines(bitcoin.blocks_a_day())
            .contains("5,760 blocks (about 40 days)"));
        assert!(t
            .lines(mutinynet.blocks_a_day())
            .contains("5,760 blocks (about 2 days)"));
    }
}
