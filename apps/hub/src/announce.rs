//! The hub's announcement on Nostr relays, for wallets to discover it.

use std::{sync::Arc, time::Duration};

use licash_hub::Hub;
use licash_nostr::{Announcement, Announcer, Role, Route};

/// Announce `hub` at `urls`, named `name`, on `relays` reached through
/// `route`, for good: once its first checkpoint names the network it
/// follows.
pub async fn announce(
    hub: Arc<Hub>,
    relays: Vec<String>,
    route: Route,
    urls: Vec<String>,
    name: Option<String>,
) {
    let profile = loop {
        if let Some(checkpoint) = hub.checkpoint() {
            break checkpoint.profile();
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    };
    let announcement = Announcement {
        urls,
        network: profile.name().to_owned(),
        name,
    };
    let secret = match hub.nostr_secret() {
        Ok(secret) => secret,
        Err(e) => return tracing::error!("announcing on Nostr: {e:#}"),
    };
    match Announcer::new(&secret, Role::Hub, &relays, &route).await {
        Ok(announcer) => announcer.run(announcement).await,
        Err(e) => tracing::error!("announcing on Nostr: {e:#}"),
    }
}
