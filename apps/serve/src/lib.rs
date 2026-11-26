//! How the Licash services serve HTTP, so that no client holds more of
//! them than its share:
//!
//! - [`listen`] and [`listen_tls`] serve a router on a TCP listener, at
//!   most [`MAX_CONNECTIONS`] at once, each connection let go if its
//!   handshake or a request's headers take longer than [`HEADERS`];
//! - [`shed`] serves at most so many requests at once, answering more
//!   unavailable at once, and refuses a request whose body is still
//!   arriving [`BODY_TIME`] after its head ([`bodies_within`] alone);
//! - [`resolving`] tells each request's [`AdmissionSource`], an onion
//!   circuit or a client's address, behind proxies the operator trusts
//!   ([`Ingress`]), for the handlers that count what is asked and not paid
//!   by it ([`Admission`]).

mod listen;
mod shed;
mod source;

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use licash_api::Problem;

pub use listen::{listen, listen_tls, HEADERS, MAX_CONNECTIONS};
pub use shed::{bodies_within, shed, BODY_TIME, HEALTH};
pub use source::{
    resolving, trusted_proxy, Admission, AdmissionSource, Circuit, Ingress, Malformed,
    FORWARDED_FOR, MAX_FORWARDED,
};

/// `problem` answered as a Licash service answers one: its status, and
/// itself as JSON.
pub fn problem(problem: Problem) -> Response {
    let status =
        StatusCode::from_u16(problem.code.status()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    (status, Json(problem)).into_response()
}
