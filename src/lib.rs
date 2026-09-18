#![forbid(unsafe_code)]

//! Authenticate by SCRAM-SHA-256: the server side of the exchange, against
//! the capability's stored verifiers.
//!
//! RFC 5802 with RFC 7677's hash — what Kafka, `PostgreSQL` and XMPP speak.
//! Four messages, and the password is in none of them. The client opens
//! with its name and a nonce; [`ScramAuthenticator::server_first`] answers
//! with both nonces, the user's salt and the iteration count, and remembers
//! the exchange under the combined nonce. The client's final message
//! carries a `ClientProof`; the carrier presents it as a `scram` claim — or
//! a bare `username` — with the message riding on `Presented::proof` under
//! `scram.client-final`. This gate recovers the `ClientKey` from the proof,
//! checks that it hashes to the `StoredKey` the `CredentialStore` keeps,
//! and on success leaves the `ServerSignature` to be collected with
//! [`ScramAuthenticator::server_final`], so the client can tell that the
//! node knew the verifier too.
//!
//! An exchange is good for one final message. A name the store does not
//! hold is answered with a salt derived from the name, the same every time,
//! and is refused at the end like a wrong password. Channel binding is not
//! offered: a client that requires it is refused saying so. `SASLprep` is
//! not applied; a username and a password are compared as they were sent.

pub mod message;

pub use message::{ClientFinal, ClientFirst};

use authenticate::store::{CredentialStore, KEY_LENGTH, Verifier, fresh_salt, hmac_sha256, sha256};
use authenticate::{AuthenticateError, Authenticator, Presented};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use context::Verified;
use std::collections::HashMap;
use std::sync::{Mutex, MutexGuard, PoisonError};
use xcore::{Mechanism, mechanism};

/// The proof name this verifier reads off a `Presented`: the whole
/// client-final-message.
pub const PROOF: &str = "scram.client-final";

/// How many exchanges may stand open, and how many signatures uncollected,
/// before the oldest is dropped.
pub const MOST_OPEN: usize = 1024;

type NonceSource = Box<dyn Fn() -> String + Send + Sync>;

/// What is remembered between the server-first and the client-final.
struct Exchange {
    opened: u64,
    username: String,
    gs2_header: String,
    /// `client-first-bare,server-first`: the head of the `AuthMessage`.
    transcript: String,
    /// `None` where the store does not hold the name.
    verifier: Option<Verifier>,
}

#[derive(Default)]
struct Exchanges {
    sequence: u64,
    open: HashMap<String, Exchange>,
    proven: HashMap<String, (u64, String)>,
}

impl Exchanges {
    fn next(&mut self) -> u64 {
        self.sequence += 1;
        self.sequence
    }
}

/// Drop the oldest entry of `map` while it holds [`MOST_OPEN`] or more.
fn make_room<V>(map: &mut HashMap<String, V>, age: impl Fn(&V) -> u64) {
    while map.len() >= MOST_OPEN {
        let oldest = map
            .iter()
            .min_by_key(|(_, value)| age(value))
            .map(|(nonce, _)| nonce.clone());
        match oldest {
            Some(nonce) => map.remove(&nonce),
            None => return,
        };
    }
}

/// Runs the server side of SCRAM-SHA-256 against a credential store.
pub struct ScramAuthenticator {
    store: CredentialStore,
    nonces: NonceSource,
    decoy: [u8; 16],
    exchanges: Mutex<Exchanges>,
}

impl ScramAuthenticator {
    #[must_use]
    pub fn new(store: CredentialStore) -> Self {
        Self {
            store,
            nonces: Box::new(|| STANDARD.encode(fresh_salt("scram.nonce"))),
            decoy: fresh_salt("scram.decoy"),
            exchanges: Mutex::new(Exchanges::default()),
        }
    }

    /// Where the server's half of the nonce comes from; the tests pin it to
    /// the RFC's.
    #[must_use]
    pub fn with_nonces(mut self, nonces: impl Fn() -> String + Send + Sync + 'static) -> Self {
        self.nonces = Box::new(nonces);
        self
    }

    /// The enrollments this verifies against.
    #[must_use]
    pub fn store(&self) -> &CredentialStore {
        &self.store
    }

    fn exchanges(&self) -> MutexGuard<'_, Exchanges> {
        self.exchanges
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    /// Answer a client-first-message with the server-first-message, and
    /// remember the exchange until its final message arrives.
    ///
    /// # Errors
    ///
    /// The client-first-message cannot be read, or asks for what this node
    /// does not offer.
    pub fn server_first(&self, client_first: &str) -> Result<String, AuthenticateError> {
        let first = ClientFirst::parse(client_first)?;
        let nonce = format!("{}{}", first.nonce, (self.nonces)());
        let verifier = self.store.verifier(&first.username).cloned();
        let (salt, iterations) = if let Some(held) = &verifier {
            (held.salt().to_vec(), held.iterations())
        } else {
            let mut seed = self.decoy.to_vec();
            seed.extend_from_slice(first.username.as_bytes());
            (sha256(&seed)[..16].to_vec(), self.store.iterations())
        };
        let server_first = format!("r={nonce},s={},i={iterations}", STANDARD.encode(salt));

        let mut exchanges = self.exchanges();
        make_room(&mut exchanges.open, |exchange| exchange.opened);
        let opened = exchanges.next();
        exchanges.open.insert(
            nonce,
            Exchange {
                opened,
                username: first.username,
                gs2_header: first.gs2_header,
                transcript: format!("{},{server_first}", first.bare),
                verifier,
            },
        );
        Ok(server_first)
    }

    /// The server-final-message, `v=<ServerSignature>`, for an exchange that
    /// was proven under `nonce` — the combined nonce of the client's final
    /// message. Collected once.
    #[must_use]
    pub fn server_final(&self, nonce: &str) -> Option<String> {
        self.exchanges()
            .proven
            .remove(nonce)
            .map(|(_, signature)| format!("v={signature}"))
    }
}

/// Whether a claim is one this verifier reads: a bare `username`, or one
/// the carrier already filed under `scram`.
fn reads(mechanism: &Mechanism) -> bool {
    let name = mechanism.name();
    name == "username" || name == "scram"
}

/// `ClientKey = ClientProof XOR HMAC(StoredKey, AuthMessage)`.
fn client_key(verifier: &Verifier, auth_message: &str, proof: &[u8]) -> Option<[u8; KEY_LENGTH]> {
    if proof.len() != KEY_LENGTH {
        return None;
    }
    let mut key = hmac_sha256(verifier.stored_key(), auth_message.as_bytes());
    for (out, byte) in key.iter_mut().zip(proof) {
        *out ^= byte;
    }
    Some(key)
}

impl Authenticator for ScramAuthenticator {
    fn mechanism(&self) -> Mechanism {
        mechanism::scram()
    }

    fn verify(&self, presented: &Presented) -> Result<Verified, AuthenticateError> {
        if !reads(&presented.mechanism) {
            return Err(AuthenticateError::new(format!(
                "'{}' is not a claim the SCRAM verifier reads: it takes a username",
                presented.mechanism.name()
            )));
        }
        let message = presented.proof(PROOF).ok_or_else(|| {
            AuthenticateError::new(format!(
                "no '{PROOF}' proof was presented with the username '{}'",
                presented.value
            ))
        })?;
        let last = ClientFinal::parse(message)?;
        let exchange = self.exchanges().open.remove(&last.nonce).ok_or_else(|| {
            AuthenticateError::new(
                "no SCRAM exchange is open under that nonce: never opened, or already finished",
            )
        })?;
        if exchange.username != presented.value {
            return Err(AuthenticateError::new(format!(
                "the claim names '{}' and the SCRAM exchange was opened by '{}'",
                presented.value, exchange.username
            )));
        }
        if last.binding != exchange.gs2_header.as_bytes() {
            return Err(AuthenticateError::new(
                "the SCRAM channel binding is not the GS2 header the exchange opened with",
            ));
        }
        let Some(verifier) = exchange.verifier else {
            return Ok(Verified::Refused);
        };
        let auth_message = format!("{},{}", exchange.transcript, last.without_proof);
        let Some(key) = client_key(&verifier, &auth_message, &last.proof) else {
            return Err(AuthenticateError::new(format!(
                "the SCRAM proof is {} bytes and SHA-256's is {KEY_LENGTH}",
                last.proof.len()
            )));
        };
        if !verifier.proves(&key) {
            return Ok(Verified::Refused);
        }

        let signature = hmac_sha256(verifier.server_key(), auth_message.as_bytes());
        let mut exchanges = self.exchanges();
        make_room(&mut exchanges.proven, |(proven, _)| *proven);
        let proven = exchanges.next();
        exchanges
            .proven
            .insert(last.nonce, (proven, STANDARD.encode(signature)));
        Ok(Verified::Proven)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use authenticate::store::pbkdf2_sha256;

    const ITERATIONS: u32 = 4096;

    // RFC 7677 section 3: user "user", password "pencil".
    const CLIENT_FIRST: &str = "n,,n=user,r=rOprNGfwEbeRWgbNEkqO";
    const SERVER_NONCE: &str = "%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0";
    const SERVER_FIRST: &str = "r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,\
                                s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096";
    const CLIENT_FINAL: &str = "c=biws,r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,\
                                p=dHzbZapWIk4jUhN+Ute9ytag9zjfMHgsqmmiz7AndVQ=";
    const SERVER_FINAL: &str = "v=6rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4=";
    const NONCE: &str = "rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0";

    fn published() -> ScramAuthenticator {
        let salt = STANDARD.decode("W22ZaJ0SNY7soEsUEjb6gQ==").expect("base64");
        let mut store = CredentialStore::with_iterations(ITERATIONS);
        store.insert_verifier("user", Verifier::derive("pencil", &salt, ITERATIONS));
        ScramAuthenticator::new(store).with_nonces(|| SERVER_NONCE.to_string())
    }

    fn claim(username: &str, client_final: &str) -> Presented {
        Presented::passed(mechanism::scram(), username).with_proof(PROOF, client_final)
    }

    /// The client's half: answer a server-first-message with a password.
    fn client_final(client_first_bare: &str, server_first: &str, password: &str) -> String {
        let field = |name: &str| {
            server_first
                .split(',')
                .find_map(|part| part.strip_prefix(name))
                .expect("present")
        };
        let salt = STANDARD.decode(field("s=")).expect("base64");
        let iterations: u32 = field("i=").parse().expect("a number");
        let without_proof = format!("c=biws,r={}", field("r="));
        let auth_message = format!("{client_first_bare},{server_first},{without_proof}");
        let salted = pbkdf2_sha256(password.as_bytes(), &salt, iterations);
        let client_key = hmac_sha256(&salted, b"Client Key");
        let signature = hmac_sha256(&sha256(&client_key), auth_message.as_bytes());
        let proof: Vec<u8> = client_key
            .iter()
            .zip(signature)
            .map(|(key, byte)| key ^ byte)
            .collect();
        format!("{without_proof},p={}", STANDARD.encode(proof))
    }

    #[test]
    fn the_exchange_rfc_7677_publishes_is_proven_and_signed_as_published() {
        let verifier = published();
        assert_eq!(
            verifier.server_first(CLIENT_FIRST).expect("answered"),
            SERVER_FIRST
        );
        assert_eq!(
            verifier
                .verify(&claim("user", CLIENT_FINAL))
                .expect("verified"),
            Verified::Proven
        );
        assert_eq!(verifier.server_final(NONCE).as_deref(), Some(SERVER_FINAL));
        // Collected once.
        assert_eq!(verifier.server_final(NONCE), None);
        assert_eq!(verifier.mechanism().name(), "scram");
    }

    #[test]
    fn an_enrolled_password_proves_a_username_claim_and_a_wrong_one_is_refused() {
        let store = CredentialStore::from_entries(ITERATIONS, [("alice", "pencil")]);
        let verifier = ScramAuthenticator::new(store);
        for (password, outcome) in [("pencil", Verified::Proven), ("pen", Verified::Refused)] {
            let server_first = verifier
                .server_first("n,,n=alice,r=fyko+d2lbbFgONRv9qkxdawL")
                .expect("answered");
            let last = client_final(
                "n=alice,r=fyko+d2lbbFgONRv9qkxdawL",
                &server_first,
                password,
            );
            let bare = Presented::passed(mechanism::username(), "alice").with_proof(PROOF, &last);
            assert_eq!(verifier.verify(&bare).expect("verified"), outcome);
            let nonce = ClientFinal::parse(&last).expect("read").nonce;
            assert_eq!(
                verifier.server_final(&nonce).is_some(),
                outcome == Verified::Proven
            );
        }
        assert!(verifier.store().contains("alice"));
    }

    #[test]
    fn a_finished_exchange_cannot_be_replayed() {
        let verifier = published();
        verifier.server_first(CLIENT_FIRST).expect("answered");
        verifier
            .verify(&claim("user", CLIENT_FINAL))
            .expect("verified");
        let replay = verifier
            .verify(&claim("user", CLIENT_FINAL))
            .expect_err("replay");
        assert!(
            replay.message.contains("already finished"),
            "{}",
            replay.message
        );
    }

    #[test]
    fn an_unknown_name_is_answered_like_a_known_one_and_refused_at_the_end() {
        let store = CredentialStore::from_entries(ITERATIONS, [("alice", "pencil")]);
        let verifier = ScramAuthenticator::new(store);
        let first = verifier
            .server_first("n,,n=mallory,r=abc")
            .expect("answered");
        let again = verifier
            .server_first("n,,n=mallory,r=abd")
            .expect("answered");
        let salt = |message: &str| {
            message
                .split(',')
                .find_map(|part| part.strip_prefix("s=").map(str::to_string))
                .expect("a salt")
        };
        assert_eq!(salt(&first), salt(&again));
        assert!(first.ends_with(",i=4096"));

        let last = client_final("n=mallory,r=abc", &first, "pencil");
        assert_eq!(
            verifier.verify(&claim("mallory", &last)).expect("verified"),
            Verified::Refused
        );
    }

    #[test]
    fn a_claim_for_another_name_and_another_binding_are_refused_saying_so() {
        let verifier = published();
        verifier.server_first(CLIENT_FIRST).expect("answered");
        let failure = verifier
            .verify(&claim("admin", CLIENT_FINAL))
            .expect_err("refused");
        assert!(
            failure.message.contains("opened by 'user'"),
            "{}",
            failure.message
        );

        verifier.server_first(CLIENT_FIRST).expect("answered");
        // "eSws" is base64 of "y,,": not the header this exchange opened with.
        let rebound = CLIENT_FINAL.replace("c=biws", "c=eSws");
        let failure = verifier
            .verify(&claim("user", &rebound))
            .expect_err("refused");
        assert!(
            failure.message.contains("channel binding"),
            "{}",
            failure.message
        );
    }

    #[test]
    fn a_missing_proof_and_another_mechanism_are_refused_by_name() {
        let bare = Presented::passed(mechanism::scram(), "user");
        let failure = published().verify(&bare).expect_err("refused");
        assert!(
            failure.message.contains("'scram.client-final' proof"),
            "{}",
            failure.message
        );
        let key = Presented::passed(mechanism::api_key(), "k-1").with_proof(PROOF, CLIENT_FINAL);
        let failure = published().verify(&key).expect_err("refused");
        assert!(failure.message.contains("'api-key'"), "{}", failure.message);
    }

    #[test]
    fn the_oldest_open_exchange_makes_room_for_the_newest() {
        let verifier = published();
        let mut count = 0_usize;
        while count <= MOST_OPEN {
            verifier
                .server_first(&format!("n,,n=user,r=client{count}-"))
                .expect("answered");
            count += 1;
        }
        let exchanges = verifier.exchanges();
        assert_eq!(exchanges.open.len(), MOST_OPEN);
        assert!(
            !exchanges
                .open
                .contains_key(&format!("client0-{SERVER_NONCE}"))
        );
        assert!(
            exchanges
                .open
                .contains_key(&format!("client1-{SERVER_NONCE}"))
        );
    }
}
