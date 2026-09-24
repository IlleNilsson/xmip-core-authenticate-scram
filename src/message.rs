//! The two messages a SCRAM client sends, read and not yet believed.
//!
//! RFC 5802 section 7. The client-first-message is a GS2 header — the
//! channel-binding flag, an optional authorization identity — and then the
//! bare message `n=<user>,r=<nonce>`. The client-final-message is
//! `c=<base64 of the GS2 header>,r=<both nonces>,p=<base64 ClientProof>`,
//! and everything before `,p=` is what the proof was computed over. A
//! username writes `,` as `=2C` and `=` as `=3D`.

use authenticate::AuthenticateError;

/// The client-first-message.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClientFirst {
    /// The GS2 header as sent, commas included: `n,,` for most clients.
    pub gs2_header: String,
    /// The message after the header, which the proof is computed over.
    pub bare: String,
    /// The username, unescaped.
    pub username: String,
    /// The client's nonce.
    pub nonce: String,
}

/// Undo RFC 5802's escaping of a username.
fn unescape(name: &str) -> Result<String, AuthenticateError> {
    let mut out = String::with_capacity(name.len());
    let mut rest = name;
    while let Some(at) = rest.find('=') {
        out.push_str(&rest[..at]);
        match rest.get(at..at + 3) {
            Some("=2C") => out.push(','),
            Some("=3D") => out.push('='),
            _ => {
                return Err(AuthenticateError::new(
                    "the SCRAM username has an '=' that escapes nothing",
                ));
            }
        }
        rest = &rest[at + 3..];
    }
    out.push_str(rest);
    Ok(out)
}

/// The value of the attribute `name` at the head of `field`.
fn attribute<'a>(
    field: Option<&'a str>,
    name: char,
    of: &str,
) -> Result<&'a str, AuthenticateError> {
    field
        .and_then(|text| text.strip_prefix(name))
        .and_then(|text| text.strip_prefix('='))
        .ok_or_else(|| AuthenticateError::new(format!("the SCRAM {of} has no '{name}=' here")))
}

impl ClientFirst {
    /// Read a client-first-message.
    ///
    /// # Errors
    ///
    /// The client requires channel binding, which this node does not offer;
    /// an extension is mandatory; or the username or nonce is missing.
    pub fn parse(message: &str) -> Result<Self, AuthenticateError> {
        let of = "client-first-message";
        let mut fields = message.splitn(3, ',');
        let flag = fields.next().unwrap_or_default();
        let authzid = fields.next();
        let bare = fields.next();
        match flag {
            "n" | "y" => {}
            flag if flag.starts_with("p=") => {
                return Err(AuthenticateError::new(
                    "the SCRAM client requires channel binding and this node offers none",
                ));
            }
            _ => {
                return Err(AuthenticateError::new(format!(
                    "the SCRAM {of} does not open with a channel-binding flag"
                )));
            }
        }
        let (Some(authzid), Some(bare)) = (authzid, bare) else {
            return Err(AuthenticateError::new(format!(
                "the SCRAM {of} has no GS2 header"
            )));
        };
        if bare.starts_with("m=") {
            return Err(AuthenticateError::new(
                "the SCRAM client makes an extension mandatory and this node reads none",
            ));
        }
        let mut attributes = bare.split(',');
        let username = unescape(attribute(attributes.next(), 'n', of)?)?;
        let nonce = attribute(attributes.next(), 'r', of)?;
        if username.is_empty() || nonce.is_empty() {
            return Err(AuthenticateError::new(format!(
                "the SCRAM {of} has an empty username or nonce"
            )));
        }
        Ok(Self {
            gs2_header: format!("{flag},{authzid},"),
            bare: bare.to_string(),
            username,
            nonce: nonce.to_string(),
        })
    }
}

/// The client-final-message.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClientFinal {
    /// The channel binding the client echoes: the GS2 header, decoded.
    pub binding: Vec<u8>,
    /// The client's nonce with the server's after it.
    pub nonce: String,
    /// The message up to and not including `,p=`.
    pub without_proof: String,
    /// The `ClientProof`, decoded.
    pub proof: Vec<u8>,
}

impl ClientFinal {
    /// Read a client-final-message.
    ///
    /// # Errors
    ///
    /// An attribute is missing or out of order, or is not base64.
    pub fn parse(message: &str) -> Result<Self, AuthenticateError> {
        let of = "client-final-message";
        let (without_proof, proof) = message.rsplit_once(",p=").ok_or_else(|| {
            AuthenticateError::new(format!("the SCRAM {of} does not end with a proof"))
        })?;
        let mut attributes = without_proof.split(',');
        let binding = attribute(attributes.next(), 'c', of)?;
        let nonce = attribute(attributes.next(), 'r', of)?;
        let decode = |text: &str, what: &str| {
            codec::base64::decode(text)
                .map_err(|_| AuthenticateError::new(format!("the SCRAM {what} is not base64")))
        };
        Ok(Self {
            binding: decode(binding, "channel binding")?,
            nonce: nonce.to_string(),
            without_proof: without_proof.to_string(),
            proof: decode(proof, "proof")?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_client_first_message_yields_its_header_its_bare_part_and_the_username() {
        let read = ClientFirst::parse("n,,n=user,r=rOprNGfwEbeRWgbNEkqO").expect("read");
        assert_eq!(read.gs2_header, "n,,");
        assert_eq!(read.bare, "n=user,r=rOprNGfwEbeRWgbNEkqO");
        assert_eq!(read.username, "user");
        assert_eq!(read.nonce, "rOprNGfwEbeRWgbNEkqO");

        let escaped = ClientFirst::parse("y,a=admin,n=a=2Cb=3Dc,r=abc,x=ext").expect("read");
        assert_eq!(escaped.gs2_header, "y,a=admin,");
        assert_eq!(escaped.username, "a,b=c");
        assert_eq!(escaped.nonce, "abc");
    }

    #[test]
    fn what_this_node_does_not_offer_is_refused_by_name() {
        let refused = |message: &str| ClientFirst::parse(message).expect_err("refused").message;
        assert!(refused("p=tls-unique,,n=user,r=abc").contains("channel binding"));
        assert!(refused("n,,m=ext,n=user,r=abc").contains("mandatory"));
        assert!(refused("n=user,r=abc").contains("channel-binding flag"));
        assert!(refused("n,,r=abc").contains("no 'n='"));
        assert!(refused("n,,n=user").contains("no 'r='"));
        assert!(refused("n,,n=us=er,r=abc").contains("escapes nothing"));
        assert!(refused("n,,n=,r=abc").contains("empty"));
    }

    #[test]
    fn a_client_final_message_yields_what_the_proof_was_computed_over() {
        let read = ClientFinal::parse("c=biws,r=abcdef,p=AQID").expect("read");
        assert_eq!(read.binding, b"n,,");
        assert_eq!(read.nonce, "abcdef");
        assert_eq!(read.without_proof, "c=biws,r=abcdef");
        assert_eq!(read.proof, [1, 2, 3]);

        let refused = |message: &str| ClientFinal::parse(message).expect_err("refused").message;
        assert!(refused("c=biws,r=abcdef").contains("does not end with a proof"));
        assert!(refused("r=abcdef,p=AQID").contains("no 'c='"));
        assert!(refused("c=biws,r=abcdef,p=***").contains("not base64"));
    }
}
