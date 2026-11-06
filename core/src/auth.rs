//! moon-naive proofs: standard HMAC-SHA256 bound to the TLS exporter and HTTP stream.
//! No bearer passwords, clock window, nonce cache, or connection-wide login.
use crate::codec::{Mode, Offer};
use base64::{Engine, engine::general_purpose::STANDARD};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

pub const EXPORTER_LABEL: &str = "EXPORTER-moon-naive-v4";
const DOMAIN: &[u8] = b"moon-naive/v4/request\0";

/// Only transport adapters can supply the actual TLS exporter and stream ID.
/// Do not derive either value from untrusted HTTP headers.
#[derive(Clone, Copy)]
pub struct Binding {
    pub exporter: [u8; 32],
    pub stream_id: u64,
}

pub struct Context<'a> {
    pub binding: &'a Binding,
    pub method: &'a str,
    pub authority: &'a str,
    pub scheme: Option<&'a str>,
    pub path: Option<&'a str>,
    pub protocol: Option<&'a str>,
}

/// High-entropy shared secrets only; SHA256 is not a password-hardening KDF.
/// No Debug implementation: neither keys nor credentials enter logs.
pub struct Credentials {
    // Precompute keyed inner/outer hash states once. Clone only fixed-size state
    // per proof instead of rehashing ipad/opad for every user on every request.
    keys: Vec<Hmac<Sha256>>,
}
impl Credentials {
    pub fn new(users: &[(&str, &str)]) -> Result<Self, &'static str> {
        if users.is_empty() || users.len() > 256 {
            return Err("1..256 users required");
        }
        let mut keys = Vec::with_capacity(users.len());
        for (user, pass) in users {
            if user.is_empty()
                || user.contains(':')
                || user.chars().any(char::is_control)
                || pass.len() < 16
                || pass.chars().any(char::is_control)
                || user.len() + pass.len() > 2048
            {
                return Err(
                    "invalid credentials; use a high-entropy password of at least 16 bytes",
                );
            }
            let mut hash = Sha256::new();
            hash.update(b"moon-naive/v4/key\0");
            hash.update(user.as_bytes());
            hash.update(b":");
            hash.update(pass.as_bytes());
            keys.push(Hmac::<Sha256>::new_from_slice(&hash.finalize()).expect("32-byte HMAC key"));
        }
        Ok(Self { keys })
    }
    /// Duplicates/malformed negotiation fail before any dial. All keys are checked.
    pub fn authenticate(&self, headers: &[&str], context: &Context<'_>) -> Option<(usize, Offer)> {
        if headers.len() != 1 {
            return None;
        }
        let (bits, incoming) = parse(headers[0])?;
        let offer = Offer::from_bits(bits).ok()?;
        let transcript = transcript(context, DOMAIN, offer.bits(), 0);
        let mut matched = None;
        for (index, key) in self.keys.iter().enumerate() {
            if bool::from(incoming.ct_eq(&proof(key, &transcript))) {
                matched = Some((index, offer));
            }
        }
        matched
    }
    pub fn principal(&self, headers: &[&str], context: &Context<'_>) -> Option<usize> {
        self.authenticate(headers, context).map(|(user, _)| user)
    }
    /// Minimal finite-16 offer. Advanced clients explicitly offer additional modes.
    pub fn authorization(&self, principal: usize, context: &Context<'_>) -> Option<String> {
        self.authorization_with(principal, context, Offer::default())
    }
    /// Never-index the entire field in HPACK/QPACK. Recompute for every stream.
    pub fn authorization_with(
        &self,
        principal: usize,
        context: &Context<'_>,
        offer: Offer,
    ) -> Option<String> {
        Some(header(
            offer.bits(),
            proof(
                self.keys.get(principal)?,
                &transcript(context, DOMAIN, offer.bits(), 0),
            ),
        ))
    }
    pub fn confirmation(&self, principal: usize, context: &Context<'_>) -> Option<String> {
        self.confirmation_with(principal, context, Offer::default(), Mode::default())
    }
    pub fn confirmation_with(
        &self,
        principal: usize,
        context: &Context<'_>,
        offer: Offer,
        mode: Mode,
    ) -> Option<String> {
        if !offer.accepts(mode) {
            return None;
        }
        Some(header(
            mode.bits(),
            proof(
                self.keys.get(principal)?,
                &transcript(
                    context,
                    b"moon-naive/v4/response/200\0",
                    offer.bits(),
                    mode.bits(),
                ),
            ),
        ))
    }
    /// Verification returns the authenticated selection. Do not initialize the
    /// codec or send target payload until 200 plus this unique field is checked.
    pub fn verify_selection(
        &self,
        principal: usize,
        context: &Context<'_>,
        offer: Offer,
        response: &str,
    ) -> Option<Mode> {
        let (bits, incoming) = parse(response)?;
        let mode = Mode::from_bits(bits).ok()?;
        if !offer.accepts(mode) {
            return None;
        }
        let expected = proof(
            self.keys.get(principal)?,
            &transcript(context, b"moon-naive/v4/response/200\0", offer.bits(), bits),
        );
        bool::from(incoming.ct_eq(&expected)).then_some(mode)
    }
    pub fn verify_confirmation(
        &self,
        principal: usize,
        context: &Context<'_>,
        response: &str,
    ) -> bool {
        self.verify_selection(principal, context, Offer::default(), response)
            .is_some()
    }
}
// Exactly one allocation for either proof field; Base64 writes directly into
// its final destination rather than allocating an intermediate String.
fn header(bits: u8, mac: [u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut value = String::with_capacity(58);
    value.push_str("moon-naive ");
    value.push(char::from(HEX[usize::from(bits >> 4)]));
    value.push(char::from(HEX[usize::from(bits & 15)]));
    value.push('.');
    STANDARD.encode_string(mac, &mut value);
    debug_assert_eq!(value.len(), 58);
    value
}
fn parse(header: &str) -> Option<(u8, [u8; 32])> {
    if header.len() != 58 {
        return None;
    }
    let (scheme, value) = header.split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("moon-naive") {
        return None;
    }
    let (hex, encoded) = value.split_once('.')?;
    if hex.len() != 2
        || !hex
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return None;
    }
    let bits = u8::from_str_radix(hex, 16).ok()?;
    let mut incoming = [0; 32];
    if STANDARD.decode_slice(encoded, &mut incoming).ok()? != 32 {
        return None;
    }
    Some((bits, incoming))
}
// Hash the bounded request once, not once per configured user. This avoids
// multiplying attacker-controlled header hashing by the 256-user limit.
fn transcript(context: &Context<'_>, domain: &[u8], offer: u8, selected: u8) -> [u8; 32] {
    let mut mac = Sha256::new();
    mac.update(domain);
    mac.update(context.binding.exporter);
    mac.update(context.binding.stream_id.to_be_bytes());
    mac.update([offer, selected]);
    // Fixed field order and length prefixes distinguish absent/empty fields.
    for field in [
        Some(context.method),
        Some(context.authority),
        context.scheme,
        context.path,
        context.protocol,
    ] {
        if let Some(field) = field {
            mac.update((field.len() as u64).to_be_bytes());
            mac.update(field.as_bytes());
        } else {
            mac.update(u64::MAX.to_be_bytes());
        }
    }
    mac.finalize().into()
}

fn proof(key: &Hmac<Sha256>, transcript: &[u8; 32]) -> [u8; 32] {
    let mut mac = key.clone();
    mac.update(transcript);
    mac.finalize().into_bytes().into()
}
