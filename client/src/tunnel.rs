//! Transport-independent tunnel pieces: authentication context, the open
//! result, and Rupin record framing with randomized padding.
use moon_naive_core::{
    auth::{Binding, Context, Credentials},
    codec::{Decoder, Encoder, MAX_PAYLOAD, Mode, Offer},
};
use std::fmt;

/// The client offers every Rupin capability; the server selects.
pub const OFFER_BITS: u8 = 0x07;
pub fn offer() -> Offer {
    Offer::from_bits(OFFER_BITS).expect("valid offer")
}

/// Why opening a tunnel failed. Never carries secrets.
#[derive(Debug)]
pub enum OpenError {
    /// Transport or TLS failure before a response; the connection is unusable.
    Connection(String),
    /// The server answered with a non-200 status (policy, DNS, dial, or an
    /// authentication failure that the server routed to its website).
    Status(u16),
    /// A 200 response without a valid mona confirmation. Never treated as an
    /// established tunnel.
    Confirmation,
    /// The client refused to sign: the connection did not meet the binding
    /// requirements (for example, ECH was configured but not accepted).
    Refused,
    /// The target authority is not acceptable.
    Invalid,
    Timeout,
}
impl fmt::Display for OpenError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Connection(reason) => write!(f, "connection failed: {reason}"),
            Self::Status(status) => write!(f, "server refused the tunnel (HTTP {status})"),
            Self::Confirmation => f.write_str("server confirmation missing or invalid"),
            Self::Refused => f.write_str("connection did not meet ECH/TLS requirements"),
            Self::Invalid => f.write_str("invalid target"),
            Self::Timeout => f.write_str("tunnel setup timed out"),
        }
    }
}
impl std::error::Error for OpenError {}

/// CONNECT request fields signed by the Rupin proof.
pub fn connect_context<'a>(binding: &'a Binding, authority: &'a str) -> Context<'a> {
    Context {
        binding,
        method: "CONNECT",
        authority,
        scheme: None,
        path: None,
        protocol: None,
    }
}
pub fn authorization(credentials: &Credentials, binding: &Binding, authority: &str) -> String {
    credentials
        .authorization_with(0, &connect_context(binding, authority), offer())
        .expect("principal 0 exists")
}
/// Verify status 200 plus exactly one valid confirmation before any payload.
pub fn confirm(
    credentials: &Credentials,
    binding: &Binding,
    authority: &str,
    status: u16,
    confirmations: &[&str],
) -> Result<Mode, OpenError> {
    if status != 200 {
        return Err(OpenError::Status(status));
    }
    let [value] = confirmations else {
        return Err(OpenError::Confirmation);
    };
    credentials
        .verify_selection(0, &connect_context(binding, authority), offer(), value)
        .ok_or(OpenError::Confirmation)
}

/// Upload-side framing. Padding is sampled uniformly within the limit the
/// codec permits for each record; header overhead and padding are bounded by
/// the Rupin rules in `moon_naive_core::codec`.
pub struct Framer {
    encoder: Encoder,
}
impl Framer {
    pub fn new(mode: Mode) -> Self {
        Self {
            encoder: Encoder::new(mode),
        }
    }
    pub fn frame(&mut self, payload: &[u8]) -> Result<Vec<u8>, &'static str> {
        debug_assert!(!payload.is_empty() && payload.len() <= MAX_PAYLOAD);
        let limit = self.encoder.padding_limit(payload.len());
        let padding = if limit == 0 {
            0
        } else {
            let mut byte = [0u8; 1];
            getrandom::fill(&mut byte).map_err(|_| "random source unavailable")?;
            byte[0] % (limit + 1)
        };
        self.encoder.encode(payload, padding)
    }
}
/// Largest local read that maps to exactly one record.
pub const READ_CHUNK: usize = MAX_PAYLOAD;

/// Download-side decoding with truncation detection at EOF.
pub struct Unframer {
    decoder: Decoder,
    out: Vec<u8>,
}
impl Unframer {
    pub fn new(mode: Mode) -> Self {
        Self {
            decoder: Decoder::new(mode),
            out: Vec::new(),
        }
    }
    pub fn feed(&mut self, input: &[u8]) -> Result<&[u8], &'static str> {
        self.out.clear();
        self.decoder.feed_into(input, &mut self.out)?;
        Ok(&self.out)
    }
    pub fn finish(&self) -> Result<(), &'static str> {
        self.decoder.finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn framing_round_trips_in_every_negotiable_mode() {
        for bits in [0x01, 0x02, 0x05, 0x06] {
            let mode = Mode::from_bits(bits).unwrap();
            let mut framer = Framer::new(mode);
            let mut unframer = Unframer::new(mode);
            let mut sent = Vec::new();
            let mut received = Vec::new();
            for size in [1usize, 7, 100, 1000, READ_CHUNK, 3, 64, 9000, 1, 2] {
                for _ in 0..3 {
                    let payload: Vec<u8> = (0..size).map(|i| (i * 31 + size) as u8).collect();
                    sent.extend_from_slice(&payload);
                    let wire = framer.frame(&payload).unwrap();
                    // Deliver in awkward fragments to exercise partial state.
                    for piece in wire.chunks(5) {
                        received.extend_from_slice(unframer.feed(piece).unwrap());
                    }
                }
            }
            unframer.finish().unwrap();
            assert_eq!(sent, received, "mode {bits:#x}");
        }
    }
    #[test]
    fn truncated_record_is_detected_at_eof() {
        let mode = Mode::from_bits(0x02).unwrap();
        let wire = Framer::new(mode).frame(b"hello").unwrap();
        let mut unframer = Unframer::new(mode);
        unframer.feed(&wire[..wire.len() - 1]).unwrap();
        assert!(unframer.finish().is_err());
    }
    #[test]
    fn confirmation_requires_status_uniqueness_and_valid_mac() {
        let credentials = Credentials::new(&[("alice", "a-long-high-entropy-secret")]).unwrap();
        let binding = Binding {
            exporter: [7; 32],
            stream_id: 5,
        };
        let mode = Mode::from_bits(0x06).unwrap();
        let good = credentials
            .confirmation_with(
                0,
                &connect_context(&binding, "example.org:443"),
                offer(),
                mode,
            )
            .unwrap();
        let ok = confirm(&credentials, &binding, "example.org:443", 200, &[&good]).unwrap();
        assert_eq!(ok, mode);
        assert!(matches!(
            confirm(&credentials, &binding, "example.org:443", 403, &[&good]),
            Err(OpenError::Status(403))
        ));
        assert!(confirm(&credentials, &binding, "example.org:443", 200, &[]).is_err());
        assert!(
            confirm(
                &credentials,
                &binding,
                "example.org:443",
                200,
                &[&good, &good]
            )
            .is_err()
        );
        // Reflected request proofs and other streams/targets never confirm.
        let proof = authorization(&credentials, &binding, "example.org:443");
        assert!(confirm(&credentials, &binding, "example.org:443", 200, &[&proof]).is_err());
        assert!(confirm(&credentials, &binding, "example.net:443", 200, &[&good]).is_err());
        let other = Binding {
            stream_id: 9,
            ..binding
        };
        assert!(confirm(&credentials, &other, "example.org:443", 200, &[&good]).is_err());
    }
}
