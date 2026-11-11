//! Negotiated finite initial padding, with optional budgeted sparse records.
//! App records do not define HTTP frames, TLS records or physical packet sizes.
pub const HEADER: usize = 3;
pub const MAX_PADDING: usize = 63;
pub const MAX_WIRE: usize = 16 * 1024 - 9;
pub const MAX_PAYLOAD: usize = MAX_WIRE - HEADER - MAX_PADDING;
pub const CREDIT_CAP: usize = 128;
const RATIO: usize = 128;

/// Bits: 1 = initial 8; 2 = initial 16; 4 = sparse tail.
/// No cover/control records or unrecognized bits are accepted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Offer(u8);
impl Default for Offer {
    fn default() -> Self {
        Self(2)
    }
}
impl Offer {
    pub fn from_bits(bits: u8) -> Result<Self, &'static str> {
        if bits & !7 != 0 || bits & 3 == 0 {
            return Err("invalid moon-naive offer");
        }
        Ok(Self(bits))
    }
    pub fn bits(self) -> u8 {
        self.0
    }
    pub fn select(self, preferred: u8, sparse: bool) -> Mode {
        let wanted = if preferred == 8 { 1 } else { 2 };
        let initial = if self.0 & wanted != 0 {
            wanted
        } else {
            self.0 & 3
        };
        let tail = if sparse { self.0 & 4 } else { 0 };
        Mode(initial | tail)
    }
    pub fn accepts(self, mode: Mode) -> bool {
        mode.0 & self.0 == mode.0
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Mode(u8);
impl Default for Mode {
    fn default() -> Self {
        Self(2)
    }
}
impl Mode {
    pub fn from_bits(bits: u8) -> Result<Self, &'static str> {
        Offer::from_bits(bits)?;
        if !matches!(bits & 3, 1 | 2) {
            return Err("select exactly one initial window");
        }
        Ok(Self(bits))
    }
    pub fn bits(self) -> u8 {
        self.0
    }
    pub fn initial(self) -> u8 {
        if self.0 & 1 != 0 { 8 } else { 16 }
    }
    pub fn sparse(self) -> bool {
        self.0 & 4 != 0
    }
}
pub fn padding_limit(completed: u8, payload: usize) -> u8 {
    limit(Mode::default(), completed, payload)
}
fn limit(mode: Mode, completed: u8, payload: usize) -> u8 {
    if completed < mode.initial() {
        ((63 - usize::from(completed) * (64 / usize::from(mode.initial()))).min(payload / 8)) as u8
    } else if mode.sparse() && payload < 8192 {
        31.min(payload / 32) as u8
    } else {
        0
    }
}
#[derive(Default)]
struct State {
    mode: Mode,
    records: u8,
    credit: usize,
}
impl State {
    fn new(mode: Mode) -> Self {
        Self {
            mode,
            ..Self::default()
        }
    }
    fn is_raw(&self) -> bool {
        self.records == self.mode.initial() && !self.mode.sparse()
    }
    fn limit(&self, payload: usize) -> u8 {
        let max = limit(self.mode, self.records, payload);
        if self.records < self.mode.initial() {
            max
        } else {
            usize::from(max).min((self.credit + payload).min(CREDIT_CAP * RATIO) / RATIO) as u8
        }
    }
    fn data(&mut self, payload: usize, padding: u8) -> Result<(), &'static str> {
        if payload == 0 || payload > MAX_PAYLOAD || padding > self.limit(payload) {
            return Err("invalid moon-naive record length/budget");
        }
        self.credit = (self.credit + payload).min(CREDIT_CAP * RATIO);
        if self.records >= self.mode.initial() {
            self.credit -= usize::from(padding) * RATIO;
        }
        Ok(())
    }
    fn complete(&mut self) {
        self.records = (self.records + 1).min(self.mode.initial());
    }
}
#[derive(Default)]
pub struct Encoder {
    state: State,
}
impl Encoder {
    pub fn new(mode: Mode) -> Self {
        Self {
            state: State::new(mode),
        }
    }
    pub fn is_raw(&self) -> bool {
        self.state.is_raw()
    }
    pub fn is_initial(&self) -> bool {
        self.state.records < self.state.mode.initial()
    }
    pub fn padding_limit(&self, payload: usize) -> u8 {
        self.state.limit(payload)
    }
    pub fn header(
        &mut self,
        payload: usize,
        padding: u8,
    ) -> Result<Option<[u8; HEADER]>, &'static str> {
        if self.is_raw() {
            if padding != 0 {
                return Err("padding after finite records");
            }
            return Ok(None);
        }
        self.state.data(payload, padding)?;
        let [a, b] = (payload as u16).to_be_bytes();
        self.state.complete();
        Ok(Some([a, b, padding]))
    }
    pub fn encode(&mut self, payload: &[u8], padding: u8) -> Result<Vec<u8>, &'static str> {
        let header = self.header(payload.len(), padding)?;
        let mut out =
            Vec::with_capacity(header.map_or(0, |_| HEADER) + payload.len() + usize::from(padding));
        if let Some(header) = header {
            out.extend_from_slice(&header);
        }
        out.extend_from_slice(payload);
        out.resize(out.len() + usize::from(padding), 0);
        Ok(out)
    }
}
#[derive(Default)]
pub struct Decoder {
    state: State,
    header: [u8; HEADER],
    used: usize,
    payload_left: usize,
    padding_left: usize,
    failed: bool,
}
impl Decoder {
    pub fn new(mode: Mode) -> Self {
        Self {
            state: State::new(mode),
            ..Self::default()
        }
    }
    pub fn is_raw(&self) -> bool {
        self.state.is_raw()
    }
    fn complete(&mut self) {
        self.used = 0;
        self.state.complete();
    }
    /// Borrow from the transport input without payload allocation/copy.
    pub fn decode_slice<'a>(&mut self, input: &'a [u8]) -> Result<(usize, &'a [u8]), &'static str> {
        if self.failed {
            return Err("failed moon-naive decoder");
        }
        let mut at = 0;
        while at < input.len() {
            if self.is_raw() {
                return Ok((input.len(), &input[at..]));
            }
            if self.used < HEADER {
                let n = (HEADER - self.used).min(input.len() - at);
                self.header[self.used..self.used + n].copy_from_slice(&input[at..at + n]);
                self.used += n;
                at += n;
                if self.used < HEADER {
                    break;
                }
                let length = u16::from_be_bytes([self.header[0], self.header[1]]);
                self.payload_left = usize::from(length);
                self.padding_left = usize::from(self.header[2]);
                let checked = self.state.data(self.payload_left, self.header[2]);
                if let Err(error) = checked {
                    self.failed = true;
                    return Err(error);
                }
            }
            if self.payload_left != 0 {
                let n = self.payload_left.min(input.len() - at);
                if n == 0 {
                    break;
                }
                self.payload_left -= n;
                if self.payload_left == 0 && self.padding_left == 0 {
                    self.complete();
                }
                return Ok((at + n, &input[at..at + n]));
            }
            let n = self.padding_left.min(input.len() - at);
            self.padding_left -= n;
            at += n;
            if self.padding_left != 0 {
                break;
            }
            self.complete();
        }
        Ok((at, &input[at..at]))
    }
    pub fn feed(&mut self, input: &[u8]) -> Result<Vec<u8>, &'static str> {
        let mut out = Vec::with_capacity(input.len());
        self.feed_into(input, &mut out)?;
        Ok(out)
    }
    pub fn feed_into(&mut self, mut input: &[u8], out: &mut Vec<u8>) -> Result<(), &'static str> {
        while !input.is_empty() {
            let (consumed, payload) = self.decode_slice(input)?;
            debug_assert!(consumed > 0);
            out.extend_from_slice(payload);
            input = &input[consumed..];
        }
        if self.failed {
            return Err("failed moon-naive decoder");
        }
        Ok(())
    }
    pub fn finish(&self) -> Result<(), &'static str> {
        if self.failed || self.used != 0 {
            Err("truncated or invalid moon-naive record")
        } else {
            Ok(())
        }
    }
    pub fn records(&self) -> u8 {
        self.state.records
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn independent_vector_all_splits_and_raw_tail_in_same_input() {
        let record = [0, 8, 1, b'a', b'b', b'c', b'd', b'e', b'f', b'g', b'h', 77];
        let mut wire = record.repeat(16);
        // These bytes would be invalid as a record; they must survive verbatim.
        let raw = [0, 0, 255, 1, 2, 3, 4, 0];
        wire.extend(raw);
        let mut expected = b"abcdefgh".repeat(16);
        expected.extend(raw);
        for chunk in 1..=wire.len() {
            let mut d = Decoder::default();
            let mut out = Vec::new();
            for part in wire.chunks(chunk) {
                d.feed_into(part, &mut out).unwrap();
            }
            assert_eq!(out, expected);
            assert!(d.is_raw());
            assert_eq!(d.records(), 16);
            d.finish().unwrap();
        }
        let mut e = Encoder::default();
        for _ in 0..16 {
            let frame = e.encode(b"abcdefgh", 1).unwrap();
            assert_eq!(&frame[..11], &record[..11]);
            assert_eq!(frame[11], 0);
        }
        assert_eq!(e.encode(&raw, 0).unwrap(), raw);
        assert!(e.encode(b"x", 1).is_err());
    }
    #[test]
    fn malformed_truncated_and_excessive_padding_fail_closed() {
        for bad in [[0, 0, 0], [0, 8, 2], [1, 255, 64], [255, 255, 0]] {
            let mut d = Decoder::default();
            assert!(d.feed(&bad).is_err());
            assert!(d.feed(&[0, 1, 0, b'x']).is_err());
            assert!(d.finish().is_err());
        }
        let wire = [0, 8, 1, b'a', b'b', b'c', b'd', b'e', b'f', b'g', b'h', 0];
        for cut in 1..wire.len() {
            let mut d = Decoder::default();
            d.feed(&wire[..cut]).unwrap();
            assert!(d.finish().is_err());
        }
        let mut d = Decoder::default();
        d.feed(&wire.repeat(15)).unwrap();
        assert!(d.feed(&[0, 255, 4]).is_err()); // Last record permits at most three.
        Decoder::default().finish().unwrap(); // Empty stream needs no marker.
    }
    #[test]
    fn initial_budget_tapers_and_borrowed_payload_has_no_copy() {
        let mut e = Encoder::default();
        let mut d = Decoder::default();
        let payload = vec![7; MAX_PAYLOAD];
        let mut extra = 0;
        for i in 0..16 {
            let limit = e.padding_limit(payload.len());
            assert_eq!(limit, 63 - i * 4);
            let wire = e.encode(&payload, limit).unwrap();
            extra += wire.len() - payload.len();
            assert!(wire.len() <= MAX_WIRE);
            let (used, data) = d.decode_slice(&wire).unwrap();
            assert_eq!(data.as_ptr(), wire[HEADER..].as_ptr());
            assert_eq!(data, payload);
            d.feed(&wire[used..]).unwrap();
        }
        assert_eq!(extra, 576);
        let raw = [0, 0, 0, 255];
        let (used, data) = d.decode_slice(&raw).unwrap();
        assert_eq!(used, raw.len());
        assert_eq!(data.as_ptr(), raw.as_ptr());
        for n in 1..248 {
            assert!(usize::from(padding_limit(0, n)) <= n / 8);
        }
        assert!(
            Encoder::default()
                .encode(&vec![0; MAX_PAYLOAD + 1], 0)
                .is_err()
        );
        assert!(Encoder::default().encode(b"", 0).is_err());
    }
}

#[cfg(test)]
mod negotiated_tests {
    use super::*;
    #[test]
    fn finite_sixteen_client_offer_is_supported_by_every_server_preference() {
        let offer = Offer::from_bits(0x02).unwrap();
        for initial in [8, 16] {
            for sparse in [false, true] {
                let selected = offer.select(initial, sparse);
                assert_eq!(selected.bits(), 0x02);
                assert!(offer.accepts(selected));
            }
        }
    }

    // A new stream (or the other direction) must not inherit the connection's
    // earlier traffic counters, negotiated mode, or earned sparse credit.
    #[test]
    fn late_streams_and_directions_have_independent_padding_state() {
        let payload = [7; 1024];
        for bits in [1, 2, 5, 6] {
            let mode = Mode::from_bits(bits).unwrap();
            let mut busy = Encoder::new(mode);
            let mut busy_decoder = Decoder::new(mode);
            for _ in 0..64 {
                let wire = busy.encode(&payload, 0).unwrap();
                assert_eq!(busy_decoder.feed(&wire).unwrap(), payload);
            }
            let mut late = Encoder::new(mode);
            let mut reverse = Decoder::new(mode);
            assert!(late.is_initial());
            assert_eq!(late.padding_limit(payload.len()), 63);
            let wire = late.encode(&payload, 63).unwrap();
            assert_eq!(&wire[..3], &[4, 0, 63]);
            assert_eq!(reverse.feed(&wire).unwrap(), payload);
            // Independent framing windows remain intact after the interleave.
            assert_eq!(busy.is_raw(), !mode.sparse());
            assert_eq!(busy_decoder.is_raw(), !mode.sparse());
            assert!(!reverse.is_raw());
            reverse.finish().unwrap();
            if mode.sparse() {
                let mut small = Encoder::new(mode);
                for _ in 0..mode.initial() {
                    small.encode(b"x", 0).unwrap();
                }
                // A lightly used stream cannot spend the busy stream's credit.
                assert_eq!(small.padding_limit(32), 0);
                assert!(busy.padding_limit(32) > 0);
            }
        }
    }

    #[test]
    fn windows_fragmentation_and_sparse_budgets() {
        for bits in [1, 2, 5, 6] {
            let mode = Mode::from_bits(bits).unwrap();
            let mut encoder = Encoder::new(mode);
            let mut wire = Vec::new();
            let mut expected = Vec::new();
            for i in 0..40 {
                let p = vec![i; 1024];
                expected.extend(&p);
                wire.extend(encoder.encode(&p, encoder.padding_limit(p.len())).unwrap());
            }
            for chunk in [1, 2, 3, 17, 1024, wire.len()] {
                let mut decoder = Decoder::new(mode);
                let mut result = Vec::new();
                for part in wire.chunks(chunk) {
                    decoder.feed_into(part, &mut result).unwrap();
                }
                decoder.finish().unwrap();
                assert_eq!(result, expected);
                assert_eq!(decoder.is_raw(), !mode.sparse());
            }
        }
        for bits in [0, 8, 9, 13, 15, 255] {
            assert!(Offer::from_bits(bits).is_err());
        }
        for bits in 1..=7 {
            if let Ok(offer) = Offer::from_bits(bits) {
                for n in [8, 16] {
                    for sparse in [false, true] {
                        assert!(offer.accepts(offer.select(n, sparse)));
                    }
                }
            }
        }
        let mode = Mode::from_bits(6).unwrap();
        let mut encoder = Encoder::new(mode);
        for _ in 0..16 {
            encoder.encode(b"x", 0).unwrap();
        }
        assert_eq!(encoder.padding_limit(32), 0);
        assert!(encoder.encode(&[0; 32], 1).is_err());
        assert_eq!(encoder.padding_limit(8192), 0);
        let mut decoder = Decoder::new(mode);
        assert!(decoder.feed(&[0x81, 0, 0]).is_err());
    }
}
