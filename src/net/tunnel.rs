//! One idle deadline for the entire duplex tunnel. Progress in either direction
//! keeps it alive; stalled writes still backpressure their own bounded queue.
use super::{CHUNK, Result};
use bytes::{BufMut, Bytes, BytesMut};
use std::{
    future::Future,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    time::Instant,
};

#[derive(Clone)]
pub(super) struct Activity(Arc<Progress>);
struct Progress {
    epoch: Instant,
    nanos: AtomicU64,
}

impl Activity {
    pub fn new() -> Self {
        Self(Arc::new(Progress {
            epoch: Instant::now(),
            nanos: AtomicU64::new(0),
        }))
    }
    pub fn touch(&self) {
        // Timestamp only: no data publication and no per-record timer wakeup.
        // Concurrent readers/writers must never move the deadline backwards.
        let nanos = self.0.epoch.elapsed().as_nanos().min(u64::MAX as u128) as u64;
        self.0.nanos.fetch_max(nanos, Ordering::Relaxed);
    }
    fn last(&self) -> Instant {
        self.0.epoch + Duration::from_nanos(self.0.nanos.load(Ordering::Relaxed))
    }
    pub fn is_idle(&self, idle: Duration) -> bool {
        self.last().elapsed() >= idle
    }
    pub fn deadline(&self, idle: Duration) -> Instant {
        self.last() + idle
    }
    async fn expired(&self, idle: Duration) {
        loop {
            // Progress can only extend this deadline. Recheck when it arrives,
            // without waking/resetting this timer on each read or write.
            tokio::time::sleep_until(self.deadline(idle)).await;
            if self.is_idle(idle) {
                return;
            }
        }
    }
    pub async fn run<T>(&self, idle: Duration, work: impl Future<Output = Result<T>>) -> Result<T> {
        tokio::select! {
            result = work => result,
            _ = self.expired(idle) => Err("tunnel idle deadline".into()),
        }
    }
    pub async fn write_all(
        &self,
        writer: &mut (impl AsyncWrite + Unpin),
        mut bytes: &[u8],
    ) -> Result<()> {
        while !bytes.is_empty() {
            let n = writer.write(bytes).await?;
            if n == 0 {
                return Err("target write returned zero".into());
            }
            self.touch();
            bytes = &bytes[n..];
        }
        Ok(())
    }
}

// Negotiated framing; website WebSockets are raw from the start.
use moon_naive_core::codec::{Encoder, HEADER, MAX_PAYLOAD, MAX_WIRE, Mode};
pub(super) struct TunnelDownload {
    encoder: Option<Encoder>,
    entropy: [u8; 32],
    entropy_used: usize,
    buffer: BytesMut,
}
impl TunnelDownload {
    pub(super) fn new(framed: Option<Mode>) -> Result<Self> {
        Ok(Self {
            encoder: framed.map(Encoder::new),
            entropy: [0; 32],
            entropy_used: 32,
            buffer: BytesMut::with_capacity(CHUNK),
        })
    }
    fn read_capacity(&self) -> usize {
        if self.encoder.is_some() {
            MAX_PAYLOAD
        } else {
            // Leave room for the H2 DATA header inside a 16 KiB TLS write.
            // Reading 16 KiB of raw payload forces a 9-byte spill even with
            // vectored-write coalescing. No wait, dummy bytes or protocol change.
            MAX_WIRE
        }
    }
    /// Uniform in a small bounded range without modulo bias. No entropy is
    /// consumed for tiny payloads with limit zero, empty reads or the raw tail.
    fn padding(&mut self, limit: u8) -> Result<u8> {
        if limit == 0 {
            return Ok(0);
        }
        let range = u16::from(limit) + 1;
        let ceiling = 256 - 256 % range;
        loop {
            if self.entropy_used == self.entropy.len() {
                boring::rand::rand_bytes(&mut self.entropy)?;
                self.entropy_used = 0;
            }
            let value = u16::from(self.entropy[self.entropy_used]);
            self.entropy_used += 1;
            if value < ceiling {
                return Ok((value % range) as u8);
            }
        }
    }
    /// Direct read into owned storage. No wait-to-fill, timer or tail marker.
    pub(super) async fn read_next(
        &mut self,
        reader: &mut (impl AsyncRead + Unpin),
    ) -> Result<Option<Bytes>> {
        self.buffer.clear();
        self.buffer.reserve(CHUNK);
        if self.encoder.is_some() {
            self.buffer.extend_from_slice(&[0; HEADER]);
        }
        let capacity = self.read_capacity();
        let n = reader
            .read_buf(&mut (&mut self.buffer).limit(capacity))
            .await?;
        if n == 0 {
            self.buffer.clear();
            return Ok(None);
        }
        if let Some(encoder) = &self.encoder {
            let limit = encoder.padding_limit(n);
            let initial = encoder.is_initial();
            let padding = if n >= 8192 || limit == 0 || (!initial && self.padding(15)? != 0) {
                0
            } else {
                self.padding(limit)?
            };
            let encoder = self.encoder.as_mut().expect("initial encoder");
            let header = encoder.header(n, padding)?.expect("initial record");
            self.buffer[..HEADER].copy_from_slice(&header);
            self.buffer.resize(HEADER + n + usize::from(padding), 0);
            if encoder.is_raw() {
                self.encoder = None;
            }
        }
        Ok(Some(self.buffer.split().freeze()))
    }
}
/// Borrow payload slices from the transport input instead of collecting a Vec.
/// Finite modes drop parser state after the initial window; sparse modes retain it.
pub(super) struct TunnelDecoder {
    decoder: Option<moon_naive_core::codec::Decoder>,
}
impl TunnelDecoder {
    pub(super) fn new(framed: Option<Mode>) -> Self {
        Self {
            decoder: framed.map(moon_naive_core::codec::Decoder::new),
        }
    }
    pub(super) async fn write_to(
        &mut self,
        writer: &mut (impl tokio::io::AsyncWrite + Unpin),
        mut data: &[u8],
        activity: &Activity,
    ) -> Result<()> {
        while !data.is_empty() {
            let Some(decoder) = &mut self.decoder else {
                return activity.write_all(writer, data).await;
            };
            let (consumed, payload) = decoder.decode_slice(data)?;
            debug_assert!(consumed > 0);
            activity.write_all(writer, payload).await?;
            data = &data[consumed..];
            if decoder.is_raw() {
                self.decoder = None;
            }
        }
        Ok(())
    }
    pub(super) fn finish(&self) -> Result<()> {
        if let Some(decoder) = &self.decoder {
            decoder.finish()?;
        }
        Ok(())
    }
}
