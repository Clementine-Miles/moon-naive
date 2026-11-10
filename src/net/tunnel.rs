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

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(start_paused = true)]
    async fn long_lived_activity_deadline_tracks_progress_then_expires() {
        let activity = Activity::new();
        let idle = Duration::from_secs(600);
        for _ in 0..288 {
            // 24 simulated hours, never a wall-clock soak claim.
            tokio::time::advance(Duration::from_secs(300)).await;
            assert!(!activity.is_idle(idle));
            activity.touch();
            assert_eq!(activity.deadline(idle), Instant::now() + idle);
        }
        tokio::time::advance(idle).await;
        assert!(activity.is_idle(idle));
        assert_eq!(activity.deadline(idle), Instant::now());
    }

    #[tokio::test(start_paused = true)]
    async fn silent_tunnel_expires_at_deadline() {
        let activity = Activity::new();
        let start = Instant::now();
        assert!(
            activity
                .run(Duration::from_secs(5), std::future::pending::<Result<()>>())
                .await
                .is_err()
        );
        assert_eq!(start.elapsed(), Duration::from_secs(5));
    }

    #[tokio::test(start_paused = true)]
    async fn progress_does_not_wake_an_armed_idle_timer() {
        use std::{
            sync::atomic::AtomicUsize,
            task::{Context, Wake, Waker},
        };
        #[derive(Default)]
        struct Count(AtomicUsize);
        impl Wake for Count {
            fn wake(self: Arc<Self>) {
                self.0.fetch_add(1, Ordering::Relaxed);
            }
            fn wake_by_ref(self: &Arc<Self>) {
                self.0.fetch_add(1, Ordering::Relaxed);
            }
        }
        let activity = Activity::new();
        let count = Arc::new(Count::default());
        let waker = Waker::from(count.clone());
        let mut cx = Context::from_waker(&waker);
        let mut expiry = Box::pin(activity.expired(Duration::from_secs(5)));
        assert!(expiry.as_mut().poll(&mut cx).is_pending());
        tokio::time::advance(Duration::from_secs(1)).await;
        for _ in 0..100 {
            activity.touch();
        }
        assert_eq!(count.0.load(Ordering::Relaxed), 0);
        drop(expiry);
        tokio::time::advance(Duration::from_secs(10)).await;
        assert_eq!(count.0.load(Ordering::Relaxed), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn either_direction_extends_idle_without_waking_timer_on_progress() {
        let activity = Activity::new();
        let other = activity.clone();
        let task = tokio::spawn(async move {
            other
                .run(Duration::from_secs(5), std::future::pending::<Result<()>>())
                .await
        });
        tokio::task::yield_now().await;
        for step in 0..4 {
            tokio::time::advance(Duration::from_secs(4)).await;
            if step % 2 == 0 {
                activity.clone().touch();
            } else {
                activity
                    .write_all(&mut tokio::io::sink(), b"progress")
                    .await
                    .unwrap();
            }
            tokio::task::yield_now().await;
            assert!(!task.is_finished());
        }
        tokio::time::advance(Duration::from_secs(4)).await;
        tokio::task::yield_now().await;
        assert!(!task.is_finished());
        tokio::time::advance(Duration::from_secs(1)).await;
        assert!(task.await.unwrap().is_err());
    }

    /// Same clock and one live observer; reports median ns/update, not bandwidth.
    #[test]
    #[ignore = "release microbenchmark; run separately with --nocapture --test-threads=1"]
    fn benchmark_activity_updates() {
        let legacy = tokio::sync::watch::channel(Instant::now());
        let activity = Activity::new();
        let mut old = Vec::new();
        let mut new = Vec::new();
        const N: u32 = 200_000;
        for _ in 0..9 {
            let start = std::time::Instant::now();
            for _ in 0..N {
                std::hint::black_box(legacy.0.send_replace(Instant::now()));
            }
            old.push(start.elapsed() / N);
            let start = std::time::Instant::now();
            for _ in 0..N {
                std::hint::black_box(&activity).touch();
            }
            new.push(start.elapsed() / N);
        }
        old.sort();
        new.sort();
        eprintln!(
            "activity: old_watch={:?}/update new_atomic={:?}/update (median, n={N}, batches=9)",
            old[4], new[4]
        );
        std::hint::black_box(legacy.1);
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
#[cfg(test)]
mod framing_tests {
    use super::*;
    #[tokio::test]
    async fn initial_records_are_bounded_then_raw_without_further_entropy() {
        for framed in [false, true] {
            let mut download = TunnelDownload::new(framed.then(Mode::default)).unwrap();
            let mut decoder = moon_naive_core::codec::Decoder::default();
            let mut entropy_at_cutoff = None;
            let mut overhead = 0;
            for i in 0..80 {
                let payload = vec![
                    i;
                    if i % 2 == 0 {
                        download.read_capacity()
                    } else {
                        17
                    }
                ];
                let wire = download
                    .read_next(&mut payload.as_slice())
                    .await
                    .unwrap()
                    .unwrap();
                if framed {
                    if i < 16 {
                        overhead += wire.len() - payload.len();
                        assert!(
                            usize::from(wire[2])
                                <= usize::from(moon_naive_core::codec::padding_limit(
                                    i,
                                    payload.len()
                                ))
                        );
                    } else {
                        assert_eq!(wire.as_ref(), payload);
                        assert_eq!(Some(download.entropy_used), entropy_at_cutoff);
                    }
                    assert_eq!(decoder.feed(&wire).unwrap(), payload);
                } else {
                    assert_eq!(wire.as_ref(), payload);
                    assert_eq!(download.entropy_used, 32);
                }
                if i == 15 {
                    entropy_at_cutoff = Some(download.entropy_used);
                    assert!(download.encoder.is_none());
                }
            }
            assert!(overhead <= 576);
            decoder.finish().unwrap();
            if framed {
                assert_eq!(decoder.records(), 16);
            }
        }
    }
    #[tokio::test]
    async fn cancelled_empty_and_tiny_reads_do_not_consume_entropy() {
        let mut download = TunnelDownload::new(Some(Mode::default())).unwrap();
        let (mut input, mut output) = tokio::io::duplex(64);
        assert!(
            tokio::time::timeout(Duration::from_millis(5), download.read_next(&mut input))
                .await
                .is_err()
        );
        assert!(download.encoder.is_some());
        assert_eq!(download.entropy_used, 32);
        output.write_all(b"hello").await.unwrap();
        output.shutdown().await.unwrap();
        let wire = download.read_next(&mut input).await.unwrap().unwrap();
        assert_eq!(&wire[..], b"\0\x05\0hello");
        assert_eq!(download.entropy_used, 32); // floor(5 / 8) == 0
        assert!(download.read_next(&mut input).await.unwrap().is_none());
        assert_eq!(download.entropy_used, 32);
    }
    #[tokio::test]
    async fn read_storage_transferred_retained_chunks_immutable_and_bad_upload_fails() {
        use std::{
            pin::Pin,
            task::{Context, Poll},
        };
        struct Probe {
            pointer: usize,
        }
        impl AsyncRead for Probe {
            fn poll_read(
                mut self: Pin<&mut Self>,
                _: &mut Context<'_>,
                buf: &mut tokio::io::ReadBuf<'_>,
            ) -> Poll<std::io::Result<()>> {
                self.pointer = buf.initialize_unfilled().as_ptr() as usize;
                buf.put_slice(b"payload");
                Poll::Ready(Ok(()))
            }
        }
        for framed in [false, true] {
            let mut download = TunnelDownload::new(framed.then(Mode::default)).unwrap();
            let mut reader = Probe { pointer: 0 };
            let first = download.read_next(&mut reader).await.unwrap().unwrap();
            assert_eq!(
                first[if framed { HEADER } else { 0 }..].as_ptr() as usize,
                reader.pointer
            );
            let saved = first.to_vec();
            for _ in 0..40 {
                download.read_next(&mut reader).await.unwrap();
            }
            assert_eq!(first.as_ref(), saved);
        }
        let mut decoder = TunnelDecoder::new(Some(Mode::default()));
        assert!(
            decoder
                .write_to(&mut tokio::io::sink(), &[0, 0, 0], &Activity::new())
                .await
                .is_err()
        );
        assert!(decoder.finish().is_err());
    }
    #[tokio::test]
    async fn upload_crosses_padding_boundary_and_releases_parser_without_copying() {
        let mut wire = b"\0\x08\x01abcdefgh\0".repeat(16);
        wire.extend_from_slice(b"\0\0\0raw bytes");
        let mut decoder = TunnelDecoder::new(Some(Mode::default()));
        let mut out = Vec::new();
        decoder
            .write_to(&mut out, &wire, &Activity::new())
            .await
            .unwrap();
        assert!(decoder.decoder.is_none());
        assert_eq!(&out[..128], b"abcdefgh".repeat(16));
        assert_eq!(&out[128..], b"\0\0\0raw bytes");
        decoder.finish().unwrap();
    }
}

#[cfg(test)]
mod sparse_tests {
    use super::*;
    #[tokio::test]
    async fn dense_reads_use_no_padding_rng_and_sparse_payload_remains_exact() {
        let mode = Mode::from_bits(6).unwrap();
        let mut download = TunnelDownload::new(Some(mode)).unwrap();
        let mut decoder = moon_naive_core::codec::Decoder::new(mode);
        for _ in 0..40 {
            let payload = vec![1; MAX_PAYLOAD];
            let wire = download
                .read_next(&mut payload.as_slice())
                .await
                .unwrap()
                .unwrap();
            assert_eq!(wire.len(), MAX_PAYLOAD + HEADER);
            assert_eq!(wire[2], 0);
            assert_eq!(decoder.feed(&wire).unwrap(), payload);
        }
        assert_eq!(download.entropy_used, 32);
        download.entropy.fill(0);
        download.entropy[1] = 31;
        download.entropy_used = 0;
        let wire = download
            .read_next(&mut vec![2; 1024].as_slice())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(wire[2], 31);
        assert!(wire[HEADER + 1024..].iter().all(|b| *b == 0));
        assert_eq!(decoder.feed(&wire).unwrap(), vec![2; 1024]);
        decoder.finish().unwrap();
    }
}
