//! Endpoint-wide wire-byte pacing. This is separate from HTTP/QUIC flow control.
//! Each direction has one shared token bucket across TCP connections and QUIC
//! packets, with at most 16 KiB initial/idle burst. Pending or cancelled IO does
//! not consume credit. UDP callers use the returned deadline in their scheduler;
//! they must not sleep inside the connection/stream driver.
use std::{
    fmt,
    future::Future,
    io,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll},
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    time::Sleep,
};

pub(super) const BURST: usize = 16 * 1024;
const UNIT: u128 = 1_000_000_000;
#[derive(Clone, Copy)]
pub(super) enum Direction {
    Upload,
    Download,
}
impl Direction {
    fn index(self) -> usize {
        match self {
            Self::Upload => 0,
            Self::Download => 1,
        }
    }
}
struct Bucket {
    credit: u128,
    updated: Instant,
}
pub(super) struct Rate {
    bytes_per_second: Option<u64>,
    buckets: Mutex<[Bucket; 2]>,
}
impl Rate {
    pub fn new(bytes_per_second: Option<u64>) -> Result<Arc<Self>, &'static str> {
        if bytes_per_second == Some(0) {
            return Err("bandwidth rate must be positive");
        }
        let now = tokio::time::Instant::now().into_std();
        Ok(Arc::new(Self {
            bytes_per_second,
            buckets: Mutex::new([
                Bucket {
                    credit: BURST as u128 * UNIT,
                    updated: now,
                },
                Bucket {
                    credit: BURST as u128 * UNIT,
                    updated: now,
                },
            ]),
        }))
    }
    /// Reserve exactly one bounded wire packet. Dropping the grant refunds all
    /// bytes; call commit only with the count actually accepted by the socket.
    pub fn try_reserve(
        self: &Arc<Self>,
        direction: Direction,
        bytes: usize,
        now: Instant,
    ) -> Result<Grant, Instant> {
        self.reserve(direction, bytes, true, now)
    }
    fn reserve(
        self: &Arc<Self>,
        direction: Direction,
        wanted: usize,
        exact: bool,
        now: Instant,
    ) -> Result<Grant, Instant> {
        let Some(rate) = self.bytes_per_second else {
            return Ok(Grant {
                rate: None,
                direction,
                reserved: wanted,
            });
        };
        // A received UDP datagram is untrusted and can exceed the supported
        // quantum. Deny it without panicking; transmit callers only submit
        // bounded quiche packets, and receive callers drop denied datagrams.
        if wanted > BURST {
            return Err(now + Duration::from_secs(1));
        }
        let mut buckets = self
            .buckets
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        let bucket = &mut buckets[direction.index()];
        let elapsed = now.saturating_duration_since(bucket.updated);
        bucket.credit = (bucket
            .credit
            .saturating_add(elapsed.as_nanos().saturating_mul(u128::from(rate))))
        .min(BURST as u128 * UNIT);
        bucket.updated = bucket.updated.max(now);
        let needed = if exact {
            wanted
        } else {
            // Coalesce waits to about 10 ms of credit instead of waking and
            // writing one byte at a time at low rates.
            wanted.min(rate.div_ceil(100).clamp(1, BURST as u64) as usize)
        } as u128
            * UNIT;
        if bucket.credit < needed {
            let nanos = (needed - bucket.credit).div_ceil(u128::from(rate));
            return Err(now + Duration::from_nanos(nanos.min(u128::from(u64::MAX)) as u64));
        }
        let reserved = if exact {
            wanted
        } else {
            wanted.min((bucket.credit / UNIT) as usize)
        };
        bucket.credit -= reserved as u128 * UNIT;
        Ok(Grant {
            rate: Some(self.clone()),
            direction,
            reserved,
        })
    }
}
/// Owns reserved wire credit until IO completes or the operation is cancelled.
pub(super) struct Grant {
    rate: Option<Arc<Rate>>,
    direction: Direction,
    reserved: usize,
}
impl Grant {
    pub fn len(&self) -> usize {
        self.reserved
    }
    pub fn commit(mut self, actual: usize) {
        assert!(actual <= self.reserved, "socket exceeded rate reservation");
        self.reserved -= actual;
    }
}
impl Drop for Grant {
    fn drop(&mut self) {
        if let Some(rate) = &self.rate {
            let mut buckets = rate
                .buckets
                .lock()
                .unwrap_or_else(|poison| poison.into_inner());
            let bucket = &mut buckets[self.direction.index()];
            bucket.credit =
                (bucket.credit + self.reserved as u128 * UNIT).min(BURST as u128 * UNIT);
        }
    }
}

/// Wrap an initialized L4 stream before TLS, so all encrypted H1/H2 traffic,
/// including handshakes, shares the endpoint's wire-byte policy with QUIC.
pub(super) struct RateStream<T> {
    inner: T,
    rate: Arc<Rate>,
    read_wait: Option<Pin<Box<Sleep>>>,
    write_wait: Option<Pin<Box<Sleep>>>,
}
impl<T> RateStream<T> {
    pub fn new(inner: T, rate: Arc<Rate>) -> Self {
        Self {
            inner,
            rate,
            read_wait: None,
            write_wait: None,
        }
    }
}
impl<T: fmt::Debug> fmt::Debug for RateStream<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("RateStream").field(&self.inner).finish()
    }
}
fn poll_grant(
    rate: &Arc<Rate>,
    direction: Direction,
    wanted: usize,
    wait: &mut Option<Pin<Box<Sleep>>>,
    cx: &mut Context<'_>,
) -> Poll<Grant> {
    loop {
        match rate.reserve(
            direction,
            wanted.min(BURST),
            false,
            tokio::time::Instant::now().into_std(),
        ) {
            Ok(grant) => {
                *wait = None;
                return Poll::Ready(grant);
            }
            Err(deadline) => {
                let deadline = tokio::time::Instant::from_std(deadline);
                let sleep =
                    wait.get_or_insert_with(|| Box::pin(tokio::time::sleep_until(deadline)));
                sleep.as_mut().reset(deadline);
                if sleep.as_mut().poll(cx).is_pending() {
                    return Poll::Pending;
                }
            }
        }
    }
}
impl<T: AsyncRead + Unpin> AsyncRead for RateStream<T> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.rate.bytes_per_second.is_none() {
            return Pin::new(&mut this.inner).poll_read(cx, out);
        }
        if out.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        let grant = match poll_grant(
            &this.rate,
            Direction::Upload,
            out.remaining(),
            &mut this.read_wait,
            cx,
        ) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(grant) => grant,
        };
        // Read into a bounded initialized scratch buffer to preserve ReadBuf's
        // initialization invariants without unsafe projection/assume_init.
        let mut storage = [0u8; BURST];
        let mut incoming = ReadBuf::new(&mut storage[..grant.len()]);
        match Pin::new(&mut this.inner).poll_read(cx, &mut incoming) {
            Poll::Ready(Ok(())) => {
                let data = incoming.filled();
                out.put_slice(data);
                grant.commit(data.len());
                Poll::Ready(Ok(()))
            }
            other => other,
        }
    }
}
impl<T: AsyncWrite + Unpin> AsyncWrite for RateStream<T> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if this.rate.bytes_per_second.is_none() {
            return Pin::new(&mut this.inner).poll_write(cx, bytes);
        }
        if bytes.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let grant = match poll_grant(
            &this.rate,
            Direction::Download,
            bytes.len(),
            &mut this.write_wait,
            cx,
        ) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(grant) => grant,
        };
        match Pin::new(&mut this.inner).poll_write(cx, &bytes[..grant.len()]) {
            Poll::Ready(Ok(n)) => {
                grant.commit(n);
                Poll::Ready(Ok(n))
            }
            other => other,
        }
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

// Preserve Pingora's trusted socket/TLS metadata and transport ownership APIs.
use pingora_core::protocols::{
    GetProxyDigest, GetSocketDigest, GetTimingDigest, Peek, Shutdown, SocketDigest, Ssl,
    TimingDigest, UniqueID, UniqueIDType, raw_connect::ProxyDigest,
};
impl<T: UniqueID> UniqueID for RateStream<T> {
    fn id(&self) -> UniqueIDType {
        self.inner.id()
    }
}
impl<T: Ssl> Ssl for RateStream<T> {
    fn get_ssl(&self) -> Option<&pingora_core::protocols::tls::TlsRef> {
        self.inner.get_ssl()
    }
    fn get_ssl_digest(&self) -> Option<Arc<pingora_core::protocols::tls::SslDigest>> {
        self.inner.get_ssl_digest()
    }
    fn selected_alpn_proto(&self) -> Option<pingora_core::protocols::ALPN> {
        self.inner.selected_alpn_proto()
    }
}
impl<T: GetTimingDigest> GetTimingDigest for RateStream<T> {
    fn get_timing_digest(&self) -> Vec<Option<TimingDigest>> {
        self.inner.get_timing_digest()
    }
    fn get_read_pending_time(&self) -> Duration {
        self.inner.get_read_pending_time()
    }
    fn get_write_pending_time(&self) -> Duration {
        self.inner.get_write_pending_time()
    }
}
impl<T: GetProxyDigest> GetProxyDigest for RateStream<T> {
    fn get_proxy_digest(&self) -> Option<Arc<ProxyDigest>> {
        self.inner.get_proxy_digest()
    }
    fn set_proxy_digest(&mut self, value: ProxyDigest) {
        self.inner.set_proxy_digest(value);
    }
}
impl<T: GetSocketDigest> GetSocketDigest for RateStream<T> {
    fn get_socket_digest(&self) -> Option<Arc<SocketDigest>> {
        self.inner.get_socket_digest()
    }
    fn set_socket_digest(&mut self, value: SocketDigest) {
        self.inner.set_socket_digest(value);
    }
}
#[async_trait::async_trait]
impl<T: Peek + Send + Sync> Peek for RateStream<T> {
    async fn try_peek(&mut self, buffer: &mut [u8]) -> io::Result<bool> {
        self.inner.try_peek(buffer).await
    }
}
#[async_trait::async_trait]
impl<T: Shutdown + Send + Sync> Shutdown for RateStream<T> {
    async fn shutdown(&mut self) {
        self.inner.shutdown().await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    #[test]
    fn exact_packet_reservations_refund_pending_and_account_partial_io() {
        let rate = Rate::new(Some(1024)).unwrap();
        let now = Instant::now();
        let grant = rate.try_reserve(Direction::Download, BURST, now).unwrap();
        assert!(rate.try_reserve(Direction::Download, 1, now).is_err());
        drop(grant); // WouldBlock or cancellation.
        rate.try_reserve(Direction::Download, BURST, now)
            .unwrap()
            .commit(BURST - 1);
        rate.try_reserve(Direction::Download, 1, now)
            .unwrap()
            .commit(1);
        assert_eq!(
            rate.try_reserve(Direction::Download, 1024, now).err(),
            Some(now + Duration::from_secs(1))
        );
        assert!(rate.try_reserve(Direction::Upload, BURST, now).is_ok());
    }
    #[test]
    fn refill_is_bounded_and_endpoints_are_independent() {
        let a = Rate::new(Some(1024)).unwrap();
        let b = Rate::new(Some(1024)).unwrap();
        let now = Instant::now();
        a.try_reserve(Direction::Download, BURST, now)
            .unwrap()
            .commit(BURST);
        assert!(a.try_reserve(Direction::Download, 1, now).is_err());
        assert!(b.try_reserve(Direction::Download, BURST, now).is_ok());
        let later = now + Duration::from_secs(3600);
        a.try_reserve(Direction::Download, BURST, later)
            .unwrap()
            .commit(BURST);
        assert!(a.try_reserve(Direction::Download, 1, later).is_err());
    }
    #[tokio::test]
    async fn socket_backpressure_refunds_credit_and_half_close_is_preserved() {
        let rate = Rate::new(Some(1024)).unwrap();
        let (writer, mut reader) = tokio::io::duplex(1);
        let mut writer = RateStream::new(writer, rate.clone());
        assert_eq!(writer.write(b"ab").await.unwrap(), 1);
        let pending = tokio::time::timeout(Duration::from_millis(5), writer.write(b"b")).await;
        assert!(pending.is_err());
        // Only the one byte actually accepted by the socket was charged.
        assert!(
            rate.try_reserve(Direction::Download, BURST - 1, Instant::now())
                .is_ok()
        );
        AsyncWriteExt::shutdown(&mut writer).await.unwrap();
        let mut received = Vec::new();
        reader.read_to_end(&mut received).await.unwrap();
        assert_eq!(received, b"a");
    }
    #[tokio::test(start_paused = true)]
    async fn tcp_connections_share_directional_credit_but_other_endpoints_progress() {
        let a = Rate::new(Some(1024)).unwrap();
        let b = Rate::new(Some(1024)).unwrap();
        let (socket_a, _peer_a) = tokio::io::duplex(BURST * 2);
        let (socket_b, _peer_b) = tokio::io::duplex(BURST * 2);
        let mut first = RateStream::new(socket_a, a.clone());
        let mut second = RateStream::new(socket_b, a);
        first.write_all(&vec![0; BURST]).await.unwrap();
        let started = tokio::time::Instant::now();
        // The second connection shares endpoint a's emptied bucket.
        second.write_all(&vec![0; 1024]).await.unwrap();
        assert!(started.elapsed() >= Duration::from_secs(1));
        // Endpoint b has never consumed its independent initial burst.
        assert!(
            b.try_reserve(
                Direction::Download,
                BURST,
                tokio::time::Instant::now().into_std()
            )
            .is_ok()
        );
    }
    #[test]
    fn zero_rate_is_rejected_and_unlimited_never_delays() {
        assert!(Rate::new(Some(0)).is_err());
        assert!(
            Rate::new(Some(1024))
                .unwrap()
                .try_reserve(Direction::Upload, BURST + 1, Instant::now())
                .is_err()
        );
        let rate = Rate::new(None).unwrap();
        rate.try_reserve(Direction::Upload, BURST * 4, Instant::now())
            .unwrap()
            .commit(BURST * 4);
        for _ in 0..32 {
            rate.try_reserve(Direction::Upload, BURST, Instant::now())
                .unwrap()
                .commit(BURST);
        }
    }
}
