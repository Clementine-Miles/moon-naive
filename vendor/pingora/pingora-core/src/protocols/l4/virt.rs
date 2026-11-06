//! Provides [`VirtualSocketStream`].

use std::{
    pin::Pin,
    task::{Context, Poll},
};

use tokio::io::{AsyncRead, AsyncWrite};

use super::ext::TcpKeepalive;

/// A limited set of socket options that can be set on a [`VirtualSocket`].
#[non_exhaustive]
#[derive(Debug, Clone)]
pub enum VirtualSockOpt {
    NoDelay,
    KeepAlive(TcpKeepalive),
}

/// A "virtual" socket that supports async read and write operations.
pub trait VirtualSocket: AsyncRead + AsyncWrite + Unpin + Send + Sync + std::fmt::Debug {
    /// Set a socket option.
    fn set_socket_option(&self, opt: VirtualSockOpt) -> std::io::Result<()>;
}

/// Wrapper around any type implementing  [`VirtualSocket`].
#[derive(Debug)]
pub struct VirtualSocketStream {
    pub(crate) socket: Box<dyn VirtualSocket>,
}

impl VirtualSocketStream {
    pub fn new(socket: Box<dyn VirtualSocket>) -> Self {
        Self { socket }
    }

    #[inline]
    pub fn set_socket_option(&self, opt: VirtualSockOpt) -> std::io::Result<()> {
        self.socket.set_socket_option(opt)
    }
}

impl AsyncRead for VirtualSocketStream {
    #[inline]
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut *self.get_mut().socket).poll_read(cx, buf)
    }
}

impl AsyncWrite for VirtualSocketStream {
    #[inline]
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut *self.get_mut().socket).poll_write(cx, buf)
    }

    #[inline]
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut *self.get_mut().socket).poll_flush(cx)
    }

    #[inline]
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut *self.get_mut().socket).poll_shutdown(cx)
    }
}
