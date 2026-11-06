// Copyright 2026 Cloudflare, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! TLS server specific implementation

use crate::listeners::TlsAccept;
use crate::protocols::tls::SslStream;
use crate::protocols::{Shutdown, IO};
use crate::tls::ext;
use crate::tls::ext::ssl_from_acceptor;
use crate::tls::ssl;
use crate::tls::ssl::SslAcceptor;

use async_trait::async_trait;
use log::warn;
use pingora_error::{ErrorType::*, OrErr, Result};
use std::pin::Pin;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};

/// Prepare a TLS stream for handshake
pub fn prepare_tls_stream<S: IO>(ssl_acceptor: &SslAcceptor, io: S) -> Result<SslStream<S>> {
    let ssl = ssl_from_acceptor(ssl_acceptor)
        .explain_err(TLSHandshakeFailure, |e| format!("ssl_acceptor error: {e}"))?;
    SslStream::new(ssl, io).explain_err(TLSHandshakeFailure, |e| format!("ssl stream error: {e}"))
}

/// Perform TLS handshake for the given connection with the given configuration
pub async fn handshake<S: IO>(ssl_acceptor: &SslAcceptor, io: S) -> Result<SslStream<S>> {
    let mut stream = prepare_tls_stream(ssl_acceptor, io)?;
    stream
        .accept()
        .await
        .explain_err(TLSHandshakeFailure, |e| format!("TLS accept() failed: {e}"))?;
    Ok(stream)
}

/// Perform TLS handshake for the given connection with the given configuration and callbacks
pub async fn handshake_with_callback<S: IO>(
    ssl_acceptor: &SslAcceptor,
    io: S,
    callbacks: &(dyn TlsAccept + Send + Sync),
) -> Result<SslStream<S>> {
    let mut tls_stream = prepare_tls_stream(ssl_acceptor, io)?;
    let done = Pin::new(&mut tls_stream)
        .start_accept()
        .await
        .explain_err(TLSHandshakeFailure, |e| format!("TLS accept() failed: {e}"))?;
    if !done {
        // safety: we do hold a mut ref of tls_stream
        let ssl_mut = unsafe { ext::ssl_mut(tls_stream.ssl()) };
        callbacks.certificate_callback(ssl_mut).await;
        Pin::new(&mut tls_stream)
            .resume_accept()
            .await
            .explain_err(TLSHandshakeFailure, |e| format!("TLS accept() failed: {e}"))?;
    }
    {
        let ssl = tls_stream.ssl();
        if let Some(extension) = callbacks.handshake_complete_callback(ssl).await {
            if let Some(digest_mut) = tls_stream.ssl_digest_mut() {
                digest_mut.extension.set(extension);
            }
        }
    }
    Ok(tls_stream)
}

#[async_trait]
impl<S> Shutdown for SslStream<S>
where
    S: AsyncRead + AsyncWrite + Sync + Unpin + Send,
{
    async fn shutdown(&mut self) {
        match <Self as AsyncWriteExt>::shutdown(self).await {
            Ok(()) => {}
            Err(e) => {
                warn!("TLS shutdown failed, {e}");
            }
        }
    }
}

/// Resumable TLS server side handshake.
#[async_trait]
pub trait ResumableAccept {
    /// Start a resumable TLS accept handshake.
    ///
    /// * `Ok(true)` when the handshake is finished
    /// * `Ok(false)`` when the handshake is paused midway
    ///
    /// For now, the accept will only pause when a certificate is needed.
    async fn start_accept(self: Pin<&mut Self>) -> Result<bool, ssl::Error>;

    /// Continue the TLS handshake
    ///
    /// This function should be called after the certificate is provided.
    async fn resume_accept(self: Pin<&mut Self>) -> Result<(), ssl::Error>;
}

#[async_trait]
impl<S: AsyncRead + AsyncWrite + Send + Unpin> ResumableAccept for SslStream<S> {
    async fn start_accept(mut self: Pin<&mut Self>) -> Result<bool, ssl::Error> {
        // safety: &mut self
        let ssl_mut = unsafe { ext::ssl_mut(self.ssl()) };
        ext::suspend_when_need_ssl_cert(ssl_mut);
        let res = self.accept().await;

        match res {
            Ok(()) => Ok(true),
            Err(e) => {
                if ext::is_suspended_for_cert(&e) {
                    Ok(false)
                } else {
                    Err(e)
                }
            }
        }
    }

    async fn resume_accept(mut self: Pin<&mut Self>) -> Result<(), ssl::Error> {
        // safety: &mut ssl
        let ssl_mut = unsafe { ext::ssl_mut(self.ssl()) };
        ext::unblock_ssl_cert(ssl_mut);
        self.accept().await
    }
}
