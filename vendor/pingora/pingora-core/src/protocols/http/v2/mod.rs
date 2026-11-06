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

//! HTTP/2 implementation

use std::time::Duration;

use crate::{Error, ErrorType::*, OrErr, Result};
use pingora_timeout::timeout;

use bytes::Bytes;
use h2::SendStream;

pub mod client;
pub mod server;

async fn reserve_and_send(
    writer: &mut SendStream<Bytes>,
    remaining: &mut Bytes,
    end: bool,
) -> Result<()> {
    // reserve remaining bytes then wait
    writer.reserve_capacity(remaining.len());
    let res = std::future::poll_fn(|cx| writer.poll_capacity(cx)).await;

    match res {
        None => Error::e_explain(H2Error, "cannot reserve capacity"),
        Some(ready) => {
            let n = ready.or_err(H2Error, "while waiting for capacity")?;
            let remaining_size = remaining.len();
            let data_to_send = remaining.split_to(std::cmp::min(remaining_size, n));
            writer
                .send_data(data_to_send, remaining.is_empty() && end)
                .or_err(WriteError, "while writing h2 request body")?;
            Ok(())
        }
    }
}

/// A helper function to write the body of h2 streams.
pub async fn write_body(
    writer: &mut SendStream<Bytes>,
    data: Bytes,
    end: bool,
    write_timeout: Option<Duration>,
) -> Result<()> {
    let mut remaining = data;

    // Cannot poll 0 capacity, so send it directly.
    if remaining.is_empty() {
        writer
            .send_data(remaining, end)
            .or_err(WriteError, "while writing h2 request body")?;
        return Ok(());
    }

    loop {
        match write_timeout {
            Some(t) => match timeout(t, reserve_and_send(writer, &mut remaining, end)).await {
                Ok(res) => res?,
                Err(_) => Error::e_explain(
                    WriteTimedout,
                    format!("while writing h2 request body, timeout: {t:?}"),
                )?,
            },
            None => {
                reserve_and_send(writer, &mut remaining, end).await?;
            }
        }
        if remaining.is_empty() {
            return Ok(());
        }
    }
}
