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

use super::{Encode, COMPRESSION_ERROR};
use bytes::Bytes;
use parking_lot::Mutex;
use pingora_error::{OrErr, Result};
use std::io::Write;
use std::time::{Duration, Instant};
use zstd::stream::write::Encoder;

/// [RFC 9842](https://datatracker.ietf.org/doc/html/rfc9842) magic number for dcz.
pub const DCZ_MAGIC: [u8; 8] = [0x5e, 0x2a, 0x4d, 0x18, 0x20, 0x00, 0x00, 0x00];

/// [RFC 9842](https://datatracker.ietf.org/doc/html/rfc9842) header size: 8-byte magic + 32-byte SHA-256 hash.
pub const DCZ_HEADER_SIZE: usize = 40;

pub struct Compressor {
    compress: Mutex<Encoder<'static, Vec<u8>>>,
    total_in: usize,
    total_out: usize,
    duration: Duration,
}

impl Compressor {
    pub fn new(level: u32) -> Self {
        Compressor {
            // Mutex because Encoder is not Sync
            // https://github.com/gyscos/zstd-rs/issues/186
            compress: Mutex::new(Encoder::new(vec![], level as i32).unwrap()),
            total_in: 0,
            total_out: 0,
            duration: Duration::new(0, 0),
        }
    }
}

impl Encode for Compressor {
    fn encode(&mut self, input: &[u8], end: bool) -> Result<Bytes> {
        // reserve at most 16k
        const MAX_INIT_COMPRESSED_BUF_SIZE: usize = 16 * 1024;
        let start = Instant::now();
        self.total_in += input.len();
        let mut compress = self.compress.lock();
        // reserve at most input size, cap at 16k, compressed output should be smaller
        compress
            .get_mut()
            .reserve(std::cmp::min(MAX_INIT_COMPRESSED_BUF_SIZE, input.len()));
        compress
            .write_all(input)
            .or_err(COMPRESSION_ERROR, "while compress zstd")?;
        // write to vec will never fail.
        if end {
            compress
                .do_finish()
                .or_err(COMPRESSION_ERROR, "while compress zstd")?;
        }
        self.total_out += compress.get_ref().len();
        self.duration += start.elapsed();
        Ok(std::mem::take(compress.get_mut()).into()) // into() Bytes will drop excess capacity
    }

    fn stat(&self) -> (&'static str, usize, usize, Duration) {
        ("zstd", self.total_in, self.total_out, self.duration)
    }
}

/// Dictionary compressor for [RFC 9842](https://datatracker.ietf.org/doc/html/rfc9842) (dcz).
/// Prepends [`DCZ_HEADER_SIZE`]-byte header to output.
pub struct DictionaryCompressor {
    compress: Mutex<Encoder<'static, Vec<u8>>>,
    dictionary_hash: [u8; 32],
    header_written: bool,
    total_in: usize,
    total_out: usize,
    duration: Duration,
}

impl DictionaryCompressor {
    pub fn new(level: u32, dictionary: &[u8], dictionary_hash: [u8; 32]) -> Result<Self> {
        let encoder = Encoder::with_dictionary(vec![], level as i32, dictionary).or_err(
            COMPRESSION_ERROR,
            "failed to create zstd encoder with dictionary",
        )?;

        Ok(DictionaryCompressor {
            compress: Mutex::new(encoder),
            dictionary_hash,
            header_written: false,
            total_in: 0,
            total_out: 0,
            duration: Duration::new(0, 0),
        })
    }

    fn build_header(&self) -> [u8; DCZ_HEADER_SIZE] {
        let mut header = [0u8; DCZ_HEADER_SIZE];
        header[..8].copy_from_slice(&DCZ_MAGIC);
        header[8..].copy_from_slice(&self.dictionary_hash);
        header
    }
}

impl Encode for DictionaryCompressor {
    fn encode(&mut self, input: &[u8], end: bool) -> Result<Bytes> {
        const MAX_INIT_COMPRESSED_BUF_SIZE: usize = 16 * 1024;
        let start = Instant::now();
        self.total_in += input.len();
        let mut compress = self.compress.lock();

        let reserve_size = if !self.header_written {
            DCZ_HEADER_SIZE + std::cmp::min(MAX_INIT_COMPRESSED_BUF_SIZE, input.len())
        } else {
            std::cmp::min(MAX_INIT_COMPRESSED_BUF_SIZE, input.len())
        };
        compress.get_mut().reserve(reserve_size);

        if !self.header_written {
            compress.get_mut().extend_from_slice(&self.build_header());
            self.header_written = true;
        }

        compress
            .write_all(input)
            .or_err(COMPRESSION_ERROR, "while compress dcz")?;
        if end {
            compress
                .do_finish()
                .or_err(COMPRESSION_ERROR, "while compress dcz")?;
        }
        self.total_out += compress.get_ref().len();
        self.duration += start.elapsed();
        Ok(std::mem::take(compress.get_mut()).into())
    }

    fn stat(&self) -> (&'static str, usize, usize, Duration) {
        ("dcz", self.total_in, self.total_out, self.duration)
    }
}
