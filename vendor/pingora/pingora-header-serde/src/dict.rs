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

//! Training to generate the zstd dictionary.

use std::fs;
use zstd::dict;

/// Train the zstd dictionary from all the files under the given `dir_path`
///
/// The output will be the trained dictionary
pub fn train<P: AsRef<std::path::Path>>(dir_path: P) -> Vec<u8> {
    // TODO: check f is file, it can be dir
    let files = fs::read_dir(dir_path)
        .unwrap()
        .filter_map(|entry| entry.ok().map(|f| f.path()));
    dict::from_files(files, 64 * 1024 * 1024).unwrap()
}
