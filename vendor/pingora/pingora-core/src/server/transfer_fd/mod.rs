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

#[cfg(target_os = "linux")]
use log::{debug, error, warn};
use nix::errno::Errno;
#[cfg(target_os = "linux")]
use nix::sys::socket::{self, AddressFamily, Backlog, RecvMsg, SockFlag, SockType, UnixAddr};
#[cfg(target_os = "linux")]
use nix::sys::stat;
use nix::{Error, NixPath};
use std::collections::{HashMap, HashSet};
use std::io::Write;
#[cfg(target_os = "linux")]
use std::io::{IoSlice, IoSliceMut};
#[cfg(target_os = "linux")]
use std::os::fd::{AsRawFd, BorrowedFd, FromRawFd, OwnedFd};
use std::os::unix::io::RawFd;
#[cfg(target_os = "linux")]
use std::{thread, time};

// Utilities to transfer file descriptors between sockets, e.g. during graceful upgrades.

/// Container for open file descriptors and their associated bind addresses.
pub struct Fds {
    map: HashMap<String, RawFd>,
}

impl Fds {
    pub fn new() -> Self {
        Fds {
            map: HashMap::new(),
        }
    }

    pub fn add(&mut self, bind: String, fd: RawFd) {
        self.map.insert(bind, fd);
    }

    pub fn get(&self, bind: &str) -> Option<&RawFd> {
        self.map.get(bind)
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    pub fn serialize(&self) -> (Vec<String>, Vec<RawFd>) {
        self.map.iter().map(|(key, val)| (key.clone(), val)).unzip()
    }

    pub fn deserialize(&mut self, binds: Vec<String>, fds: Vec<RawFd>) {
        assert_eq!(binds.len(), fds.len());
        for (bind, fd) in binds.into_iter().zip(fds) {
            self.map.insert(bind, fd);
        }
    }

    pub fn send_to_sock<P>(&self, path: &P) -> Result<usize, Error>
    where
        P: ?Sized + NixPath + std::fmt::Display,
    {
        let (vec_key, vec_fds) = self.serialize();
        let mut ser_buf: [u8; 2048] = [0; 2048];
        let ser_key_size = serialize_vec_string(&vec_key, &mut ser_buf);
        send_fds_to(vec_fds, &ser_buf[..ser_key_size], path, None)
    }

    pub fn get_from_sock<P>(&mut self, path: &P) -> Result<(), Error>
    where
        P: ?Sized + NixPath + std::fmt::Display,
    {
        let mut de_buf: [u8; 2048] = [0; 2048];
        let (fds, bytes) = get_fds_from(path, &mut de_buf, None)?;
        let keys = deserialize_vec_string(&de_buf[..bytes])?;
        self.deserialize(keys, fds);
        Ok(())
    }

    /// Close and remove inherited listening fds whose bind addresses are absent from `keep`.
    ///
    /// An unclaimed `SO_REUSEPORT` socket remains active without an acceptor and can black-hole
    /// connections. Removing it also prevents it from being transferred to the next process.
    /// Returns the addresses removed from the table.
    #[cfg(unix)]
    pub fn close_unclaimed(&mut self, keep: &HashSet<String>) -> Vec<String> {
        let mut closed = Vec::new();
        self.map.retain(|bind, fd| {
            if keep.contains(bind) {
                return true;
            }
            if let Err(e) = nix::unistd::close(*fd) {
                log::warn!(
                    "Failed to close orphaned inherited listening socket fd {fd} ({bind}): {e}"
                );
            }
            closed.push(bind.clone());
            false
        });
        closed
    }
}

fn serialize_vec_string(vec_string: &[String], mut buf: &mut [u8]) -> usize {
    // There are many ways to do this. Serde is probably the way to go
    // But let's start with something simple: space separated strings
    let joined = vec_string.join(" ");
    // TODO: check the buf is large enough
    buf.write(joined.as_bytes()).unwrap()
}

fn deserialize_vec_string(buf: &[u8]) -> Result<Vec<String>, Error> {
    let joined = std::str::from_utf8(buf).map_err(|_| Error::EINVAL)?;
    Ok(joined.split_ascii_whitespace().map(String::from).collect())
}

#[cfg(target_os = "linux")]
pub fn get_fds_from<P>(
    path: &P,
    payload: &mut [u8],
    max_retry: Option<usize>,
) -> Result<(Vec<RawFd>, usize), Error>
where
    P: ?Sized + NixPath + std::fmt::Display,
{
    let max_retry = max_retry.unwrap_or(MAX_RETRY);
    const MAX_FDS: usize = 32;

    let listen_fd = socket::socket(
        AddressFamily::Unix,
        SockType::Stream,
        SockFlag::SOCK_NONBLOCK,
        None,
    )
    .unwrap();
    let unix_addr = UnixAddr::new(path).unwrap();
    // clean up old sock
    match nix::unistd::unlink(path) {
        Ok(()) => {
            debug!("unlink {} done", path);
        }
        Err(e) => {
            // Normal if file does not exist
            debug!("unlink {} failed: {}", path, e);
            // TODO: warn if exist but not able to unlink
        }
    };
    socket::bind(listen_fd.as_raw_fd(), &unix_addr).unwrap();

    /* sock is created before we change user, need to give permission */
    stat::fchmodat(
        // SAFETY: AT_FDCWD is a well-defined POSIX sentinel constant used by *at() syscalls
        // to indicate the current working directory. It is not a real file descriptor and does
        // not require ownership or lifetime guarantees.
        unsafe { BorrowedFd::borrow_raw(libc::AT_FDCWD) },
        path,
        stat::Mode::from_bits_truncate(0o666),
        stat::FchmodatFlags::FollowSymlink,
    )
    .unwrap();

    socket::listen(
        &listen_fd,
        Backlog::new(8).expect("8 is well within SOMAXCONN"),
    )
    .unwrap();

    let fd = match accept_with_retry_timeout(listen_fd.as_raw_fd(), max_retry) {
        Ok(fd) => fd,
        Err(e) => {
            error!("Giving up reading socket from: {path}, error: {e:?}");
            //cleanup
            if nix::unistd::close(listen_fd).is_ok() {
                nix::unistd::unlink(path).unwrap();
            }
            return Err(e);
        }
    };

    // The accepted connection is only needed for this transfer. Take ownership of it so
    // that it is closed on every path out of this function, including the early return
    // from `cmsgs()?` below; otherwise every graceful upgrade leaks one unix socket.
    //
    // SAFETY: `fd` was just returned by accept(2) and is not owned or closed anywhere else.
    let conn = unsafe { OwnedFd::from_raw_fd(fd) };

    let mut io_vec = [IoSliceMut::new(payload); 1];
    let mut cmsg_buf = nix::cmsg_space!([RawFd; MAX_FDS]);
    // MSG_CMSG_CLOEXEC sets FD_CLOEXEC on the received descriptors atomically. These
    // listening sockets are kept for the rest of the process's lifetime, so without it any
    // subprocess an application built on pingora execs inherits them, and can keep the
    // port bound after the server itself is gone.
    let msg: RecvMsg<UnixAddr> = socket::recvmsg(
        conn.as_raw_fd(),
        &mut io_vec,
        Some(&mut cmsg_buf),
        socket::MsgFlags::MSG_CMSG_CLOEXEC,
    )
    .unwrap();

    let mut fds: Vec<RawFd> = Vec::new();
    for cmsg in msg.cmsgs()? {
        if let socket::ControlMessageOwned::ScmRights(mut vec_fds) = cmsg {
            fds.append(&mut vec_fds)
        } else {
            warn!("Unexpected control messages: {cmsg:?}")
        }
    }

    //cleanup
    if nix::unistd::close(listen_fd).is_ok() {
        nix::unistd::unlink(path).unwrap();
    }

    Ok((fds, msg.bytes))
}

#[cfg(not(target_os = "linux"))]
pub fn get_fds_from<P>(
    _path: &P,
    _payload: &mut [u8],
    _max_retry: Option<usize>,
) -> Result<(Vec<RawFd>, usize), Error>
where
    P: ?Sized + NixPath + std::fmt::Display,
{
    log::error!("Upgrade is not currently supported outside of Linux platforms");
    Err(Errno::ECONNREFUSED)
}

#[cfg(target_os = "linux")]
const MAX_RETRY: usize = 5;
#[cfg(target_os = "linux")]
const RETRY_INTERVAL: time::Duration = time::Duration::from_secs(1);

#[cfg(target_os = "linux")]
fn accept_with_retry_timeout(listen_fd: i32, max_retry: usize) -> Result<i32, Error> {
    let mut retried = 0;
    loop {
        match socket::accept(listen_fd) {
            Ok(fd) => return Ok(fd),
            Err(e) => {
                if retried > max_retry {
                    return Err(e);
                }
                match e {
                    Errno::EAGAIN => {
                        error!(
                            "No incoming socket transfer, sleep {RETRY_INTERVAL:?} and try again"
                        );
                        retried += 1;
                        thread::sleep(RETRY_INTERVAL);
                    }
                    _ => {
                        error!("Error accepting socket transfer: {e}");
                        return Err(e);
                    }
                }
            }
        }
    }
}

#[cfg(target_os = "linux")]
pub fn send_fds_to<P>(
    fds: Vec<RawFd>,
    payload: &[u8],
    path: &P,
    max_retry: Option<usize>,
) -> Result<usize, Error>
where
    P: ?Sized + NixPath + std::fmt::Display,
{
    let max_retry = max_retry.unwrap_or(MAX_RETRY);
    const MAX_NONBLOCKING_POLLS: usize = 20;
    const NONBLOCKING_POLL_INTERVAL: time::Duration = time::Duration::from_millis(500);

    let send_fd = socket::socket(
        AddressFamily::Unix,
        SockType::Stream,
        SockFlag::SOCK_NONBLOCK,
        None,
    )?;
    let unix_addr = UnixAddr::new(path)?;
    let mut retried = 0;
    let mut nonblocking_polls = 0;

    let conn_result: Result<usize, Error> = loop {
        match socket::connect(send_fd.as_raw_fd(), &unix_addr) {
            Ok(_) => break Ok(0),
            Err(e) => match e {
                /* If the new process hasn't created the upgrade sock we'll get an ENOENT.
                ECONNREFUSED may happen if the sock wasn't cleaned up
                and the old process tries sending before the new one is listening.
                EACCES may happen if connect() happen before the correct permission is set */
                Errno::ENOENT | Errno::ECONNREFUSED | Errno::EACCES => {
                    /*the server is not ready yet*/
                    retried += 1;
                    if retried > max_retry {
                        error!(
                            "Max retry: {} reached. Giving up sending socket to: {}, error: {:?}",
                            max_retry, path, e
                        );
                        break Err(e);
                    }
                    warn!("server not ready, will try again in {RETRY_INTERVAL:?}");
                    thread::sleep(RETRY_INTERVAL);
                }
                /* handle nonblocking IO */
                Errno::EINPROGRESS => {
                    nonblocking_polls += 1;
                    if nonblocking_polls >= MAX_NONBLOCKING_POLLS {
                        error!("Connect() not ready after retries when sending socket to: {path}",);
                        break Err(e);
                    }
                    warn!("Connect() not ready, will try again in {NONBLOCKING_POLL_INTERVAL:?}",);
                    thread::sleep(NONBLOCKING_POLL_INTERVAL);
                }
                _ => {
                    error!("Error sending socket to: {path}, error: {e:?}");
                    break Err(e);
                }
            },
        }
    };

    let result = match conn_result {
        Ok(_) => {
            let io_vec = [IoSlice::new(payload); 1];
            let scm = socket::ControlMessage::ScmRights(fds.as_slice());
            let cmsg = [scm; 1];
            loop {
                match socket::sendmsg(
                    send_fd.as_raw_fd(),
                    &io_vec,
                    &cmsg,
                    socket::MsgFlags::empty(),
                    None::<&UnixAddr>,
                ) {
                    Ok(result) => break Ok(result),
                    Err(e) => match e {
                        /* handle nonblocking IO */
                        Errno::EAGAIN => {
                            nonblocking_polls += 1;
                            if nonblocking_polls >= MAX_NONBLOCKING_POLLS {
                                error!(
                                    "Sendmsg() not ready after retries when sending socket to: {}",
                                    path
                                );
                                break Err(e);
                            }
                            warn!(
                                "Sendmsg() not ready, will try again in {:?}",
                                NONBLOCKING_POLL_INTERVAL
                            );
                            thread::sleep(NONBLOCKING_POLL_INTERVAL);
                        }
                        _ => break Err(e),
                    },
                }
            }
        }
        Err(_) => conn_result,
    };

    nix::unistd::close(send_fd).unwrap();
    result
}

#[cfg(not(target_os = "linux"))]
pub fn send_fds_to<P>(
    _fds: Vec<RawFd>,
    _payload: &[u8],
    _path: &P,
    _max_retry: Option<usize>,
) -> Result<usize, Error>
where
    P: ?Sized + NixPath + std::fmt::Display,
{
    Ok(0)
}
