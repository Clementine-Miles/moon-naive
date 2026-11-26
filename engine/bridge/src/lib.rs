//! Safe Rust bridge to the Moon-naive Chromium Native Engine.
//!
//! `libmoon_engine` is Chromium's own network stack (host resolution, socket
//! pools, BoringSSL TLS, HTTP/2 and QUIC/HTTP/3 sessions, the Chrome Root
//! Store verifier) built as a shared library with a narrow C ABI
//! (`engine/src/net/tools/moon_engine/moon_engine.h`). This crate loads it at
//! run time, checks the ABI version and exposes tunnels as async handles.
//!
//! The engine contains no protocol constants or cryptography: every CONNECT is
//! signed and every confirmation verified by the [`Authenticator`] supplied
//! here, with the exact binding (TLS exporter and actually allocated stream
//! ID) that Chromium reports for that stream.
//!
//! All `unsafe` code of the client lives in this crate.
use libloading::Library;
use std::{
    ffi::{CString, c_char, c_int, c_void},
    fmt,
    panic::{AssertUnwindSafe, catch_unwind},
    path::{Path, PathBuf},
    ptr::NonNull,
    sync::{Arc, Mutex, OnceLock},
    time::Duration,
};
use tokio::sync::{mpsc, oneshot};

/// Must equal `MOON_ENGINE_ABI_VERSION` of the loaded library.
pub const ABI_VERSION: u32 = 1;
/// File name of the engine library on this platform.
pub const LIBRARY_NAME: &str = "libmoon_engine.so";
/// Environment variable that overrides where the library is looked up.
pub const LIBRARY_ENV: &str = "MOON_NAIVE_ENGINE";

/// Largest read requested from the engine in one call.
pub const MAX_READ: usize = 64 * 1024;
const MAX_AUTHORIZATION: usize = 256;

// ---------------------------------------------------------------------------
// C ABI mirror. Keep in sync with moon_engine.h.

mod ffi {
    use super::*;

    pub const TRANSPORT_H2: u32 = 2;
    pub const TRANSPORT_H3: u32 = 3;
    pub const OPEN_OK: u8 = 0;
    pub const OPEN_CONNECTION: u8 = 1;
    pub const OPEN_STATUS: u8 = 2;
    pub const OPEN_CONFIRMATION: u8 = 3;
    pub const OPEN_REFUSED: u8 = 4;

    #[repr(C)]
    pub struct Engine {
        _private: [u8; 0],
    }

    #[repr(C)]
    pub struct Binding {
        pub exporter: [u8; 32],
        pub stream_id: u64,
        pub ech_accepted: u8,
        pub http_version: u8,
    }

    pub type AuthorizeFn = unsafe extern "C" fn(
        *mut c_void,
        *const Binding,
        *const c_char,
        usize,
        *mut u8,
        usize,
        *mut usize,
    ) -> c_int;
    pub type VerifyFn = unsafe extern "C" fn(
        *mut c_void,
        *const Binding,
        *const c_char,
        usize,
        *const *const c_char,
        *const usize,
        usize,
    ) -> u8;
    pub type LogFn = unsafe extern "C" fn(*mut c_void, c_int, *const c_char, usize);

    #[repr(C)]
    pub struct Config {
        pub abi_version: u32,
        pub server_name: *const c_char,
        pub connect_host: *const c_char,
        pub port: u16,
        pub ca_file: *const c_char,
        pub ech_config_list: *const u8,
        pub ech_config_list_len: usize,
        pub exporter_label: *const c_char,
        pub quic_idle_timeout_secs: u32,
        pub auth_ctx: *mut c_void,
        pub authorize: Option<AuthorizeFn>,
        pub verify: Option<VerifyFn>,
        pub log_ctx: *mut c_void,
        pub log: Option<LogFn>,
    }

    #[repr(C)]
    pub struct OpenResult {
        pub kind: u8,
        pub transport: u8,
        pub selection: u8,
        pub net_error: i32,
        pub http_status: i32,
    }

    #[repr(C)]
    pub struct TunnelCallbacks {
        pub ctx: *mut c_void,
        pub on_open: Option<unsafe extern "C" fn(*mut c_void, *const OpenResult)>,
        pub on_read: Option<unsafe extern "C" fn(*mut c_void, i32, *const u8)>,
        pub on_write: Option<unsafe extern "C" fn(*mut c_void, i32)>,
        pub on_shutdown: Option<unsafe extern "C" fn(*mut c_void, i32)>,
        pub on_closed: Option<unsafe extern "C" fn(*mut c_void)>,
    }

    /// Function table resolved from the library. The library is never
    /// unloaded: Chromium keeps process-wide threads and singletons.
    pub struct Api {
        pub abi_version: unsafe extern "C" fn() -> u32,
        pub create: unsafe extern "C" fn(*const Config, *mut c_char, usize) -> *mut Engine,
        pub destroy: unsafe extern "C" fn(*mut Engine),
        pub open: unsafe extern "C" fn(
            *mut Engine,
            *const c_char,
            usize,
            u32,
            *const TunnelCallbacks,
        ) -> u64,
        pub read: unsafe extern "C" fn(*mut Engine, u64, usize),
        pub write: unsafe extern "C" fn(*mut Engine, u64, *const u8, usize),
        pub shutdown_write: unsafe extern "C" fn(*mut Engine, u64),
        pub close: unsafe extern "C" fn(*mut Engine, u64),
    }
}

// ---------------------------------------------------------------------------
// Library loading.

// Only successful loads are cached, so a later attempt with a corrected path
// can still succeed. Loading is serialized.
static API: OnceLock<(PathBuf, ffi::Api)> = OnceLock::new();
static LOADING: Mutex<()> = Mutex::new(());

/// Candidate library paths in lookup order: the explicit path, then
/// `$MOON_NAIVE_ENGINE`, then next to the running executable, then
/// `<exe dir>/../lib/moon-naive/`.
pub fn library_candidates(explicit: Option<&Path>) -> Vec<PathBuf> {
    if let Some(path) = explicit {
        return vec![path.to_path_buf()];
    }
    if let Some(path) = std::env::var_os(LIBRARY_ENV).filter(|p| !p.is_empty()) {
        return vec![PathBuf::from(path)];
    }
    let mut candidates = Vec::new();
    if let Some(dir) = std::env::current_exe()
        .ok()
        .and_then(|exe| exe.parent().map(Path::to_path_buf))
    {
        candidates.push(dir.join(LIBRARY_NAME));
        candidates.push(dir.join("../lib/moon-naive").join(LIBRARY_NAME));
    }
    candidates
}

fn load_api(explicit: Option<&Path>) -> Result<&'static ffi::Api, String> {
    let _serialized = LOADING.lock().unwrap_or_else(|e| e.into_inner());
    if let Some((path, api)) = API.get() {
        if let Some(explicit) = explicit
            && explicit != path
        {
            return Err(format!(
                "engine already loaded from {}; cannot also load {}",
                path.display(),
                explicit.display()
            ));
        }
        return Ok(api);
    }
    let mut errors = Vec::new();
    for path in library_candidates(explicit) {
        if !path.exists() {
            errors.push(format!("{}: not found", path.display()));
            continue;
        }
        match resolve(&path) {
            Ok(api) => return Ok(&API.get_or_init(|| (path, api)).1),
            Err(error) => errors.push(format!("{}: {error}", path.display())),
        }
    }
    Err(format!(
        "the Chromium native engine ({LIBRARY_NAME}) could not be loaded ({}). \
         Install it next to the client executable, set {LIBRARY_ENV}, or set \
         engine_library in the client configuration. Build it with \
         `cargo xtask engine build` (see docs/development.md)",
        if errors.is_empty() {
            "no candidate path".to_owned()
        } else {
            errors.join("; ")
        }
    ))
}

fn resolve(path: &Path) -> Result<ffi::Api, String> {
    // SAFETY: loading runs the library's static initializers. The library is
    // the engine built from this repository's pinned Chromium revision.
    let library = unsafe { Library::new(path) }.map_err(|e| e.to_string())?;
    // Never unload: Chromium owns process-wide threads after initialization.
    let library: &'static Library = Box::leak(Box::new(library));
    macro_rules! symbol {
        ($name:literal) => {
            // SAFETY: the type matches the declaration in moon_engine.h and
            // the library stays loaded for the life of the process.
            *unsafe { library.get($name) }.map_err(|e| e.to_string())?
        };
    }
    let api = ffi::Api {
        abi_version: symbol!(b"moon_engine_abi_version\0"),
        create: symbol!(b"moon_engine_create\0"),
        destroy: symbol!(b"moon_engine_destroy\0"),
        open: symbol!(b"moon_tunnel_open\0"),
        read: symbol!(b"moon_tunnel_read\0"),
        write: symbol!(b"moon_tunnel_write\0"),
        shutdown_write: symbol!(b"moon_tunnel_shutdown_write\0"),
        close: symbol!(b"moon_tunnel_close\0"),
    };
    // SAFETY: a plain function without arguments.
    let version = unsafe { (api.abi_version)() };
    if version != ABI_VERSION {
        return Err(format!(
            "ABI version {version} does not match the client's {ABI_VERSION}; \
             rebuild the engine from this release"
        ));
    }
    Ok(api)
}

// ---------------------------------------------------------------------------
// Public types.

/// Transport of the CONNECT stream to the proxy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transport {
    H2,
    H3,
}
impl Transport {
    fn raw(self) -> u32 {
        match self {
            Self::H2 => ffi::TRANSPORT_H2,
            Self::H3 => ffi::TRANSPORT_H3,
        }
    }
}

/// Channel binding of one CONNECT stream, as reported by Chromium.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Binding {
    /// TLS exporter of the proxy connection (TLS 1.3, empty context).
    pub exporter: [u8; 32],
    /// The stream ID the transport actually allocated for this CONNECT.
    pub stream_id: u64,
    /// Whether the proxy connection negotiated Encrypted Client Hello.
    pub ech_accepted: bool,
    /// 2 or 3.
    pub http_version: u8,
}
impl fmt::Debug for Binding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The exporter is secret-derived: never print it.
        f.debug_struct("Binding")
            .field("stream_id", &self.stream_id)
            .field("ech_accepted", &self.ech_accepted)
            .field("http_version", &self.http_version)
            .finish_non_exhaustive()
    }
}

/// Signs CONNECT requests and verifies confirmations. Runs on the engine
/// thread: implementations must be fast and must not block.
pub trait Authenticator: Send + Sync + 'static {
    /// The `proxy-authorization` value for a CONNECT with this binding and
    /// exact `:authority`, or `None` to refuse (no request is sent).
    fn authorize(&self, binding: &Binding, authority: &str) -> Option<Vec<u8>>;
    /// Given every `proxy-authentication-info` value of a 200 response,
    /// return the selected record mode (nonzero) if exactly one value is a
    /// valid confirmation, or `None`.
    fn verify(&self, binding: &Binding, authority: &str, values: &[&[u8]]) -> Option<u8>;
}

/// Engine diagnostics sink (no secrets are ever passed).
pub type Logger = Box<dyn Fn(LogLevel, &str) + Send + Sync + 'static>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum LogLevel {
    Info,
    Warning,
    Error,
}

/// Proxy and engine settings.
#[derive(Debug, Clone)]
pub struct Config {
    /// Explicit library path; otherwise see [`library_candidates`].
    pub library: Option<PathBuf>,
    /// TLS server name of the proxy (SNI or ECH inner name, certificate name).
    pub server_name: String,
    /// Address to connect to when different from `server_name` (DNS name or
    /// IP literal; IPv6 without brackets).
    pub connect_host: Option<String>,
    pub port: u16,
    /// Additional PEM trust anchors.
    pub ca_file: Option<PathBuf>,
    /// ECHConfigList; when present ECH is mandatory.
    pub ech_config_list: Option<Vec<u8>>,
    /// TLS exporter label for the channel binding.
    pub exporter_label: String,
    pub quic_idle_timeout: Duration,
}

/// Why opening a tunnel failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OpenError {
    /// No proxy connection or stream; nothing was received for this tunnel.
    Connection { net_error: i32 },
    /// The proxy answered with a status other than 200.
    Status(u16),
    /// Status 200 without exactly one valid confirmation.
    Confirmation,
    /// The authenticator refused to sign; no request was sent.
    Refused,
    /// The engine rejected the arguments (invalid authority).
    Invalid,
    /// The engine went away.
    Closed,
}
impl fmt::Display for OpenError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Connection { net_error } => {
                write!(f, "connection failed (net error {net_error})")
            }
            Self::Status(status) => write!(f, "server refused the tunnel (HTTP {status})"),
            Self::Confirmation => f.write_str("server confirmation missing or invalid"),
            Self::Refused => f.write_str("request not signed (ECH or binding requirements unmet)"),
            Self::Invalid => f.write_str("invalid target authority"),
            Self::Closed => f.write_str("engine closed"),
        }
    }
}
impl std::error::Error for OpenError {}

// ---------------------------------------------------------------------------
// Engine.

struct AuthContext {
    authenticator: Arc<dyn Authenticator>,
}

struct LogContext {
    logger: Option<Logger>,
}

struct Inner {
    api: &'static ffi::Api,
    raw: NonNull<ffi::Engine>,
    // Referenced by the engine through raw pointers; freed after destroy.
    auth: *mut AuthContext,
    log: *mut LogContext,
}
// SAFETY: every engine entry point may be called from any thread
// (moon_engine.h, "Threading"), and the contexts are Send + Sync.
unsafe impl Send for Inner {}
// SAFETY: as above.
unsafe impl Sync for Inner {}

impl Drop for Inner {
    fn drop(&mut self) {
        // SAFETY: `raw` came from moon_engine_create and is destroyed once.
        // Destroy joins the engine thread, so no callback runs afterwards.
        unsafe { (self.api.destroy)(self.raw.as_ptr()) };
        // SAFETY: created by Box::into_raw in Engine::new and no longer used.
        drop(unsafe { Box::from_raw(self.auth) });
        // The log context may still be referenced by Chromium's process-wide
        // log handler, which outlives this engine: keep it alive.
        let _ = self.log;
    }
}

/// One Chromium network stack and its proxy configuration.
#[derive(Clone)]
pub struct Engine {
    inner: Arc<Inner>,
}
impl fmt::Debug for Engine {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Engine").finish_non_exhaustive()
    }
}

/// Path of the library in use, once loaded.
pub fn loaded_library() -> Option<&'static Path> {
    API.get().map(|(path, _)| path.as_path())
}

/// Load the library (if needed) and check the ABI without starting anything.
pub fn probe(library: Option<&Path>) -> Result<PathBuf, String> {
    load_api(library)?;
    Ok(loaded_library().expect("loaded").to_path_buf())
}

fn c_string(value: &str, what: &str) -> Result<CString, String> {
    CString::new(value).map_err(|_| format!("{what} contains a NUL byte"))
}

impl Engine {
    pub fn new(
        config: &Config,
        authenticator: Arc<dyn Authenticator>,
        logger: Option<Logger>,
    ) -> Result<Self, String> {
        let api = load_api(config.library.as_deref())?;
        let server_name = c_string(&config.server_name, "server_name")?;
        let connect_host = config
            .connect_host
            .as_deref()
            .map(|h| c_string(h, "connect_host"))
            .transpose()?;
        let ca_file = config
            .ca_file
            .as_deref()
            .map(|p| {
                p.to_str()
                    .ok_or_else(|| "ca_file path is not UTF-8".to_owned())
                    .and_then(|p| c_string(p, "ca_file"))
            })
            .transpose()?;
        let label = c_string(&config.exporter_label, "exporter_label")?;
        let ech = config.ech_config_list.as_deref().unwrap_or(&[]);
        let auth = Box::into_raw(Box::new(AuthContext { authenticator }));
        let log = Box::into_raw(Box::new(LogContext { logger }));
        let raw_config = ffi::Config {
            abi_version: ABI_VERSION,
            server_name: server_name.as_ptr(),
            connect_host: connect_host
                .as_ref()
                .map_or(std::ptr::null(), |h| h.as_ptr()),
            port: config.port,
            ca_file: ca_file.as_ref().map_or(std::ptr::null(), |p| p.as_ptr()),
            ech_config_list: if ech.is_empty() {
                std::ptr::null()
            } else {
                ech.as_ptr()
            },
            ech_config_list_len: ech.len(),
            exporter_label: label.as_ptr(),
            quic_idle_timeout_secs: u32::try_from(config.quic_idle_timeout.as_secs())
                .unwrap_or(u32::MAX)
                .max(1),
            auth_ctx: auth.cast(),
            authorize: Some(authorize_trampoline),
            verify: Some(verify_trampoline),
            log_ctx: log.cast(),
            log: Some(log_trampoline),
        };
        let mut error = [0 as c_char; 512];
        // SAFETY: all pointers are valid for the duration of the call; the
        // engine copies every string and the ECH list before returning.
        let raw = unsafe { (api.create)(&raw_config, error.as_mut_ptr(), error.len()) };
        let Some(raw) = NonNull::new(raw) else {
            // SAFETY: the engine did not keep the contexts.
            drop(unsafe { Box::from_raw(auth) });
            // SAFETY: as above.
            drop(unsafe { Box::from_raw(log) });
            // SAFETY: the engine NUL-terminates the message within capacity.
            let message = unsafe { std::ffi::CStr::from_ptr(error.as_ptr()) };
            return Err(format!(
                "the Chromium native engine failed to start: {}",
                message.to_string_lossy()
            ));
        };
        Ok(Self {
            inner: Arc::new(Inner {
                api,
                raw,
                auth,
                log,
            }),
        })
    }

    /// Hand one reference to `shared` to the engine and start the tunnel.
    /// Returns 0 (and keeps the reference) if the engine rejected it.
    fn start(&self, authority: &str, transport: Transport, shared: Arc<TunnelShared>) -> u64 {
        let ctx = Arc::into_raw(shared).cast_mut().cast::<c_void>();
        let callbacks = ffi::TunnelCallbacks {
            ctx,
            on_open: Some(on_open),
            on_read: Some(on_read),
            on_write: Some(on_write),
            on_shutdown: Some(on_shutdown),
            on_closed: Some(on_closed),
        };
        // SAFETY: the engine is alive (we hold `inner`); the authority and
        // callbacks are copied before returning. On success the engine owns
        // the reference to `shared` until on_closed.
        let id = unsafe {
            (self.inner.api.open)(
                self.inner.raw.as_ptr(),
                authority.as_ptr().cast(),
                authority.len(),
                transport.raw(),
                &callbacks,
            )
        };
        if id == 0 {
            // SAFETY: the engine did not take the reference (no callback runs).
            drop(unsafe { Arc::from_raw(ctx.cast::<TunnelShared>()) });
        }
        id
    }

    /// Open a tunnel to `authority` (`host:port` or `[v6]:port`) and wait for
    /// the proxy's verified confirmation.
    pub async fn open(
        &self,
        authority: &str,
        transport: Transport,
    ) -> Result<(Tunnel, Opened), OpenError> {
        let (open_tx, open_rx) = oneshot::channel();
        let (read_tx, read_rx) = mpsc::unbounded_channel();
        let (write_tx, write_rx) = mpsc::unbounded_channel();
        let shared = Arc::new(TunnelShared {
            open: Mutex::new(Some(open_tx)),
            read: read_tx,
            write: write_tx,
        });
        let id = self.start(authority, transport, shared);
        if id == 0 {
            return Err(OpenError::Invalid);
        }
        // From here on the tunnel is closed on every exit path.
        let handle = Arc::new(Handle {
            engine: self.inner.clone(),
            id,
        });
        let tunnel = Tunnel {
            reader: TunnelReader {
                handle: handle.clone(),
                rx: read_rx,
                pending: false,
                eof: false,
            },
            writer: TunnelWriter {
                handle,
                rx: write_rx,
                pending: false,
            },
        };
        let result = open_rx.await.map_err(|_| OpenError::Closed)?;
        let opened = match result.kind {
            ffi::OPEN_OK => Opened {
                transport: if result.transport == ffi::TRANSPORT_H3 as u8 {
                    Transport::H3
                } else {
                    Transport::H2
                },
                selection: result.selection,
            },
            ffi::OPEN_STATUS => {
                return Err(OpenError::Status(
                    u16::try_from(result.http_status).unwrap_or(0),
                ));
            }
            ffi::OPEN_CONFIRMATION => return Err(OpenError::Confirmation),
            ffi::OPEN_REFUSED => return Err(OpenError::Refused),
            ffi::OPEN_CONNECTION => {
                return Err(OpenError::Connection {
                    net_error: result.net_error,
                });
            }
            _ => return Err(OpenError::Confirmation),
        };
        Ok((tunnel, opened))
    }
}

/// Facts about an established tunnel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Opened {
    pub transport: Transport,
    /// Authenticated record mode selected by the server.
    pub selection: u8,
}

// ---------------------------------------------------------------------------
// Tunnels.

#[derive(Debug)]
enum ReadEvent {
    Data(Vec<u8>),
    Eof,
    Error(i32),
}

#[derive(Debug)]
enum WriteEvent {
    Write(i32),
    Shutdown(i32),
}

struct TunnelShared {
    open: Mutex<Option<oneshot::Sender<ffi::OpenResult>>>,
    read: mpsc::UnboundedSender<ReadEvent>,
    write: mpsc::UnboundedSender<WriteEvent>,
}

/// Closes the tunnel in the engine once both halves are gone. Closing a
/// tunnel whose directions both finished only releases it; otherwise the
/// stream is reset.
struct Handle {
    engine: Arc<Inner>,
    id: u64,
}
impl Drop for Handle {
    fn drop(&mut self) {
        // SAFETY: the engine is alive while we hold `engine`; on_closed then
        // releases the callback context on the engine thread.
        unsafe { (self.engine.api.close)(self.engine.raw.as_ptr(), self.id) };
    }
}

/// An established, confirmed CONNECT tunnel.
#[derive(Debug)]
pub struct Tunnel {
    reader: TunnelReader,
    writer: TunnelWriter,
}
impl Tunnel {
    /// Split into independently usable download and upload halves.
    pub fn into_split(self) -> (TunnelReader, TunnelWriter) {
        (self.reader, self.writer)
    }
    pub async fn read(&mut self) -> Result<Option<Vec<u8>>, IoError> {
        self.reader.read().await
    }
    pub async fn write_all(&mut self, data: &[u8]) -> Result<(), IoError> {
        self.writer.write_all(data).await
    }
    pub async fn shutdown(&mut self) -> Result<(), IoError> {
        self.writer.shutdown().await
    }
}

/// Download half.
pub struct TunnelReader {
    handle: Arc<Handle>,
    rx: mpsc::UnboundedReceiver<ReadEvent>,
    // Cancellation safety: a read whose future was dropped still owns the
    // single outstanding slot until its result is consumed.
    pending: bool,
    eof: bool,
}
impl fmt::Debug for TunnelReader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TunnelReader")
            .field("id", &self.handle.id)
            .finish()
    }
}

/// Upload half.
pub struct TunnelWriter {
    handle: Arc<Handle>,
    rx: mpsc::UnboundedReceiver<WriteEvent>,
    pending: bool,
}
impl fmt::Debug for TunnelWriter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TunnelWriter")
            .field("id", &self.handle.id)
            .finish()
    }
}

/// A tunnel I/O failure (stream reset or connection error).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IoError(pub i32);
impl fmt::Display for IoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "tunnel reset (net error {})", self.0)
    }
}
impl std::error::Error for IoError {}

const ERR_CONNECTION_CLOSED: i32 = -100;

impl TunnelReader {
    /// Read the next chunk from the peer; `Ok(None)` is a clean half-close.
    /// Cancellation safe.
    pub async fn read(&mut self) -> Result<Option<Vec<u8>>, IoError> {
        if self.eof {
            return Ok(None);
        }
        if !self.pending {
            let engine = &self.handle.engine;
            // SAFETY: the engine is alive; reading an unknown or closed
            // tunnel is a no-op.
            unsafe { (engine.api.read)(engine.raw.as_ptr(), self.handle.id, MAX_READ) };
            self.pending = true;
        }
        let event = self.rx.recv().await;
        self.pending = false;
        match event {
            Some(ReadEvent::Data(data)) => Ok(Some(data)),
            Some(ReadEvent::Eof) => {
                self.eof = true;
                Ok(None)
            }
            Some(ReadEvent::Error(error)) => Err(IoError(error)),
            None => Err(IoError(ERR_CONNECTION_CLOSED)),
        }
    }
}

impl TunnelWriter {
    async fn finish_pending(&mut self) -> Result<(), IoError> {
        if !self.pending {
            return Ok(());
        }
        let event = self.rx.recv().await;
        self.pending = false;
        match event {
            Some(WriteEvent::Write(n) | WriteEvent::Shutdown(n)) if n >= 0 => Ok(()),
            Some(WriteEvent::Write(error) | WriteEvent::Shutdown(error)) => Err(IoError(error)),
            None => Err(IoError(ERR_CONNECTION_CLOSED)),
        }
    }

    /// Write all of `data`. A cancelled write still completes in the engine
    /// before the next write or shutdown starts.
    pub async fn write_all(&mut self, data: &[u8]) -> Result<(), IoError> {
        self.finish_pending().await?;
        if data.is_empty() {
            return Ok(());
        }
        let engine = &self.handle.engine;
        // SAFETY: the engine copies `data` before returning.
        unsafe {
            (engine.api.write)(
                engine.raw.as_ptr(),
                self.handle.id,
                data.as_ptr(),
                data.len(),
            )
        };
        self.pending = true;
        self.finish_pending().await
    }

    /// Half-close the upload direction after all written data.
    pub async fn shutdown(&mut self) -> Result<(), IoError> {
        self.finish_pending().await?;
        let engine = &self.handle.engine;
        // SAFETY: the engine is alive.
        unsafe { (engine.api.shutdown_write)(engine.raw.as_ptr(), self.handle.id) };
        self.pending = true;
        self.finish_pending().await
    }
}

// ---------------------------------------------------------------------------
// Callback trampolines. Each one contains panics: unwinding into C++ is
// undefined behavior.

fn guard<T>(fallback: T, f: impl FnOnce() -> T) -> T {
    catch_unwind(AssertUnwindSafe(f)).unwrap_or(fallback)
}

/// # Safety
/// `ctx` is the TunnelShared reference handed to moon_tunnel_open, valid
/// until on_closed.
unsafe fn shared<'a>(ctx: *mut c_void) -> &'a TunnelShared {
    // SAFETY: guaranteed by the caller.
    unsafe { &*ctx.cast::<TunnelShared>() }
}

fn binding(raw: &ffi::Binding) -> Binding {
    Binding {
        exporter: raw.exporter,
        stream_id: raw.stream_id,
        ech_accepted: raw.ech_accepted != 0,
        http_version: raw.http_version,
    }
}

/// # Safety
/// `ptr`/`len` must describe a readable byte range (or len 0).
unsafe fn bytes<'a>(ptr: *const c_char, len: usize) -> &'a [u8] {
    if len == 0 || ptr.is_null() {
        &[]
    } else {
        // SAFETY: guaranteed by the caller.
        unsafe { std::slice::from_raw_parts(ptr.cast(), len) }
    }
}

unsafe extern "C" fn authorize_trampoline(
    ctx: *mut c_void,
    raw: *const ffi::Binding,
    authority: *const c_char,
    authority_len: usize,
    out: *mut u8,
    out_cap: usize,
    out_len: *mut usize,
) -> c_int {
    guard(-1, || {
        // SAFETY: the engine passes the auth context, a valid binding, the
        // authority bytes and an output buffer of out_cap bytes.
        let (context, raw, authority) = unsafe {
            (
                &*ctx.cast::<AuthContext>(),
                &*raw,
                bytes(authority, authority_len),
            )
        };
        let Ok(authority) = std::str::from_utf8(authority) else {
            return -1;
        };
        let Some(value) = context.authenticator.authorize(&binding(raw), authority) else {
            return -1;
        };
        if value.is_empty() || value.len() > out_cap.min(MAX_AUTHORIZATION) {
            return -1;
        }
        // SAFETY: bounds checked above.
        unsafe {
            std::ptr::copy_nonoverlapping(value.as_ptr(), out, value.len());
            *out_len = value.len();
        }
        0
    })
}

unsafe extern "C" fn verify_trampoline(
    ctx: *mut c_void,
    raw: *const ffi::Binding,
    authority: *const c_char,
    authority_len: usize,
    values: *const *const c_char,
    value_lens: *const usize,
    count: usize,
) -> u8 {
    guard(0, || {
        // SAFETY: the engine passes `count` (pointer, length) pairs that stay
        // valid for the call.
        let (context, raw, authority, values) = unsafe {
            let values: Vec<&[u8]> = (0..count)
                .map(|i| bytes(*values.add(i), *value_lens.add(i)))
                .collect();
            (
                &*ctx.cast::<AuthContext>(),
                &*raw,
                bytes(authority, authority_len),
                values,
            )
        };
        let Ok(authority) = std::str::from_utf8(authority) else {
            return 0;
        };
        context
            .authenticator
            .verify(&binding(raw), authority, &values)
            .unwrap_or(0)
    })
}

unsafe extern "C" fn log_trampoline(
    ctx: *mut c_void,
    level: c_int,
    msg: *const c_char,
    len: usize,
) {
    guard((), || {
        // SAFETY: the log context outlives every engine; the message is valid
        // for the call.
        let (context, message) = unsafe { (&*ctx.cast::<LogContext>(), bytes(msg, len)) };
        if let Some(logger) = &context.logger {
            let level = match level {
                0 => LogLevel::Info,
                1 => LogLevel::Warning,
                _ => LogLevel::Error,
            };
            logger(level, &String::from_utf8_lossy(message));
        }
    });
}

unsafe extern "C" fn on_open(ctx: *mut c_void, result: *const ffi::OpenResult) {
    guard((), || {
        // SAFETY: valid context and result for the call.
        let (shared, result) = unsafe { (shared(ctx), &*result) };
        if let Some(sender) = shared.open.lock().ok().and_then(|mut s| s.take()) {
            let _ = sender.send(ffi::OpenResult {
                kind: result.kind,
                transport: result.transport,
                selection: result.selection,
                net_error: result.net_error,
                http_status: result.http_status,
            });
        }
    });
}

unsafe extern "C" fn on_read(ctx: *mut c_void, result: i32, data: *const u8) {
    guard((), || {
        // SAFETY: valid context; `data` holds `result` bytes when positive.
        let shared = unsafe { shared(ctx) };
        let event = match result {
            n if n > 0 => {
                // SAFETY: as above.
                let data = unsafe { bytes(data.cast(), n as usize) };
                ReadEvent::Data(data.to_vec())
            }
            0 => ReadEvent::Eof,
            error => ReadEvent::Error(error),
        };
        let _ = shared.read.send(event);
    });
}

unsafe extern "C" fn on_write(ctx: *mut c_void, result: i32) {
    guard((), || {
        // SAFETY: valid context.
        let _ = unsafe { shared(ctx) }.write.send(WriteEvent::Write(result));
    });
}

unsafe extern "C" fn on_shutdown(ctx: *mut c_void, result: i32) {
    guard((), || {
        // SAFETY: valid context.
        let _ = unsafe { shared(ctx) }
            .write
            .send(WriteEvent::Shutdown(result));
    });
}

unsafe extern "C" fn on_closed(ctx: *mut c_void) {
    guard((), || {
        // SAFETY: last callback for this tunnel; releases the engine's
        // reference taken in Engine::open.
        drop(unsafe { Arc::from_raw(ctx.cast::<TunnelShared>()) });
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn layouts_match_the_c_header() {
        // Offsets per the C struct rules for moon_engine.h on LP64.
        assert_eq!(std::mem::size_of::<ffi::Binding>(), 48);
        assert_eq!(std::mem::size_of::<ffi::OpenResult>(), 12);
        assert_eq!(std::mem::size_of::<ffi::TunnelCallbacks>(), 48);
        assert_eq!(std::mem::size_of::<ffi::Config>(), 112);
    }

    #[test]
    fn missing_library_error_is_actionable() {
        let error = probe(Some(Path::new("/nonexistent/libmoon_engine.so"))).unwrap_err();
        assert!(error.contains("cargo xtask engine build"), "{error}");
        assert!(error.contains(LIBRARY_ENV), "{error}");
    }

    #[test]
    fn binding_debug_hides_the_exporter() {
        let text = format!(
            "{:?}",
            Binding {
                exporter: [0xab; 32],
                stream_id: 0,
                ech_accepted: true,
                http_version: 3
            }
        );
        assert!(!text.contains("171") && !text.contains("ab"), "{text}");
    }
}
