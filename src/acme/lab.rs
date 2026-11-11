//! Default-test ACME laboratory. All keys, CAs and endpoints are synthetic.
use super::lab_support::{Capture, Case};
use super::{
    Result,
    certificate::{Candidate, Validator},
    crypto::CRYPTO,
    dns::DnsProvider,
    http::Http,
    manager::Manager,
    persist::{Journal, Order, State},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as B64};
use boring::{
    asn1::Asn1Time,
    bn::BigNum,
    pkey::{PKey, Private},
    ssl::{SslAcceptor, SslMethod},
    x509::{
        X509, X509NameBuilder, X509Req,
        extension::{
            AuthorityKeyIdentifier, BasicConstraints, KeyUsage, SubjectAlternativeName,
            SubjectKeyIdentifier,
        },
    },
};
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use moon_naive_core::config::Config;
use serde_json::{Value, json};
use std::{
    fs,
    io::Write,
    path::PathBuf,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use tokio::net::TcpListener;

#[derive(Clone, Debug, PartialEq)]
pub(crate) enum Mode {
    Normal,
    Nonce404,
    Order404,
    RecoverProcessing,
    RecoveryRetry(&'static str),
    Dns(&'static str),
    Retry(&'static str),
    AriRate(&'static str),
    Certificate(usize),
    CertificatePem(usize),
    CertificateKind(&'static str),
    Stall(&'static str),
    NonceReject(usize, bool),
}
pub(crate) struct Environment {
    pub case: Case,
    pub base: String,
    pub ca_file: PathBuf,
    pub port: u16,
    issuer: Arc<Issuer>,
    tls: Arc<boring::ssl::SslAcceptor>,
    pub state: Arc<Mutex<Mock>>,
    task: tokio::task::JoinHandle<()>,
}
pub(crate) struct Mock {
    pub mode: Mode,
    pub requests: Vec<String>,
    pub creates: usize,
    faults: usize,
    records: Vec<Value>,
    count: usize,
    nonce_rejected: usize,
    pub domain: String,
    csr: Vec<u8>,
    certificate_cache: Option<Vec<u8>>,
    finalized: bool,
    serial: u32,
    replaces: Value,
    jwk: Option<Value>,
    pub finalized_at: Option<Instant>,
    pub poll_delay: Option<Duration>,
}
struct Issuer {
    cert: X509,
    key: PKey<Private>,
}
impl Issuer {
    fn new() -> Self {
        let key = super::crypto::p256().unwrap();
        let mut name = X509NameBuilder::new().unwrap();
        name.append_entry_by_text("CN", "ACME lab synthetic root")
            .unwrap();
        let name = name.build();
        let mut cert = X509::builder().unwrap();
        cert.set_version(2).unwrap();
        cert.set_subject_name(&name).unwrap();
        cert.set_issuer_name(&name).unwrap();
        cert.set_pubkey(&key).unwrap();
        cert.set_serial_number(&BigNum::from_u32(1).unwrap().to_asn1_integer().unwrap())
            .unwrap();
        cert.set_not_before(&Asn1Time::from_unix(super::now() as i64 - 3600).unwrap())
            .unwrap();
        cert.set_not_after(&Asn1Time::days_from_now(2).unwrap())
            .unwrap();
        cert.append_extension(&BasicConstraints::new().critical().ca().build().unwrap())
            .unwrap();
        cert.append_extension(&KeyUsage::new().key_cert_sign().crl_sign().build().unwrap())
            .unwrap();
        cert.append_extension(
            &SubjectKeyIdentifier::new()
                .build(&cert.x509v3_context(None, None))
                .unwrap(),
        )
        .unwrap();
        cert.sign(&key, boring::hash::MessageDigest::sha256())
            .unwrap();
        Self {
            cert: cert.build(),
            key,
        }
    }
    fn sign<T: boring::pkey::HasPublic>(
        &self,
        key: &boring::pkey::PKeyRef<T>,
        domain: &str,
        serial: u32,
        lifetime: u64,
    ) -> Vec<u8> {
        self.sign_variant(key, domain, serial, lifetime, "normal")
    }
    fn sign_variant<T: boring::pkey::HasPublic>(
        &self,
        key: &boring::pkey::PKeyRef<T>,
        domain: &str,
        serial: u32,
        lifetime: u64,
        kind: &str,
    ) -> Vec<u8> {
        let mut name = X509NameBuilder::new().unwrap();
        name.append_entry_by_text("CN", domain).unwrap();
        let mut cert = X509::builder().unwrap();
        cert.set_version(2).unwrap();
        cert.set_subject_name(&name.build()).unwrap();
        cert.set_issuer_name(self.cert.subject_name()).unwrap();
        cert.set_pubkey(key).unwrap();
        cert.set_serial_number(&BigNum::from_u32(serial).unwrap().to_asn1_integer().unwrap())
            .unwrap();
        cert.set_not_before(
            &Asn1Time::from_unix(super::now() as i64 + if kind == "future" { 4 } else { -1 })
                .unwrap(),
        )
        .unwrap();
        cert.set_not_after(
            &Asn1Time::from_unix(super::now().saturating_add(lifetime) as i64).unwrap(),
        )
        .unwrap();
        cert.append_extension(&BasicConstraints::new().critical().build().unwrap())
            .unwrap();
        if kind == "eku" {
            cert.append_extension(
                &boring::x509::extension::ExtendedKeyUsage::new()
                    .client_auth()
                    .build()
                    .unwrap(),
            )
            .unwrap();
        }
        let mut san = SubjectAlternativeName::new();
        san.dns(domain);
        if domain == "localhost" {
            san.ip("127.0.0.1");
        }
        cert.append_extension(
            &san.build(&cert.x509v3_context(Some(&self.cert), None))
                .unwrap(),
        )
        .unwrap();
        cert.append_extension(
            &AuthorityKeyIdentifier::new()
                .keyid(true)
                .build(&cert.x509v3_context(Some(&self.cert), None))
                .unwrap(),
        )
        .unwrap();
        cert.sign(&self.key, boring::hash::MessageDigest::sha256())
            .unwrap();
        let mut bytes = cert.build().to_pem().unwrap();
        bytes.extend(self.cert.to_pem().unwrap());
        bytes
    }
}
impl Drop for Environment {
    fn drop(&mut self) {
        self.task.abort();
    }
}
impl Environment {
    pub async fn start(name: &str, mode: Mode) -> Self {
        let case = Case::new(name);
        let issuer = Arc::new(Issuer::new());
        let ca_file = case.path().join("ca.pem");
        fs::write(&ca_file, issuer.cert.to_pem().unwrap()).unwrap();
        let key = super::crypto::p256().unwrap();
        let chain = issuer.sign(&key, "localhost", 2, 86400);
        let chain = X509::stack_from_pem(&chain).unwrap();
        let mut tls = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls()).unwrap();
        tls.set_certificate(&chain[0]).unwrap();
        tls.set_private_key(&key).unwrap();
        tls.add_extra_chain_cert(issuer.cert.clone()).unwrap();
        let keys = case.keylog();
        tls.set_keylog_callback(move |_, line| {
            let mut file = keys.lock().unwrap();
            writeln!(file, "{line}").unwrap();
            file.flush().unwrap();
        });
        let tls = Arc::new(tls.build());
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let base = format!("https://localhost:{port}");
        let state = Arc::new(Mutex::new(Mock {
            mode,
            requests: vec![],
            creates: 0,
            faults: 0,
            records: vec![],
            count: 0,
            nonce_rejected: 0,
            domain: "acme.example.test".into(),
            csr: vec![],
            certificate_cache: None,
            finalized: false,
            serial: 10,
            replaces: Value::Null,
            jwk: None,
            finalized_at: None,
            poll_delay: None,
        }));
        let shared = state.clone();
        let log = case.clone();
        let address = base.clone();
        let ca = issuer.clone();
        let retained_tls = tls.clone();
        let task = tokio::spawn(async move {
            let mut tasks = tokio::task::JoinSet::new();
            loop {
                tokio::select! {
                    Some(_)=tasks.join_next(),if !tasks.is_empty()=>{},
                    accepted=listener.accept()=>{let(socket,_)=accepted.unwrap();let tls=tls.clone();let state=shared.clone();let log=log.clone();let base=address.clone();let ca=ca.clone();tasks.spawn(async move {let Ok(stream)=tokio_boring::accept(&tls,socket).await else{return;};let service=hyper::service::service_fn(move |request:hyper::Request<hyper::body::Incoming>| {let state=state.clone();let log=log.clone();let base=base.clone();let ca=ca.clone();async move {let(parts,body)=request.into_parts();let body=body.collect().await.unwrap().to_bytes();let response=respond(parts,body,&base,&state,&log,&ca).await;Ok::<_,std::convert::Infallible>(response)}});let _=hyper::server::conn::http1::Builder::new().serve_connection(hyper_util::rt::TokioIo::new(stream),service).await;});}
                }
            }
        });
        case.event("server",json!({"port":port,"pid":std::process::id(),"base":base,"mode":format!("{:?}",state.lock().unwrap().mode)}));
        Self {
            case,
            base,
            ca_file,
            port,
            issuer,
            tls: retained_tls,
            state,
            task,
        }
    }
    pub fn capture(&self) -> Option<Capture> {
        self.case.capture(&[self.port, 53])
    }
    pub fn http(&self) -> Http {
        Http::new(Some(&self.ca_file), Duration::from_secs(5)).unwrap()
    }
    pub fn config(&self) -> Config {
        let mut config = Config::parse(include_str!("../../config.example.toml")).unwrap();
        config.domain = self.state.lock().unwrap().domain.clone();
        config.acme.accept_terms = true;
        config.acme.eab = None;
        config.acme.issuer = moon_naive_core::config::Issuer::Letsencrypt;
        config.acme.dns_zone = Some("example.test".into());
        config.acme.directory_url = Some(format!("{}/dir", self.base));
        config.acme.certificate_ca_file = Some(self.ca_file.clone());
        config.acme.directory_ca_file = Some(self.ca_file.clone());
        config.acme.renew_before_secs = 4;
        config.acme.operation_timeout_secs = 30;
        config.acme.retry_initial_secs = 1;
        config.acme.retry_max_secs = 2;
        config.state_dir = self.case.path().join("state");
        config
    }
    pub(crate) fn panic_provider(
        &self,
        exit: std::sync::mpsc::Receiver<()>,
    ) -> Box<dyn DnsProvider> {
        Box::new(NoDns {
            panic: Some(self.case.clone()),
            exit_barrier: Some(exit),
        })
    }
    pub fn provider(&self, kind: &str) -> Box<dyn DnsProvider> {
        match kind {
            "cloudflare" => Box::new(super::dns::Cloudflare::laboratory(
                self.http(),
                self.base.clone(),
            )),
            "porkbun" => Box::new(super::porkbun::Porkbun::laboratory(
                self.http(),
                self.base.clone(),
            )),
            _ => Box::new(NoDns {
                panic: None,
                exit_barrier: None,
            }),
        }
    }
    pub fn seed(&self, config: &Config, provider: &dyn DnsProvider) {
        let (signer, key) = CRYPTO.key_provider.generate_key().unwrap();
        self.state.lock().unwrap().jwk = Some(serde_json::to_value(signer.as_jwk()).unwrap());
        let (key_pem, csr) = super::certificate::csr(&config.domain).unwrap();
        let namespace = boring::sha::sha256(
            format!("{}\0{}", config.acme.directory(), config.domain).as_bytes(),
        )
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
        let state = State::open(&config.state_dir.join("acme"), &namespace).unwrap();
        state
            .save(&Journal {
                version: 2,
                domain: config.domain.clone(),
                directory: config.acme.directory().into(),
                dns_identity: provider.identity(),
                account_key: key.secret_pkcs8_der().to_vec(),
                account_id: Some(format!("{}/acct/1", self.base)),
                order: Some(Order {
                    url: format!("{}/order/1", self.base),
                    key_pem,
                    csr,
                }),
                ..Journal::default()
            })
            .unwrap();
    }
    pub fn outer(&self, lifetime: u64) -> (PathBuf, PathBuf) {
        use std::os::unix::fs::PermissionsExt;
        let key = super::crypto::p256().unwrap();
        let cert = self.case.path().join("outer.pem");
        let private = self.case.path().join("outer.key");
        fs::write(
            &cert,
            self.issuer.sign(&key, "public.example.test", 42, lifetime),
        )
        .unwrap();
        fs::write(&private, key.private_key_to_pem_pkcs8().unwrap()).unwrap();
        fs::set_permissions(&private, fs::Permissions::from_mode(0o600)).unwrap();
        (cert, private)
    }
    pub fn install_old(&self, config: &Config) {
        let key = super::crypto::p256().unwrap();
        let candidate = Candidate {
            chain_pem: self.issuer.sign(&key, &config.domain, 3, 86400),
            key_pem: key.private_key_to_pem_pkcs8().unwrap(),
        };
        let verified = Validator::for_config(config)
            .unwrap()
            .verify(candidate, super::now())
            .unwrap();
        super::persist::DiskStore::open(&config.state_dir.join("certificates"))
            .unwrap()
            .install(&verified)
            .unwrap();
    }
}
struct NoDns {
    panic: Option<Case>,
    exit_barrier: Option<std::sync::mpsc::Receiver<()>>,
}
impl Drop for NoDns {
    fn drop(&mut self) {
        if let Some(release) = self.exit_barrier.take() {
            self.panic
                .as_ref()
                .unwrap()
                .event("control_exit_blocked", json!({}));
            let _ = release.recv();
        }
    }
}
#[async_trait::async_trait]
impl DnsProvider for NoDns {
    fn identity(&self) -> String {
        "lab-none".into()
    }
    async fn prepare(&mut self, _: &mut super::persist::Lease) -> Result<()> {
        if let Some(case) = &self.panic {
            case.event("control_fault", json!({"stage":"dns-prepare"}));
            panic!("injected control provider panic");
        }
        Ok(())
    }
    async fn present(&mut self, _: &mut super::persist::Lease) -> Result<()> {
        Err("unexpected DNS creation".into())
    }
    async fn propagated(&mut self, _: &super::persist::Lease) -> Result<bool> {
        Ok(true)
    }
    async fn cleanup(&mut self, _: &super::persist::Lease) -> Result<()> {
        Ok(())
    }
}
fn problem(kind: &str) -> Value {
    json!({"type":format!("urn:ietf:params:acme:error:{kind}"),"detail":"synthetic laboratory response"})
}
async fn respond(
    parts: hyper::http::request::Parts,
    body: Bytes,
    base: &str,
    state: &Arc<Mutex<Mock>>,
    case: &Case,
    issuer: &Issuer,
) -> hyper::Response<Full<Bytes>> {
    let path = parts.uri.path().to_owned();
    let method = parts.method.to_string();
    let envelope: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
    let protected: Value = envelope["protected"]
        .as_str()
        .and_then(|s| B64.decode(s).ok())
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or(Value::Null);
    let payload_bytes = envelope["payload"]
        .as_str()
        .and_then(|s| B64.decode(s).ok())
        .unwrap_or_default();
    let payload: Value = serde_json::from_slice(&payload_bytes).unwrap_or(Value::Null);
    let (mode, number) = {
        let mut shared = state.lock().unwrap();
        shared.requests.push(format!("{method} {path}"));
        shared.count += 1;
        (shared.mode.clone(), shared.count)
    };
    let signature_valid = if envelope["signature"].is_string() {
        let shared = state.lock().unwrap();
        Some(verify_envelope(&envelope, &protected, shared.jwk.as_ref()))
    } else {
        None
    };
    let url_matches = protected["url"]
        .as_str()
        .map(|url| url == format!("{base}{}", parts.uri));
    case.event("request",json!({"method":method,"path":path,"protected":protected,"payload":payload,"payload_empty":payload_bytes.is_empty(),"bytes":body.len(),"jose_signature_valid":signature_valid,"protected_url_matches":url_matches}));
    if signature_valid.is_some() {
        assert_eq!(
            signature_valid,
            Some(true),
            "independent ES256 r||s verification"
        );
        assert_eq!(
            url_matches,
            Some(true),
            "JWS protected.url must match request URL"
        );
    }
    if matches!(mode, Mode::Stall("headers")) {
        tokio::time::sleep(Duration::from_secs(3)).await;
    }
    let mut status = 200;
    let mut extra = vec![];
    let mut raw = None;
    let order_state = |shared: &Mock, status: &str| json!({"status":status,"identifiers":[{"type":"dns","value":shared.domain}],"authorizations":[format!("{base}/authz/1")],"finalize":format!("{base}/finalize/1"),"certificate":format!("{base}/certificate/1"),"replaces":shared.replaces});
    let value = if path == "/dir" {
        json!({"newNonce":format!("{base}/new-nonce"),"newAccount":format!("{base}/new-account"),"newOrder":format!("{base}/new-order"),"revokeCert":format!("{base}/revoke"),"keyChange":format!("{base}/key-change"),"renewalInfo":format!("{base}/renewal-info")})
    } else if path == "/new-nonce" {
        if mode == Mode::Nonce404 && number > 3 {
            status = 404;
            problem("malformed")
        } else {
            json!({})
        }
    } else if let Mode::NonceReject(rejects, nonce) = mode.clone()
        && method == "POST"
        && {
            let mut shared = state.lock().unwrap();
            let reject = shared.nonce_rejected < rejects;
            if reject {
                shared.nonce_rejected += 1;
            }
            reject
        }
    {
        status = 400;
        if !nonce {
            extra.push(("no-nonce".to_owned(), "1".to_owned()));
        }
        problem("badNonce")
    } else if path == "/new-account" {
        status = 201;
        extra.push(("location".into(), format!("{base}/acct/1")));
        state.lock().unwrap().jwk = Some(protected["jwk"].clone());
        json!({"status":"valid"})
    } else if path == "/acct/1" {
        json!({"status":"valid"})
    } else if path == "/new-order" {
        status = 201;
        extra.push(("location".into(), format!("{base}/order/1")));
        let mut s = state.lock().unwrap();
        s.domain = payload["identifiers"][0]["value"]
            .as_str()
            .unwrap_or(&s.domain)
            .to_owned();
        s.finalized = false;
        s.replaces = payload["replaces"].clone();
        s.certificate_cache = None;
        order_state(&s, "ready")
    } else if path == "/order/1" {
        let mut s = state.lock().unwrap();
        if s.finalized {
            s.poll_delay = s.finalized_at.map(|t| t.elapsed());
        }
        if mode == Mode::Order404 {
            status = 404;
            problem("malformed")
        } else {
            if let Mode::RecoveryRetry(value) = &mode {
                extra.push(("retry-after".into(), (*value).into()));
            }
            if s.finalized
                && let Mode::Retry(value) = &mode
            {
                extra.push(("retry-after".into(), (*value).into()));
            }
            order_state(
                &s,
                if matches!(mode, Mode::Dns(_)) {
                    "pending"
                } else if matches!(mode, Mode::RecoverProcessing | Mode::RecoveryRetry(_))
                    && s.requests
                        .iter()
                        .filter(|r| r.as_str() == "POST /order/1")
                        .count()
                        < 2
                {
                    "processing"
                } else if s.finalized {
                    "valid"
                } else {
                    "ready"
                },
            )
        }
    } else if path == "/authz/1" {
        let s = state.lock().unwrap();
        json!({"identifier":{"type":"dns","value":s.domain},"status":"pending","challenges":[{"type":"dns-01","url":format!("{base}/challenge/1"),"status":"pending","token":"synthetic-token"}]})
    } else if path == "/finalize/1" {
        let mut s = state.lock().unwrap();
        s.csr = B64.decode(payload["csr"].as_str().unwrap()).unwrap();
        let req = X509Req::from_der(&s.csr).unwrap();
        assert!(req.verify(&req.public_key().unwrap()).unwrap());
        s.finalized = true;
        s.finalized_at = Some(Instant::now());
        s.serial += 1;
        if let Mode::Retry(value) = &mode {
            extra.push(("retry-after".into(), (*value).into()));
        }
        order_state(&s, "processing")
    } else if path == "/certificate/1" {
        let mut s = state.lock().unwrap();
        let bytes = if let Mode::Certificate(size) = mode {
            vec![b'X'; size]
        } else if let Mode::CertificatePem(size) = mode {
            let req = X509Req::from_der(&s.csr).unwrap();
            let mut bytes = issuer.sign(&req.public_key().unwrap(), &s.domain, s.serial, 12);
            bytes.resize(size, b'\n');
            bytes
        } else if let Mode::CertificateKind(kind) = mode {
            if let Some(cached) = &s.certificate_cache {
                cached.clone()
            } else {
                let req = X509Req::from_der(&s.csr).unwrap();
                let bytes = match kind {
                    "san" => issuer.sign(
                        &req.public_key().unwrap(),
                        "other.example.test",
                        s.serial,
                        60,
                    ),
                    "key" => issuer.sign(&super::crypto::p256().unwrap(), &s.domain, s.serial, 60),
                    "chain" => {
                        Issuer::new().sign(&req.public_key().unwrap(), &s.domain, s.serial, 60)
                    }
                    _ => issuer.sign_variant(
                        &req.public_key().unwrap(),
                        &s.domain,
                        s.serial,
                        60,
                        kind,
                    ),
                };
                s.certificate_cache = Some(bytes.clone());
                bytes
            }
        } else {
            let req = X509Req::from_der(&s.csr).unwrap();
            issuer.sign(&req.public_key().unwrap(), &s.domain, s.serial, 12)
        };
        raw = Some(bytes);
        json!({})
    } else if path.starts_with("/renewal-info") {
        extra.push((
            "retry-after".into(),
            if let Mode::Retry(v) | Mode::AriRate(v) = mode {
                v.into()
            } else {
                "3600".into()
            },
        ));
        if matches!(mode, Mode::AriRate(_)) {
            status = 429;
            problem("rateLimited")
        } else {
            json!({"suggestedWindow":{"start":"2030-01-01T00:00:00Z","end":"2020-01-01T00:00:00Z"}})
        }
    } else if path.starts_with("/zones/")
        || path.starts_with("/domain/")
        || path.starts_with("/dns/")
    {
        provider_response(&path, &method, &body, &mode, state, &mut status)
    } else {
        status = 404;
        problem("malformed")
    };
    if mode == Mode::Dns("late")
        && ((path.ends_with("dns_records") && method == "POST") || path.contains("/create/"))
    {
        let state = state.clone();
        let case = case.clone();
        let mut record: Value = serde_json::from_slice(&body).unwrap();
        let porkbun = path.contains("/create/");
        if porkbun {
            record["name"] = json!(format!("{}.example.test", record["name"].as_str().unwrap()));
        }
        record["id"] = json!(if porkbun { "10" } else { "bbbb" });
        case.event("create_submitted", json!({"record":record}));
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(1200)).await;
            state.lock().unwrap().records.push(record.clone());
            case.event("remote_commit", json!({"record":record}));
        });
        tokio::time::sleep(Duration::from_secs(3)).await;
    }
    let mut response = hyper::Response::builder()
        .status(status)
        .header("content-type", "application/json");
    if !extra.iter().any(|(k, _)| k == "no-nonce") {
        response = response.header("replay-nonce", format!("nonce-{number}"));
    }
    for (k, v) in &extra {
        if k != "no-nonce" {
            response = response.header(k, v);
        }
    }
    case.event("response",json!({"method":method,"path":path,"status":status,"headers":extra,"body_length":raw.as_ref().map(Vec::len),"problem_type":value.get("type")}));
    response
        .body(Full::new(Bytes::from(
            raw.unwrap_or_else(|| serde_json::to_vec(&value).unwrap()),
        )))
        .unwrap()
}
fn provider_response(
    path: &str,
    method: &str,
    body: &Bytes,
    mode: &Mode,
    state: &Mutex<Mock>,
    status: &mut u16,
) -> Value {
    let mut s = state.lock().unwrap();
    let input: Value = serde_json::from_slice(body).unwrap_or(Value::Null);
    let discovery = path.ends_with(&"a".repeat(32)) || path.contains("getNs");
    let list = (path.contains("dns_records") && method == "GET") || path.contains("retrieve");
    let create = (path.ends_with("dns_records") && method == "POST") || path.contains("/create/");
    if (discovery && mode == &Mode::Dns("discover")) || (list && mode == &Mode::Dns("list")) {
        s.faults += 1;
        *status = 503;
        return json!({"success":false,"status":"ERROR"});
    }
    if create {
        s.creates += 1;
        if mode == &Mode::Dns("late") {
            return json!({"success":true,"result":{"id":"bbbb"},"status":"SUCCESS","id":"10"});
        }
        s.faults += 1;
        *status = 403;
        return json!({"success":false,"status":"ERROR"});
    }
    if method == "DELETE" || path.contains("/delete/") {
        let id = path.rsplit('/').next().unwrap();
        s.records.retain(|record| record["id"] != id);
        return json!({"success":true,"status":"SUCCESS"});
    }
    if discovery {
        json!({"success":true,"result":{"name":"example.test","name_servers":["127.0.0.1"]},"status":"SUCCESS","ns":["curitiba.porkbun.com"]})
    } else if list {
        json!({"success":true,"result":s.records,"result_info":{"total_pages":1},"status":"SUCCESS","records":s.records})
    } else {
        let _ = input;
        json!({"success":true,"status":"SUCCESS"})
    }
}

async fn dns_case(kind: &str, phase: &'static str) {
    let env = Environment::start(&format!("dns-{kind}-{phase}"), Mode::Dns(phase)).await;
    let _capture = env.capture();
    let config = env.config();
    let provider = env.provider(kind);
    env.seed(&config, &*provider);
    let mut manager = Manager::open(&config, provider, env.http()).unwrap();
    let result = manager.tick().await;
    env.case.event(
        "tick",
        json!({"result":format!("{result:?}"),"creates":env.state.lock().unwrap().creates}),
    );
    env.case.journal(&config.state_dir, "after-failure");
    assert_eq!(result.unwrap(), super::manager::Tick::RetryScheduled);
    assert_eq!(
        env.state.lock().unwrap().faults,
        1,
        "named provider fault must be reached"
    );
    assert_eq!(
        env.state.lock().unwrap().creates,
        usize::from(phase == "reject"),
        "fault must occur at the intended provider phase"
    );
    env.state.lock().unwrap().mode = Mode::Normal;
    let cleanup = manager.cleanup().await;
    let after = env.case.journal(&config.state_dir, "after-recovery");
    env.case.event(
        "recovery",
        json!({"result":format!("{cleanup:?}"),"creates":env.state.lock().unwrap().creates}),
    );
    assert!(
        cleanup.is_ok() && after["leases"].as_array().unwrap().is_empty(),
        "confirmed pre-write/rejection failure must recover without forgetting an uncertain POST; see {}",
        env.case.path().display()
    );
}
macro_rules! dns_tests {($($name:ident,$kind:literal,$phase:literal;)*)=>{$(#[tokio::test]async fn $name(){dns_case($kind,$phase).await;})*};}
dns_tests! {
 cloudflare_discovery_failure_recovers,"cloudflare","discover";
 cloudflare_list_failure_recovers,"cloudflare","list";
 cloudflare_confirmed_create_rejection_recovers,"cloudflare","reject";
 porkbun_discovery_failure_recovers,"porkbun","discover";
 porkbun_list_failure_recovers,"porkbun","list";
 porkbun_confirmed_create_rejection_recovers,"porkbun","reject";
}
async fn status_case(mode: Mode, should_keep: bool) {
    let env = Environment::start(if should_keep { "nonce404" } else { "order404" }, mode).await;
    let _capture = env.capture();
    let config = env.config();
    let provider = env.provider("none");
    env.seed(&config, &*provider);
    let before = env.case.journal(&config.state_dir, "before");
    let mut manager = Manager::open(&config, provider, env.http()).unwrap();
    let result = manager.tick().await;
    env.case
        .event("tick", json!({"result":format!("{result:?}")}));
    let after = env.case.journal(&config.state_dir, "after");
    let requests = env.state.lock().unwrap().requests.clone();
    env.case.write("requests.json", &json!(requests));
    if should_keep {
        assert!(!requests.iter().any(|s| s == "POST /order/1"));
        assert_eq!(
            after["order"], before["order"],
            "newNonce 404 must not retire an unrequested existing order"
        );
    } else {
        assert!(requests.iter().any(|s| s == "POST /order/1"));
        assert!(after["order"].is_null());
    }
}
#[tokio::test]
async fn nonce_endpoint_404_preserves_existing_order() {
    status_case(Mode::Nonce404, true).await;
}
#[tokio::test]
async fn order_endpoint_404_is_attributed_to_order() {
    status_case(Mode::Order404, false).await;
}

async fn retry_case(value: &'static str, required: Option<Duration>) {
    let env = Environment::start("retry-after", Mode::Retry(value)).await;
    let _capture = env.capture();
    let mut config = env.config();
    config.acme.operation_timeout_secs = 130;
    let provider = env.provider("none");
    env.seed(&config, &*provider);
    let mut manager = Manager::open(&config, provider, env.http()).unwrap();
    let result = manager.tick().await;
    env.case.event("tick",json!({"result":format!("{result:?}"),"header":value,"first_poll_ms":env.state.lock().unwrap().poll_delay.map(|d|d.as_millis())}));
    env.case.journal(&config.state_dir, "after");
    assert!(
        env.state
            .lock()
            .unwrap()
            .requests
            .iter()
            .any(|r| r == "POST /finalize/1"),
        "the intended finalize stage must be exercised"
    );
    if value == "18446744073709551615" {
        assert_eq!(result.unwrap(), super::manager::Tick::RetryScheduled);
        return;
    }
    assert_eq!(result.unwrap(), super::manager::Tick::Installed);
    if let Some(required) = required {
        assert!(
            env.state
                .lock()
                .unwrap()
                .poll_delay
                .is_some_and(|delay| delay >= required),
            "initial certificate poll ignored finalize Retry-After: {value}"
        );
    }
}
#[tokio::test]
async fn finalize_processing_honors_initial_retry_after_120() {
    retry_case("120", Some(Duration::from_secs(119))).await;
}
#[tokio::test]
async fn retry_after_maximum_does_not_panic() {
    retry_case("18446744073709551615", None).await;
}
#[tokio::test]
async fn retry_after_past_date_is_bounded() {
    retry_case("Wed, 01 Jan 2020 00:00:00 GMT", None).await;
}
#[tokio::test]
async fn retry_after_invalid_value_is_bounded() {
    retry_case("not-a-date", None).await;
}

async fn certificate_case(size: usize, pem: bool) {
    let env = Environment::start(
        &format!("certificate-{size}-{pem}"),
        if pem {
            Mode::CertificatePem(size)
        } else {
            Mode::Certificate(size)
        },
    )
    .await;
    let _capture = env.capture();
    let config = env.config();
    env.install_old(&config);
    let provider = env.provider("none");
    env.seed(&config, &*provider);
    let mut manager = Manager::open(&config, provider, env.http()).unwrap();
    let old = manager.current(crate::acme::now()).unwrap().clone();
    let result = manager.tick().await;
    let journal = env.case.journal(&config.state_dir, "after");
    assert!(
        env.state
            .lock()
            .unwrap()
            .requests
            .iter()
            .any(|r| r == "POST /certificate/1"),
        "fixture must reach the certificate endpoint"
    );
    let rss = fs::read_to_string("/proc/self/status").unwrap();
    env.case.event("diagnostic",json!({"response_bytes":size,"pem":pem,"result":format!("{result:?}"),"old_certificate_valid":old.lifetime().valid_at(super::now()),"controller_ready":manager.ready(),"process_memory":rss.lines().filter(|s|s.starts_with("VmRSS:")||s.starts_with("VmHWM:")).collect::<Vec<_>>()}));
    let expected = if pem && size == 1024 * 1024 {
        super::manager::Tick::Installed
    } else {
        super::manager::Tick::RetryScheduled
    };
    assert_eq!(result.unwrap(), expected);
    assert!(manager.ready(), "prior valid service must remain available");
    assert!(serde_json::to_vec(&journal).unwrap().len() < 128 * 1024);
    if size <= 4 * 1024 * 1024 && !(pem && size == 1024 * 1024) {
        let blocked = &journal["blocked_certificate"];
        assert_eq!(blocked["original_bytes"], size);
        assert_eq!(
            blocked["chain_pem"].as_array().unwrap().len(),
            size.min(16384)
        );
        assert_eq!(blocked["sha256"].as_str().unwrap().len(), 64);
        if !pem {
            let digest: String = boring::sha::sha256(&vec![b'X'; size])
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect();
            assert_eq!(
                blocked["sha256"], digest,
                "digest covers the whole response"
            );
        }
        assert!(journal["order"].is_object());
    } else {
        assert!(journal["blocked_certificate"].is_null());
    }
}
macro_rules! cert_tests {($($name:ident,$size:expr,$pem:literal;)*)=>{$(#[tokio::test]async fn $name(){certificate_case($size,$pem).await;})*};}
cert_tests! {
 certificate_invalid_1m,1024*1024,false;
 certificate_invalid_1m_plus_one,1024*1024+1,false;
 certificate_invalid_2m,2*1024*1024,false;
 certificate_invalid_3m,3*1024*1024,false;
 certificate_invalid_4m,4*1024*1024,false;
 certificate_invalid_4m_plus_one,4*1024*1024+1,false;
 certificate_pem_1m,1024*1024,true;
 certificate_pem_1m_plus_one,1024*1024+1,true;
 certificate_pem_2m,2*1024*1024,true;
 certificate_pem_3m,3*1024*1024,true;
 certificate_pem_4m,4*1024*1024,true;
 certificate_pem_4m_plus_one,4*1024*1024+1,true;
}
#[tokio::test]
async fn control_http_header_stall_releases_connection() {
    let env = Environment::start("http-header-stall", Mode::Stall("headers")).await;
    let _capture = env.capture();
    let started = Instant::now();
    let request = hyper::Request::builder()
        .uri(format!("{}/dir", env.base))
        .body(Full::new(Bytes::new()))
        .unwrap();
    let http = Http::new(Some(&env.ca_file), Duration::from_millis(800)).unwrap();
    let result = http.request(request).await;
    env.case.event("timeout",json!({"elapsed_ms":started.elapsed().as_millis(),"error":result.as_ref().err().map(ToString::to_string)}));
    assert!(result.is_err());
    assert_eq!(env.state.lock().unwrap().requests, ["GET /dir"]);
    assert!(started.elapsed() < Duration::from_secs(3));
}

async fn nonce_case(rejects: usize, with_nonce: bool, success: bool) {
    let env = Environment::start(
        &format!("nonce-{rejects}-{with_nonce}"),
        Mode::NonceReject(rejects, with_nonce),
    )
    .await;
    let _capture = env.capture();
    let config = env.config();
    let provider = env.provider("none");
    env.seed(&config, &*provider);
    let mut manager = Manager::open(&config, provider, env.http()).unwrap();
    let result = manager.tick().await;
    let requests = env.state.lock().unwrap().requests.clone();
    env.case.event("nonce_result",json!({"rejects":rejects,"with_new_nonce":with_nonce,"result":format!("{result:?}"),"requests":requests}));
    env.case.journal(&config.state_dir, "after");
    assert_eq!(
        env.state.lock().unwrap().nonce_rejected,
        rejects.min(5),
        "badNonce injection must be exercised"
    );
    if success {
        assert!(matches!(result, Ok(super::manager::Tick::Installed)));
    } else {
        assert!(!matches!(result, Ok(super::manager::Tick::Installed)));
        assert!(requests.len() < 20, "badNonce must be bounded");
    }
}
#[tokio::test]
async fn bad_nonce_one_with_replacement() {
    nonce_case(1, true, true).await;
}
#[tokio::test]
async fn bad_nonce_three_with_replacement() {
    nonce_case(3, true, true).await;
}
#[tokio::test]
async fn bad_nonce_three_without_replacement() {
    nonce_case(3, false, true).await;
}
#[tokio::test]
async fn bad_nonce_continuous_is_bounded() {
    nonce_case(1000, true, false).await;
}

#[tokio::test]
async fn ari_maximum_retry_after_does_not_panic() {
    use rustls_pki_types::{CertificateDer, PrivatePkcs8KeyDer};
    let env = Environment::start("ari-overflow", Mode::Retry("18446744073709551615")).await;
    let _capture = env.capture();
    let config = env.config();
    env.install_old(&config);
    let (signer, key) = CRYPTO.key_provider.generate_key().unwrap();
    env.state.lock().unwrap().jwk = Some(serde_json::to_value(signer.as_jwk()).unwrap());
    let account = instant_acme::Account::builder(Box::new(env.http()), &CRYPTO)
        .unwrap()
        .from_parts(
            format!("{}/acct/1", env.base),
            PrivatePkcs8KeyDer::from(key.secret_pkcs8_der().to_vec()),
            format!("{}/dir", env.base),
        )
        .await
        .unwrap();
    let stored = super::persist::DiskStore::open(&config.state_dir.join("certificates"))
        .unwrap()
        .read_current()
        .unwrap()
        .unwrap();
    let cert = X509::stack_from_pem(&stored.candidate.chain_pem).unwrap();
    let der = CertificateDer::from(cert[0].to_der().unwrap());
    let id = instant_acme::CertificateIdentifier::try_from(&der).unwrap();
    let result = account.renewal_info(&id).await;
    env.case
        .event("ari", json!({"result":format!("{result:?}")}));
    assert!(
        result.is_err(),
        "unrepresentable remote interval should return a structured error, not panic"
    );
}

async fn transport_stall(kind: &str) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let env = Environment::start(&format!("transport-{kind}"), Mode::Normal).await;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    env.case
        .event("server", json!({"port":port,"kind":"stalled-transport"}));
    let _capture = env.case.capture(&[env.port, port]);
    let kind = kind.to_owned();
    let tls = env.tls.clone();
    let (closed, observed) = tokio::sync::oneshot::channel();
    let task = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut buffer = [0; 8192];
        if kind == "tls" {
            while socket.read(&mut buffer).await.unwrap_or(0) > 0 {}
            let _ = closed.send(());
            return;
        }
        let mut socket = tokio_boring::accept(&tls, socket).await.unwrap();
        let mut head = Vec::new();
        while !head.ends_with(b"\r\n\r\n") {
            let n = socket.read(&mut buffer).await.unwrap();
            head.extend_from_slice(&buffer[..n]);
        }
        match kind.as_str() {
            "body" => socket
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\nx")
                .await
                .unwrap(),
            "chunked" => socket
                .write_all(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n1\r\nx\r\n")
                .await
                .unwrap(),
            _ => {}
        }
        while socket.read(&mut buffer).await.unwrap_or(0) > 0 {}
        let _ = closed.send(());
    });
    let http = Http::new(Some(&env.ca_file), Duration::from_millis(800)).unwrap();
    let before = fs::read_dir("/proc/self/fd").unwrap().count();
    let start = Instant::now();
    let result = http
        .request(
            hyper::Request::builder()
                .uri(format!("https://localhost:{port}/stalled"))
                .body(Full::new(Bytes::new()))
                .unwrap(),
        )
        .await;
    assert!(result.is_err());
    assert!(start.elapsed() < Duration::from_secs(3));
    tokio::time::timeout(Duration::from_secs(2), observed)
        .await
        .unwrap()
        .unwrap();
    task.await.unwrap();
    tokio::task::yield_now().await;
    let after = fs::read_dir("/proc/self/fd").unwrap().count();
    env.case.event("resources",json!({"elapsed_ms":start.elapsed().as_millis(),"fd_before":before,"fd_after":after,"active_hyper_drivers":http.laboratory_active_drivers()}));
    assert_eq!(http.laboratory_active_drivers(), 0);
    // Process-wide FD counts are observations; concurrent default tests can
    // legitimately open unrelated descriptors. Peer EOF and owned-driver zero
    // are the per-request reclamation assertions above.
}
#[tokio::test]
async fn tls_handshake_stall_reclaims_driver_and_fd() {
    transport_stall("tls").await;
}
#[tokio::test]
async fn response_header_stall_reclaims_driver_and_fd() {
    transport_stall("headers").await;
}
#[tokio::test]
async fn response_body_stall_reclaims_driver_and_fd() {
    transport_stall("body").await;
}
#[tokio::test]
async fn unterminated_chunked_body_reclaims_driver_and_fd() {
    transport_stall("chunked").await;
}

fn verify_envelope(envelope: &Value, protected: &Value, stored: Option<&Value>) -> bool {
    use boring::{
        ec::{EcGroup, EcKey},
        ecdsa::EcdsaSig,
        nid::Nid,
    };
    let check = || -> Option<bool> {
        let jwk = if protected["jwk"].is_object() {
            &protected["jwk"]
        } else {
            stored?
        };
        let x = BigNum::from_slice(&B64.decode(jwk["x"].as_str()?).ok()?).ok()?;
        let y = BigNum::from_slice(&B64.decode(jwk["y"].as_str()?).ok()?).ok()?;
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).ok()?;
        let key = EcKey::from_public_key_affine_coordinates(&group, &x, &y).ok()?;
        let signature = B64.decode(envelope["signature"].as_str()?).ok()?;
        if signature.len() != 64 {
            return Some(false);
        }
        let sig = EcdsaSig::from_private_components(
            BigNum::from_slice(&signature[..32]).ok()?,
            BigNum::from_slice(&signature[32..]).ok()?,
        )
        .ok()?;
        let input = format!(
            "{}.{}",
            envelope["protected"].as_str()?,
            envelope["payload"].as_str()?
        );
        sig.verify(&boring::sha::sha256(input.as_bytes()), &key)
            .ok()
    };
    check().unwrap_or(false)
}

async fn late_provider(kind: &str) {
    let env = Environment::start(&format!("dns-{kind}-late"), Mode::Dns("late")).await;
    let _capture = env.capture();
    let config = env.config();
    let provider = env.provider(kind);
    env.seed(&config, &*provider);
    let http = Http::new(Some(&env.ca_file), Duration::from_millis(800)).unwrap();
    let provider: Box<dyn DnsProvider> = match kind {
        "cloudflare" => Box::new(super::dns::Cloudflare::laboratory(
            http.clone(),
            env.base.clone(),
        )),
        _ => Box::new(super::porkbun::Porkbun::laboratory(
            http.clone(),
            env.base.clone(),
        )),
    };
    let mut manager = Manager::open(&config, provider, http).unwrap();
    assert_eq!(
        manager.tick().await.unwrap(),
        super::manager::Tick::RetryScheduled
    );
    let before = env
        .case
        .journal(&config.state_dir, "empty-before-late-commit");
    assert_eq!(env.state.lock().unwrap().creates, 1);
    assert_eq!(
        before["leases"].as_array().unwrap().len(),
        1,
        "empty cleanup must retain uncertain POST intent"
    );
    assert!(manager.cleanup().await.is_err());
    drop(manager);
    tokio::time::sleep(Duration::from_millis(600)).await;
    assert_eq!(
        env.state.lock().unwrap().records.len(),
        1,
        "late remote commit actually occurred"
    );
    // A foreign value sharing the DNS name must survive ownership cleanup.
    env.state.lock().unwrap().records.push(json!({"id":"99","type":"TXT","name":"_acme-challenge.acme.example.test","content":"foreign","comment":"foreign","notes":"foreign"}));
    let mut manager = Manager::open(&config, env.provider(kind), env.http()).unwrap();
    manager.cleanup().await.unwrap();
    let after = env
        .case
        .journal(&config.state_dir, "after-restart-reconcile");
    assert!(after["leases"].as_array().unwrap().is_empty());
    let shared = env.state.lock().unwrap();
    assert_eq!(shared.creates, 1);
    assert_eq!(shared.records.len(), 1);
    assert_eq!(shared.records[0]["content"], "foreign");
}
#[tokio::test]
async fn cloudflare_late_create_empty_cleanup_and_restart() {
    late_provider("cloudflare").await;
}
#[tokio::test]
async fn porkbun_late_create_empty_cleanup_and_restart() {
    late_provider("porkbun").await;
}

#[tokio::test]
async fn retry_after_seconds_delays_initial_poll() {
    retry_case("2", Some(Duration::from_millis(1900))).await;
}
#[tokio::test]
async fn retry_after_missing_uses_bounded_fallback() {
    retry_case("", None).await;
}
#[tokio::test]
async fn retry_after_future_http_date_delays_initial_poll() {
    let value = Box::leak(
        httpdate::fmt_http_date(std::time::SystemTime::now() + Duration::from_secs(4))
            .into_boxed_str(),
    );
    retry_case(value, Some(Duration::from_secs(2))).await;
}
async fn material(kind: &'static str) {
    let env = Environment::start(&format!("completed-{kind}"), Mode::CertificateKind(kind)).await;
    let _capture = env.capture();
    let config = env.config();
    let provider = env.provider("none");
    env.install_old(&config);
    env.seed(&config, &*provider);
    let before = env.case.journal(&config.state_dir, "before");
    let mut manager = Manager::open(&config, provider, env.http()).unwrap();
    assert_eq!(
        manager.tick().await.unwrap(),
        super::manager::Tick::RetryScheduled
    );
    let blocked = env.case.journal(&config.state_dir, "blocked");
    let requested = env.state.lock().unwrap().requests.len();
    assert_eq!(manager.tick().await.unwrap(), super::manager::Tick::Idle);
    assert_eq!(
        env.state.lock().unwrap().requests.len(),
        requested,
        "blocked material should not be redownloaded on every tick"
    );
    assert!(manager.ready(), "valid prior certificate remains in use");
    assert_eq!(blocked["order"], before["order"]);
    assert_eq!(blocked["account_key"], before["account_key"]);
    assert!(blocked["blocked_certificate"].is_object());
    env.case.event("blocked_material",json!({"kind":kind,"category":blocked["blocked_certificate"]["category"],"retry_at":blocked["blocked_certificate"]["retry_at"]}));
    if kind == "future" {
        assert_eq!(
            blocked["blocked_certificate"]["category"],
            "future-not-before"
        );
        let wait = blocked["blocked_certificate"]["retry_at"]
            .as_u64()
            .unwrap()
            .saturating_sub(super::now())
            + 1;
        tokio::time::sleep(Duration::from_secs(wait)).await;
        assert_eq!(
            manager.tick().await.unwrap(),
            super::manager::Tick::Installed
        );
        let after = env.case.journal(&config.state_dir, "after-not-before");
        assert!(after["order"].is_null());
        assert_eq!(
            env.state
                .lock()
                .unwrap()
                .requests
                .iter()
                .filter(|r| r.as_str() == "POST /finalize/1")
                .count(),
            1,
            "completed order recovery must not finalize twice"
        );
    } else {
        assert!(blocked["blocked_certificate"]["retry_at"].is_null());
    }
}
#[tokio::test]
async fn completed_wrong_san_is_blocked_without_new_order() {
    material("san").await;
}
#[tokio::test]
async fn completed_wrong_key_is_blocked_without_new_order() {
    material("key").await;
}
#[tokio::test]
async fn completed_wrong_eku_is_blocked_without_new_order() {
    material("eku").await;
}
#[tokio::test]
async fn completed_untrusted_chain_is_blocked_without_new_order() {
    material("chain").await;
}
#[tokio::test]
async fn completed_future_not_before_recovers_same_order() {
    material("future").await;
}
#[tokio::test]
async fn two_managers_contend_for_same_directory_without_corrupting_key() {
    let env = Environment::start("manager-lock", Mode::Normal).await;
    let config = env.config();
    let provider = env.provider("none");
    env.seed(&config, &*provider);
    let manager = Manager::open(&config, provider, env.http()).unwrap();
    let before = env.case.journal(&config.state_dir, "before");
    let second = Manager::open(&config, env.provider("none"), env.http());
    assert!(
        second.is_err(),
        "second Manager must fail to acquire the live state lock"
    );
    env.case.event(
        "second_manager",
        json!({"error":second.err().map(|e|e.to_string())}),
    );
    let after = env.case.journal(&config.state_dir, "while-locked");
    assert_eq!(before, after);
    drop(manager);
    assert!(Manager::open(&config, env.provider("none"), env.http()).is_ok());
}
#[tokio::test]
async fn ari_remote_retry_after_is_not_clipped_by_local_recheck_policy() {
    let env = Environment::start("ari-long", Mode::Normal).await;
    let _capture = env.capture();
    let config = env.config();
    let provider = env.provider("none");
    env.seed(&config, &*provider);
    let mut manager = Manager::open(&config, provider, env.http()).unwrap();
    assert_eq!(
        manager.tick().await.unwrap(),
        super::manager::Tick::Installed
    );
    drop(manager);
    env.state.lock().unwrap().mode = Mode::Retry("3153600000");
    let path = fs::read_dir(config.state_dir.join("acme"))
        .unwrap()
        .filter_map(|e| e.ok().map(|e| e.path()))
        .find(|p| p.extension().is_some_and(|e| e == "json"))
        .unwrap();
    let mut j: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    j["ari_check_at"] = json!(0);
    fs::write(&path, serde_json::to_vec(&j).unwrap()).unwrap();
    let mut manager = Manager::open(&config, env.provider("none"), env.http()).unwrap();
    assert_eq!(manager.tick().await.unwrap(), super::manager::Tick::Idle);
    let after = env.case.journal(&config.state_dir, "long-interval");
    assert!(
        after["ari_check_at"].as_u64().unwrap() >= super::now() + 3153599999,
        "remote ARI Retry-After must not be clipped by the local recheck cadence"
    );
    // Restoring the account sets its short local cooldown; ARI must not turn
    // that into the remote century-long not-before date.
    assert!(after["next_attempt"].as_u64().unwrap() <= super::now() + 3);
    assert!(after["renew_at"].as_u64().unwrap() < after["ari_check_at"].as_u64().unwrap());
    let requests = &env.state.lock().unwrap().requests;
    assert_eq!(
        requests
            .iter()
            .filter(|r| r.starts_with("GET /renewal-info/"))
            .count(),
        2,
        "both initial scheduling and the long Retry-After response must be exercised"
    );
}

struct BeforeCreate {
    provider: Box<dyn DnsProvider>,
    entered: Arc<tokio::sync::Notify>,
}
#[async_trait::async_trait]
impl DnsProvider for BeforeCreate {
    fn identity(&self) -> String {
        self.provider.identity()
    }
    async fn prepare(&mut self, _: &mut super::persist::Lease) -> Result<()> {
        self.entered.notify_one();
        std::future::pending().await
    }
    async fn present(&mut self, lease: &mut super::persist::Lease) -> Result<()> {
        self.provider.present(lease).await
    }
    async fn recover(&mut self, lease: &mut super::persist::Lease) -> Result<()> {
        self.provider.recover(lease).await
    }
    async fn propagated(&mut self, lease: &super::persist::Lease) -> Result<bool> {
        self.provider.propagated(lease).await
    }
    async fn cleanup(&mut self, lease: &super::persist::Lease) -> Result<()> {
        self.provider.cleanup(lease).await
    }
}
async fn intent_cancel(kind: &str) {
    let env = Environment::start(&format!("intent-before-post-{kind}"), Mode::Dns("normal")).await;
    let _capture = env.capture();
    let config = env.config();
    let provider = env.provider(kind);
    env.seed(&config, &*provider);
    let entered = Arc::new(tokio::sync::Notify::new());
    let mut manager = Manager::open(
        &config,
        BeforeCreate {
            provider,
            entered: entered.clone(),
        },
        env.http(),
    )
    .unwrap();
    let task = tokio::spawn(async move { manager.tick().await });
    tokio::time::timeout(Duration::from_secs(3), entered.notified())
        .await
        .unwrap();
    env.case
        .journal(&config.state_dir, "preparation-before-mutation-intent");
    task.abort();
    let _ = task.await;
    assert_eq!(env.state.lock().unwrap().creates, 0);
    let mut manager = Manager::open(&config, env.provider(kind), env.http()).unwrap();
    let result = manager.cleanup().await;
    let after = env.case.journal(&config.state_dir, "after-cancel-restart");
    env.case.event("intent_cancel",json!({"creates":0,"cleanup":format!("{result:?}"),"evidence":"read-only preparation canceled; Manager dropped and reopened"}));
    assert!(
        result.is_ok() && after["leases"].as_array().unwrap().is_empty(),
        "known pre-POST cancellation needs a recoverable preparation state"
    );
}
#[tokio::test]
async fn cloudflare_intent_cancel_before_post_recovers() {
    intent_cancel("cloudflare").await;
}
#[tokio::test]
async fn porkbun_intent_cancel_before_post_recovers() {
    intent_cancel("porkbun").await;
}

#[tokio::test]
async fn external_cancellation_closes_socket_and_owned_driver() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let env = Environment::start("http-external-cancel", Mode::Normal).await;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    env.case
        .event("server", json!({"port":port,"kind":"cancelled-transport"}));
    let _capture = env.case.capture(&[port]);
    let tls = env.tls.clone();
    let (started, waiting) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(async move {
        let (socket, _) = listener.accept().await.unwrap();
        let mut socket = tokio_boring::accept(&tls, socket).await.unwrap();
        let mut input = [0; 4096];
        assert!(socket.read(&mut input).await.unwrap() > 0);
        socket
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\nx")
            .await
            .unwrap();
        started.send(()).unwrap();
        while socket.read(&mut input).await.unwrap_or(0) > 0 {}
    });
    let http = env.http();
    let request = http.clone();
    let start = Instant::now();
    let task = tokio::spawn(async move {
        request
            .request(
                hyper::Request::builder()
                    .uri(format!("https://localhost:{port}/cancel"))
                    .body(Full::new(Bytes::new()))
                    .unwrap(),
            )
            .await
    });
    waiting.await.unwrap();
    task.abort();
    let _ = task.await;
    tokio::time::timeout(Duration::from_secs(1), server)
        .await
        .unwrap()
        .unwrap();
    tokio::task::yield_now().await;
    env.case.event("external_cancel",json!({"elapsed_ms":start.elapsed().as_millis(),"active_hyper_drivers":http.laboratory_active_drivers(),"peer_eof":true}));
    assert_eq!(http.laboratory_active_drivers(), 0);
}

async fn completed_recovery(processing: bool) {
    let env = Environment::start(
        if processing {
            "recover-processing"
        } else {
            "recover-valid"
        },
        if processing {
            Mode::RecoverProcessing
        } else {
            Mode::Normal
        },
    )
    .await;
    let _capture = env.capture();
    let config = env.config();
    let provider = env.provider("none");
    env.seed(&config, &*provider);
    let before = env.case.journal(&config.state_dir, "before");
    {
        let mut shared = env.state.lock().unwrap();
        shared.csr = serde_json::from_value(before["order"]["csr"].clone()).unwrap();
        shared.finalized = true;
    }
    let mut manager = Manager::open(&config, provider, env.http()).unwrap();
    assert_eq!(
        manager.tick().await.unwrap(),
        super::manager::Tick::Installed
    );
    let after = env.case.journal(&config.state_dir, "installed");
    assert!(after["order"].is_null());
    let shared = env.state.lock().unwrap();
    assert!(
        !shared
            .requests
            .iter()
            .any(|r| r.as_str() == "POST /finalize/1" || r.as_str() == "POST /new-order")
    );
    assert_eq!(after["account_key"], before["account_key"]);
}
#[tokio::test]
async fn restored_processing_order_downloads_without_refinalize() {
    completed_recovery(true).await;
}
#[tokio::test]
async fn restored_valid_order_downloads_without_refinalize() {
    completed_recovery(false).await;
}

#[tokio::test]
async fn retry_after_beyond_operation_deadline_defers_without_early_poll() {
    let env = Environment::start("retry-after-beyond-deadline", Mode::Retry("120")).await;
    let _capture = env.capture();
    let config = env.config();
    let provider = env.provider("none");
    env.seed(&config, &*provider);
    let before = env.case.journal(&config.state_dir, "before");
    let start = super::now();
    let mut manager = Manager::open(&config, provider, env.http()).unwrap();
    let result = manager.tick().await;
    let after = env.case.journal(&config.state_dir, "after");
    env.case.event("operation_deadline",json!({"operation_timeout_secs":30,"retry_after_secs":120,"result":format!("{result:?}"),"first_poll_ms":env.state.lock().unwrap().poll_delay.map(|d|d.as_millis()),"next_attempt":after["next_attempt"]}));
    assert_eq!(
        result.unwrap(),
        super::manager::Tick::RetryScheduled,
        "server wait exceeds this operation budget; defer instead of polling early"
    );
    assert_eq!(before["order"], after["order"]);
    assert!(after["next_attempt"].as_u64().unwrap() >= start + 119);
    assert!(env.state.lock().unwrap().poll_delay.is_none());
}

async fn uncertain_send_gap(kind: &str) {
    let env = Environment::start(&format!("durable-send-gap-{kind}"), Mode::Dns("normal")).await;
    let _capture = env.capture();
    let config = env.config();
    let provider = env.provider(kind);
    env.seed(&config, &*provider);
    let mut journal = env.case.journal(&config.state_dir, "before-gap");
    journal["leases"] = json!([{"phase":"CreateUncertain","name":"_acme-challenge.acme.example.test","value":"pending-value","marker":"retained-gap-marker","record_id":null,"borrowed":false}]);
    let path = fs::read_dir(config.state_dir.join("acme"))
        .unwrap()
        .filter_map(|e| e.ok().map(|e| e.path()))
        .find(|p| p.extension().is_some_and(|s| s == "json"))
        .unwrap();
    fs::write(path, serde_json::to_vec(&journal).unwrap()).unwrap();
    let mut manager = Manager::open(&config, provider, env.http()).unwrap();
    assert!(manager.cleanup().await.is_err());
    let after = env.case.journal(&config.state_dir, "retained-gap");
    assert_eq!(after["leases"], journal["leases"]);
    assert_eq!(env.state.lock().unwrap().creates, 0);
    env.case
        .event("send_gap", json!({"empty_list_does_not_prove_unsent":true}));
}
#[tokio::test]
async fn cloudflare_durable_send_gap_retains_uncertainty() {
    uncertain_send_gap("cloudflare").await;
}
#[tokio::test]
async fn porkbun_durable_send_gap_retains_uncertainty() {
    uncertain_send_gap("porkbun").await;
}

async fn recovered_wait(header: &'static str, defer: bool) {
    let env = Environment::start(
        if defer {
            "recovery-deferred"
        } else {
            "recovery-first-wait"
        },
        Mode::RecoveryRetry(header),
    )
    .await;
    let _capture = env.capture();
    let config = env.config();
    let provider = env.provider("none");
    env.seed(&config, &*provider);
    let before = env.case.journal(&config.state_dir, "before");
    {
        let mut shared = env.state.lock().unwrap();
        shared.finalized = true;
        shared.csr = serde_json::from_value(before["order"]["csr"].clone()).unwrap();
    }
    let mut manager = Manager::open(&config, provider, env.http()).unwrap();
    let result = manager.tick().await.unwrap();
    let after = env.case.journal(&config.state_dir, "after");
    let calls = env.state.lock().unwrap().requests.clone();
    assert!(
        !calls
            .iter()
            .any(|r| r == "POST /finalize/1" || r == "POST /new-order")
    );
    if defer {
        assert_eq!(result, super::manager::Tick::RetryScheduled);
        assert_eq!(before["order"], after["order"]);
        assert_eq!(after["last_failure_phase"], "order-deferred");
        assert!(after["next_attempt"].as_u64().unwrap() > super::now() + 100);
        let n = calls.len();
        drop(manager);
        let mut reopened = Manager::open(&config, env.provider("none"), env.http()).unwrap();
        assert_eq!(reopened.tick().await.unwrap(), super::manager::Tick::Idle);
        assert_eq!(env.state.lock().unwrap().requests.len(), n);
    } else {
        assert_eq!(result, super::manager::Tick::Installed);
        let events = fs::read_to_string(env.case.path().join("events.jsonl")).unwrap();
        let times: Vec<_> = events
            .lines()
            .map(|l| serde_json::from_str::<Value>(l).unwrap())
            .filter(|v| v["kind"] == "request" && v["data"]["path"] == "/order/1")
            .map(|v| v["elapsed_us"].as_u64().unwrap())
            .collect();
        assert_eq!(times.len(), 2);
        assert!(
            times[1] - times[0] >= 1_900_000,
            "recovered Processing order must inherit its first Retry-After"
        );
    }
}
#[tokio::test]
async fn recovered_processing_preserves_first_retry_after() {
    recovered_wait("2", false).await;
}
#[tokio::test]
async fn deferred_order_wait_survives_restart() {
    recovered_wait("120", true).await;
}

#[tokio::test]
async fn cancellation_during_order_wait_preserves_restart_deadline() {
    let env = Environment::start("cancel-poll-wait", Mode::RecoveryRetry("120")).await;
    let _capture = env.capture();
    let mut config = env.config();
    config.acme.operation_timeout_secs = 300;
    let provider = env.provider("none");
    env.seed(&config, &*provider);
    let before = env.case.journal(&config.state_dir, "before");
    {
        let mut shared = env.state.lock().unwrap();
        shared.finalized = true;
        shared.csr = serde_json::from_value(before["order"]["csr"].clone()).unwrap();
    }
    let mut manager = Manager::open(&config, provider, env.http()).unwrap();
    let mut tick = Box::pin(manager.tick());
    tokio::select! {
        result = &mut tick => panic!("operation must still be waiting: {result:?}"),
        _ = async {
            tokio::time::timeout(Duration::from_secs(5), async {
                loop {
                    let journal = env.case.journal(&config.state_dir, "waiting");
                    if journal["next_attempt"].as_u64().unwrap() > super::now() + 100 { break; }
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            }).await.unwrap();
        } => {}
    }
    drop(tick);
    drop(manager);
    let after = env.case.journal(&config.state_dir, "cancelled");
    assert_eq!(before["order"], after["order"]);
    let requests = env.state.lock().unwrap().requests.len();
    let mut reopened = Manager::open(&config, env.provider("none"), env.http()).unwrap();
    assert_eq!(reopened.tick().await.unwrap(), super::manager::Tick::Idle);
    assert_eq!(env.state.lock().unwrap().requests.len(), requests);
    env.case.event(
        "cancelled_wait",
        json!({"persisted_until":after["next_attempt"],"operation_budget":300}),
    );
}

#[tokio::test]
async fn outer_retry_after_overflow_does_not_persist_saturated_date() {
    let env = Environment::start("outer-retry-overflow", Mode::Retry("18446744073709551615")).await;
    let _capture = env.capture();
    let config = env.config();
    let provider = env.provider("none");
    env.seed(&config, &*provider);
    let mut manager = Manager::open(&config, provider, env.http()).unwrap();
    assert_eq!(
        manager.tick().await.unwrap(),
        super::manager::Tick::RetryScheduled
    );
    let after = env.case.journal(&config.state_dir, "after");
    assert!(after["next_attempt"].as_u64().unwrap() <= super::now() + 3);
    assert!(
        env.state
            .lock()
            .unwrap()
            .requests
            .iter()
            .any(|r| r == "POST /finalize/1")
    );
}

#[tokio::test]
async fn ari_rate_limit_wait_is_not_capped_by_local_recheck_policy() {
    let env = Environment::start("ari-rate-limit", Mode::Normal).await;
    let _capture = env.capture();
    let config = env.config();
    let provider = env.provider("none");
    env.seed(&config, &*provider);
    let mut manager = Manager::open(&config, provider, env.http()).unwrap();
    assert_eq!(
        manager.tick().await.unwrap(),
        super::manager::Tick::Installed
    );
    drop(manager);
    env.state.lock().unwrap().mode = Mode::AriRate("100000");
    let path = fs::read_dir(config.state_dir.join("acme"))
        .unwrap()
        .filter_map(|e| e.ok().map(|e| e.path()))
        .find(|p| p.extension().is_some_and(|s| s == "json"))
        .unwrap();
    let mut journal: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    journal["ari_check_at"] = json!(0);
    fs::write(path, serde_json::to_vec(&journal).unwrap()).unwrap();
    let mut manager = Manager::open(&config, env.provider("none"), env.http()).unwrap();
    assert_eq!(manager.tick().await.unwrap(), super::manager::Tick::Idle);
    let after = env.case.journal(&config.state_dir, "rate-limited");
    assert!(after["ari_check_at"].as_u64().unwrap() >= super::now() + 99999);
}

#[test]
fn retry_after_parser_distinguishes_missing_malformed_and_unrepresentable() {
    use instant_acme::{RetryAfter, parse_retry_after};
    let now = std::time::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
    assert_eq!(parse_retry_after(None, now), RetryAfter::Absent);
    assert_eq!(
        parse_retry_after(Some("invalid"), now),
        RetryAfter::Malformed
    );
    assert_eq!(
        parse_retry_after(Some("2"), now),
        RetryAfter::At(now + Duration::from_secs(2))
    );
    for header in ["18446744073709551615", "18446744073709551616"] {
        assert_eq!(
            parse_retry_after(Some(header), now),
            RetryAfter::Unrepresentable
        );
    }
}
