use super::{
    Error, Result,
    certificate::{self, Validator},
    dns::DnsProvider,
    http::Http,
    now, random_below,
    state::{Journal, Lease, Order as SavedOrder, State},
};
use super::{
    certificate::{Candidate, CertificateSlot},
    store::{DiskStore, StoreFailure},
};
use instant_acme::{
    Account, AuthorizationStatus, CertificateIdentifier, ChallengeType, Identifier, NewOrder,
    OrderStatus, RetryPolicy,
};
use moon_naive_core::config::Config;
use rustls_pki_types::CertificateDer;
use std::{sync::atomic::Ordering, time::Duration};

#[derive(Debug, PartialEq, Eq)]
pub enum Tick {
    Idle,
    Installed,
    RetryScheduled,
}
/// Run on a dedicated control runtime/process: journal fsync never runs on a
/// future data-plane worker. No listener is opened by this manager.
pub struct Manager<P> {
    pub slot: CertificateSlot,
    provider: P,
    http: Http,
    validator: Validator,
    store: DiskStore,
    state: State,
    journal: Journal,
    account: Option<Account>,
    accounts: super::account::AccountClient,
    window: u64,
    initial_retry: u64,
    max_retry: u64,
    operation_timeout: Duration,
    poll_interval: Duration,
    suspended: bool,
    phase: &'static str,
}
impl<P: DnsProvider> Manager<P> {
    pub fn open(config: &Config, provider: P, http: Http) -> Result<Self> {
        config.validate()?;
        if !config.acme.accept_terms {
            return Err("live ACME requires accept_terms = true (including staging)".into());
        }
        let domain = config.domain.to_ascii_lowercase();
        let directory = config.acme.directory().to_owned();
        let uri: ::http::Uri = directory.parse()?;
        if uri.scheme_str() != Some("https")
            || uri.host().is_none()
            || uri.authority().is_some_and(|a| a.as_str().contains('@'))
        {
            return Err("invalid ACME HTTPS directory".into());
        }
        let namespace: String = boring::sha::sha256(format!("{directory}\0{domain}").as_bytes())
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        let state = State::open(&config.state_dir.join("acme"), &namespace)?;
        state.check_other_journals()?;
        let journal = state.load()?.unwrap_or_else(|| Journal {
            version: 1,
            domain: domain.clone(),
            directory: directory.clone(),
            dns_identity: provider.identity(),
            ..Journal::default()
        });
        if journal.version != 1
            || journal.domain != domain
            || journal.directory != directory
            || journal.dns_identity != provider.identity()
            || journal.leases.len() > 1
        {
            return Err(
                "ACME journal identity/version mismatch; do not discard pending DNS cleanup".into(),
            );
        }
        if journal.account.is_none()
            && journal.account_id.is_none()
            && journal.account_key.is_empty()
            && let Some(path) = config.acme.eab_credentials_file.as_deref()
        {
            super::eab::load_credentials(path)?;
        }
        if journal.account.is_none()
            && journal.account_id.is_none()
            && journal.account_key.is_empty()
            && let Some(value) = &config.acme.eab
        {
            value.validate()?;
        }
        let validator = Validator::for_config(config)?;
        let store = DiskStore::open(&config.state_dir.join("certificates"))?;
        let slot = CertificateSlot::default();
        let mut manager = Self {
            slot,
            provider,
            http: http.clone(),
            validator,
            store,
            state,
            journal,
            account: None,
            accounts: super::account::AccountClient::new(config, http.clone()),
            window: config.acme.renew_before_secs,
            initial_retry: config.acme.retry_initial_secs,
            max_retry: config.acme.retry_max_secs,
            operation_timeout: Duration::from_secs(config.acme.operation_timeout_secs),
            poll_interval: Duration::from_secs(config.acme.poll_interval_secs),
            suspended: false,
            phase: "startup",
        };
        if let Some(stored) = manager.store.read_current()? {
            // Never trust the plaintext lifetime metadata for readiness.
            if let Ok(bundle) = manager.validator.verify(stored.candidate, now()) {
                if bundle.lifetime() != stored.lifetime {
                    return Err("stored certificate lifetime metadata mismatch".into());
                }
                if manager.journal.renew_at == 0 {
                    manager.journal.renew_at = bundle.lifetime().renew_at(manager.window);
                }
                if manager
                    .journal
                    .order
                    .as_ref()
                    .is_some_and(|order| order.key_pem.as_bytes() == bundle.material().key_pem)
                {
                    // Crash after CURRENT commit, before journal completion.
                    manager.journal.order = None;
                    manager.journal.next_attempt = 0;
                    manager.journal.failures = 0;
                    manager.journal.renew_at = bundle.lifetime().renew_at(manager.window);
                    manager.journal.ari_window = None;
                    manager.journal.ari_selected = None;
                    manager.journal.ari_check_at = 0;
                }
                manager.slot.restore(bundle);
            }
        }
        manager.persist()?;
        Ok(manager)
    }
    fn persist(&mut self) -> Result<()> {
        if let Err(error) = self.state.save(&self.journal) {
            self.suspended = true;
            return Err(error);
        }
        Ok(())
    }
    pub fn next_attempt(&self) -> u64 {
        self.journal.next_attempt
    }
    pub fn renew_at(&self) -> u64 {
        self.journal.renew_at
    }
    pub fn ready(&self) -> bool {
        self.slot.current(now()).is_some()
    }
    pub fn last_failure_phase(&self) -> &str {
        self.journal.last_failure_phase.as_deref().unwrap_or("none")
    }
    pub async fn cleanup(&mut self) -> Result<()> {
        while let Some(lease) = self.journal.leases.first().cloned() {
            self.provider.cleanup(&lease).await?;
            self.journal.leases.remove(0);
            self.persist()?;
        }
        Ok(())
    }
    pub async fn tick(&mut self) -> Result<Tick> {
        if self.suspended {
            return Err("ACME state durability uncertain; restart and reconcile CURRENT".into());
        }
        let time = now();
        if time < self.journal.next_attempt {
            return Ok(Tick::Idle);
        }
        self.http.retry_after.store(0, Ordering::Relaxed);
        let result = tokio::time::timeout(self.operation_timeout, self.reconcile())
            .await
            .map_err(|_| -> Error { "ACME operation deadline exceeded".into() })
            .and_then(|r| r);
        match result {
            Ok(tick) => Ok(tick),
            Err(_) if !self.suspended => {
                self.journal.last_failure_phase = Some(self.phase.into());
                // A dropped/failed DNS POST remains recoverable by its durable
                // marker. Clean up before another order is allowed.
                let _ = tokio::time::timeout(Duration::from_secs(30), self.cleanup()).await;
                if self.suspended {
                    return Err("ACME journal persistence failed during recovery".into());
                }
                let base = self
                    .initial_retry
                    .saturating_mul(
                        1_u64
                            .checked_shl(self.journal.failures.min(63))
                            .unwrap_or(u64::MAX),
                    )
                    .min(self.max_retry);
                self.journal.failures = self.journal.failures.saturating_add(1);
                let delay = base.saturating_add(random_below(base / 5 + 1)?);
                self.journal.next_attempt = now()
                    .saturating_add(delay)
                    .max(self.http.retry_after.load(Ordering::Relaxed));
                self.persist()?;
                Ok(Tick::RetryScheduled)
            }
            Err(error) => Err(error),
        }
    }
    async fn account(&mut self) -> Result<()> {
        if self.account.is_some() {
            return Ok(());
        }
        self.phase = "account";
        self.journal.next_attempt = now().saturating_add(self.initial_retry);
        self.persist()?;
        let state = &self.state;
        let suspended = &mut self.suspended;
        self.account = Some(
            self.accounts
                .restore_or_create(&mut self.journal, |journal| {
                    state.save(journal).inspect_err(|_| *suspended = true)
                })
                .await?,
        );
        Ok(())
    }
    async fn reconcile(&mut self) -> Result<Tick> {
        self.phase = "dns-cleanup";
        self.cleanup().await?;
        if self.ready() && self.journal.order.is_none() && now() < self.journal.renew_at {
            if now() >= self.journal.ari_check_at {
                self.account().await?;
                self.update_ari().await;
                self.persist()?;
            }
            return Ok(Tick::Idle);
        }
        self.account().await?;
        if self.journal.order.is_none() {
            let (key_pem, csr) = certificate::csr(&self.journal.domain)?;
            self.journal.order = Some(SavedOrder {
                url: String::new(),
                key_pem,
                csr,
            });
        }
        if self.journal.order.as_ref().unwrap().url.is_empty() {
            self.phase = "new-order";
            // newOrder has no protocol idempotency token. A crash in its response
            // gap is bounded by this persistent cooldown, not called exactly-once.
            self.journal.next_attempt = now().saturating_add(self.initial_retry);
            self.persist()?;
            let identifiers = [Identifier::Dns(self.journal.domain.clone())];
            let mut request = NewOrder::new(&identifiers);
            let old_id = self.certificate_id();
            if let Some(id) = old_id {
                request = request.replaces(id);
            }
            let account = self.account.as_ref().unwrap();
            let order = match account.new_order(&request).await {
                Err(instant_acme::Error::Unsupported(_)) => {
                    account.new_order(&NewOrder::new(&identifiers)).await?
                }
                result => result?,
            };
            self.journal.order.as_mut().unwrap().url = order.url().into();
            self.persist()?;
        }
        let saved = self.journal.order.as_ref().unwrap();
        self.phase = "recover-order";
        self.http.last_status.store(0, Ordering::Relaxed);
        let mut order = match self
            .account
            .as_ref()
            .unwrap()
            .order(saved.url.clone())
            .await
        {
            Ok(order) => order,
            Err(error) => {
                if self.http.last_status.load(Ordering::Relaxed) == 404 {
                    self.journal.order = None;
                    self.persist()?;
                }
                return Err(error.into());
            }
        };
        if order.state().status == OrderStatus::Invalid {
            self.journal.order = None;
            self.persist()?;
            return Err("ACME order invalid; retry will create a fresh order".into());
        }
        if order.state().status == OrderStatus::Pending {
            self.phase = "authorization";
            let mut authorizations = order.authorizations();
            while let Some(authorization) = authorizations.next().await {
                let mut authorization = authorization?;
                let domain = authorization.identifier().to_string();
                if domain != self.journal.domain {
                    return Err("ACME authorization returned unexpected identifier".into());
                }
                if authorization.status == AuthorizationStatus::Valid {
                    continue;
                }
                if authorization.status != AuthorizationStatus::Pending {
                    return Err("ACME authorization no longer pending".into());
                }
                let mut challenge = authorization
                    .challenge(ChallengeType::Dns01)
                    .ok_or("CA did not offer DNS-01")?;
                let name = format!("_acme-challenge.{domain}");
                let value = challenge.key_authorization()?.dns_value();
                let marker = format!("moon-naive-acme-{:016x}", random_below(u64::MAX)?);
                self.journal.leases.push(Lease {
                    name,
                    value,
                    marker,
                    record_id: None,
                    borrowed: false,
                });
                self.persist()?;
                let mut lease = self.journal.leases[0].clone();
                self.phase = "dns-present";
                self.provider.present(&mut lease).await?;
                self.journal.leases[0] = lease.clone();
                self.persist()?;
                self.phase = "dns-propagation";
                while !self.provider.propagated(&lease).await? {
                    tokio::time::sleep(self.poll_interval).await;
                }
                self.phase = "challenge-ready";
                challenge.set_ready().await?;
            }
            self.phase = "order-ready";
            let status = order
                .poll_ready(&RetryPolicy::new().timeout(self.operation_timeout))
                .await?;
            if status != OrderStatus::Ready {
                self.journal.order = None;
                self.persist()?;
                return Err("ACME order failed validation".into());
            }
        }
        self.phase = "dns-cleanup";
        self.cleanup().await?;
        if order.state().status == OrderStatus::Ready {
            self.phase = "finalize";
            order
                .finalize_csr(&self.journal.order.as_ref().unwrap().csr)
                .await?;
        }
        self.phase = "certificate-download";
        let chain = order
            .poll_certificate(&RetryPolicy::new().timeout(self.operation_timeout))
            .await?;
        let candidate = Candidate {
            chain_pem: chain.into_bytes(),
            key_pem: self
                .journal
                .order
                .as_ref()
                .unwrap()
                .key_pem
                .as_bytes()
                .to_vec(),
        };
        self.phase = "certificate-validation";
        let bundle = self.validator.verify(candidate, now())?;
        let lifetime = bundle.lifetime();
        if lifetime.renew_at(self.window) <= now() {
            return Err("CA issued certificate already due for renewal".into());
        }
        self.phase = "certificate-install";
        if let Err(failure) = self.store.install(&bundle) {
            if failure == StoreFailure::CommitUncertain {
                self.suspended = true;
            }
            return Err("certificate generation commit failed".into());
        }
        self.slot.restore(bundle);
        self.journal.order = None;
        self.journal.next_attempt = 0;
        self.journal.failures = 0;
        self.journal.last_failure_phase = None;
        let fallback = lifetime.renew_at(self.window);
        self.journal.renew_at =
            fallback.saturating_sub(random_below(((lifetime.not_after - fallback) / 10).max(1))?);
        self.journal.ari_window = None;
        self.journal.ari_selected = None;
        self.persist()?;
        self.update_ari().await;
        self.persist()?;
        Ok(Tick::Installed)
    }
    fn certificate_id(&self) -> Option<CertificateIdentifier<'static>> {
        let bundle = self.slot.current(now())?;
        let cert = boring::x509::X509::stack_from_pem(&bundle.material().chain_pem)
            .ok()?
            .into_iter()
            .next()?;
        let der = CertificateDer::from(cert.to_der().ok()?);
        CertificateIdentifier::try_from(&der)
            .ok()
            .map(|id| id.into_owned())
    }
    async fn update_ari(&mut self) {
        self.journal.ari_check_at = now().saturating_add(3600);
        let Some(id) = self.certificate_id() else {
            return;
        };
        let Some(account) = self.account.as_ref() else {
            return;
        };
        let (info, check_after) = match account.renewal_info(&id).await {
            Ok(info) => info,
            Err(_) => {
                self.journal.ari_check_at = self
                    .journal
                    .ari_check_at
                    .max(self.http.retry_after.load(Ordering::Relaxed));
                return;
            }
        };
        self.journal.ari_check_at = now().saturating_add(check_after.as_secs().max(60));
        let (Ok(start), Ok(end)) = (
            u64::try_from(info.suggested_window.start.unix_timestamp()),
            u64::try_from(info.suggested_window.end.unix_timestamp()),
        ) else {
            return;
        };
        let Some(bundle) = self.slot.current(now()) else {
            return;
        };
        let lifetime = bundle.lifetime();
        let safety = ((lifetime.not_after - lifetime.not_before) / 10).clamp(1, 86400);
        let end = end.min(lifetime.not_after.saturating_sub(safety));
        if end <= start {
            return;
        }
        let window = (start, end);
        if self.journal.ari_window != Some(window) {
            let Ok(offset) = random_below(end - start) else {
                return;
            };
            self.journal.ari_selected = Some(start + offset);
            self.journal.ari_window = Some(window);
        }
        if let Some(selected) = self.journal.ari_selected {
            self.journal.renew_at = selected;
        }
    }
}
