use super::{
    Error, Result,
    certificate::{self, Validator},
    dns::DnsProvider,
    http::Http,
    now,
    persist::{Journal, Lease, Order as SavedOrder, State},
    random_below,
};
use super::{
    certificate::{Candidate, VerifiedBundle},
    persist::{DiskStore, StoreFailure},
};
use instant_acme::{
    Account, AuthorizationStatus, CertificateIdentifier, ChallengeType, Identifier, NewOrder,
    OrderStatus,
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
    pub(crate) health_path: std::path::PathBuf,
    bundle: Option<VerifiedBundle>,
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
    deadline: tokio::time::Instant,
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
        let mut journal = state.load()?.unwrap_or_else(|| Journal {
            version: 1,
            domain: domain.clone(),
            directory: directory.clone(),
            dns_identity: provider.identity(),
            ..Journal::default()
        });
        if !matches!(journal.version, 1..=3)
            || journal.domain != domain
            || journal.directory != directory
            || journal.dns_identity != provider.identity()
            || journal.leases.len() > 1
        {
            return Err(
                "ACME journal identity/version mismatch; do not discard pending DNS cleanup".into(),
            );
        }
        journal.version = 3;
        if journal.account.is_none()
            && journal.account_id.is_none()
            && journal.account_key.is_empty()
            && let Some(path) = config.acme.eab_credentials_file.as_deref()
        {
            super::account::load_credentials(path)?;
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
        let mut manager = Self {
            health_path: config.state_dir.join("acme/WORKER"),
            bundle: None,
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
            deadline: tokio::time::Instant::now(),
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
                manager.bundle = Some(bundle);
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
    pub fn retry_certificate(&mut self) -> Result<()> {
        self.journal.blocked_certificate = None;
        self.journal.next_attempt = 0;
        self.persist()
    }
    pub fn next_attempt(&self) -> u64 {
        self.journal.next_attempt
    }
    pub fn renew_at(&self) -> u64 {
        self.journal.renew_at
    }
    pub fn current(&self, at: u64) -> Option<&VerifiedBundle> {
        self.bundle.as_ref().filter(|b| b.lifetime().valid_at(at))
    }
    pub fn ready(&self) -> bool {
        self.current(now()).is_some()
    }
    pub fn last_failure_phase(&self) -> &str {
        self.journal.last_failure_phase.as_deref().unwrap_or("none")
    }
    pub async fn cleanup(&mut self) -> Result<()> {
        if self.suspended {
            return Err("ACME state durability uncertain; cleanup suspended".into());
        }
        if self.journal.leases.iter().any(|lease| {
            matches!(
                lease.phase,
                super::persist::LeasePhase::Created | super::persist::LeasePhase::Validating
            )
        }) {
            if self.journal.next_attempt > now()
                || self.http.retry_after.load(Ordering::Relaxed) > now()
            {
                return Ok(());
            }
            let Some(url) = self
                .journal
                .order
                .as_ref()
                .filter(|o| !o.url.is_empty())
                .map(|o| o.url.clone())
            else {
                return Err(
                    "validation lease has no original order; retain for investigation".into(),
                );
            };
            self.account().await?;
            match self
                .account
                .as_ref()
                .ok_or("ACME account unavailable after restoration")?
                .order(url.clone())
                .await
            {
                Ok(mut order) => {
                    if order.state().status == OrderStatus::Pending {
                        let mut found = false;
                        let mut authorizations = order.authorizations();
                        while let Some(authorization) = authorizations.next().await {
                            let mut authorization = authorization?;
                            found = true;
                            if authorization.identifier().to_string() != self.journal.domain {
                                return Err("cleanup authorization identity mismatch".into());
                            }
                            if authorization.status == AuthorizationStatus::Pending {
                                let challenge = authorization
                                    .challenge(ChallengeType::Dns01)
                                    .ok_or("original DNS challenge missing")?;
                                if challenge.key_authorization()?.dns_value()
                                    != self.journal.leases[0].value
                                {
                                    return Err(
                                        "cleanup DNS challenge changed; retain ownership".into()
                                    );
                                }
                                if matches!(
                                    challenge.status,
                                    instant_acme::ChallengeStatus::Pending
                                        | instant_acme::ChallengeStatus::Processing
                                ) {
                                    return Ok(());
                                }
                            }
                        }
                        if !found {
                            return Err("pending order has no authorization evidence".into());
                        }
                    }
                }
                Err(instant_acme::Error::Response {
                    url: failed,
                    status: 404,
                    method: http::Method::POST,
                    ..
                }) if failed == url => {}
                Err(error) => return Err(error.into()),
            }
        }
        self.cleanup_finished().await
    }
    async fn cleanup_finished(&mut self) -> Result<()> {
        while let Some(lease) = self.journal.leases.first().cloned() {
            let mut lease = lease;
            if lease.phase == super::persist::LeasePhase::Preparing {
                self.journal.leases.remove(0);
                self.persist()?;
                continue;
            }
            self.provider.recover(&mut lease).await?;
            if lease.phase == super::persist::LeasePhase::Created || lease.record_id.is_some() {
                lease.phase = super::persist::LeasePhase::DeleteUncertain;
                self.journal.leases[0] = lease.clone();
                self.persist()?;
            }
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
        self.deadline = tokio::time::Instant::now() + self.operation_timeout;
        let result = tokio::time::timeout(self.operation_timeout, self.reconcile())
            .await
            .map_err(|_| -> Error { "ACME operation deadline exceeded".into() })
            .and_then(|r| r);
        match result {
            Ok(tick) => Ok(tick),
            Err(_) if !self.suspended => {
                self.journal.last_failure_phase = Some(self.phase.into());
                // Preserve mutation/validation state. Recovery runs inside the next
                // operation's budget; timeout must not start another 30s network phase.
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
                    // A durable order wait survives errors and transport observation resets.
                    .max(self.journal.next_attempt)
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
        if self.journal.order.is_none() {
            self.cleanup().await?;
        }
        if let Some(blocked) = &self.journal.blocked_certificate {
            if blocked.retry_at.is_none_or(|at| now() < at) {
                return Ok(Tick::Idle);
            }
            self.journal.blocked_certificate = None;
            self.persist()?;
        }
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
        if self
            .journal
            .order
            .as_ref()
            .ok_or("ACME order missing during reconciliation")?
            .url
            .is_empty()
        {
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
            let account = self
                .account
                .as_ref()
                .ok_or("ACME account unavailable after restoration")?;
            let order = match account.new_order(&request).await {
                Err(instant_acme::Error::Unsupported(_)) => {
                    account.new_order(&NewOrder::new(&identifiers)).await?
                }
                result => result?,
            };
            self.journal
                .order
                .as_mut()
                .ok_or("ACME order missing after creation")?
                .url = order.url().into();
            self.persist()?;
        }
        let saved = self
            .journal
            .order
            .as_ref()
            .ok_or("ACME order missing during reconciliation")?;
        self.phase = "recover-order";
        let mut order = match self
            .account
            .as_ref()
            .ok_or("ACME account unavailable during order restoration")?
            .order(saved.url.clone())
            .await
        {
            Ok(order) => order,
            Err(error) => {
                if matches!(&error, instant_acme::Error::Response {url,status:404,method:http::Method::POST,..} if url == &saved.url)
                {
                    self.cleanup_finished().await?;
                    self.journal.order = None;
                    self.persist()?;
                }
                return Err(error.into());
            }
        };
        if order.state().status == OrderStatus::Invalid {
            self.cleanup_finished().await?;
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
                let mut lease = if let Some(lease) = self.journal.leases.first() {
                    if lease.name != name || lease.value != value {
                        return Err(
                            "original DNS challenge identity changed; retain ownership evidence"
                                .into(),
                        );
                    }
                    lease.clone()
                } else {
                    Lease {
                        name,
                        value,
                        marker: format!("moon-naive-acme-{:016x}", random_below(u64::MAX)?),
                        phase: super::persist::LeasePhase::Preparing,
                        ..Lease::default()
                    }
                };
                if self.journal.leases.is_empty() {
                    self.journal.leases.push(lease.clone());
                    self.persist()?;
                }
                if lease.phase == super::persist::LeasePhase::Validating {
                    // The durable ACK intent may precede the actual POST after a crash.
                    // Repeating set_ready on a still-Pending challenge is permitted.
                    if challenge.status == instant_acme::ChallengeStatus::Pending {
                        challenge.set_ready().await?;
                    }
                    continue;
                }
                if lease.phase == super::persist::LeasePhase::CreateUncertain {
                    self.provider.recover(&mut lease).await?;
                }
                if lease.phase == super::persist::LeasePhase::Preparing {
                    self.phase = "dns-prepare";
                    self.provider.prepare(&mut lease).await?;
                    lease.phase = super::persist::LeasePhase::CreateUncertain;
                    self.journal.leases[0] = lease.clone();
                    self.persist()?;
                    self.phase = "dns-present";
                    let result = self.provider.present(&mut lease).await;
                    self.journal.leases[0] = lease.clone();
                    self.persist()?;
                    result?;
                }
                lease.phase = super::persist::LeasePhase::Created;
                self.journal.leases[0] = lease.clone();
                self.persist()?;
                self.phase = "dns-propagation";
                while !self.provider.propagated(&lease).await? {
                    tokio::time::sleep(self.poll_interval).await;
                }
                self.phase = "challenge-ready";
                lease.phase = super::persist::LeasePhase::Validating;
                self.journal.leases[0] = lease;
                self.persist()?;
                challenge.set_ready().await?;
            }
            self.phase = "order-ready";
            let status = self.poll_order(&mut order, OrderStatus::Pending).await?;
            if status != OrderStatus::Ready {
                self.cleanup_finished().await?;
                self.journal.order = None;
                self.persist()?;
                return Err("ACME order failed validation".into());
            }
        }
        self.phase = "dns-cleanup";
        self.cleanup_finished().await?;
        if order.state().status == OrderStatus::Ready {
            self.phase = "finalize";
            order
                .finalize_csr(
                    &self
                        .journal
                        .order
                        .as_ref()
                        .ok_or("ACME order missing during reconciliation")?
                        .csr,
                )
                .await?;
        }
        self.phase = "certificate-download";
        self.poll_order(&mut order, OrderStatus::Processing).await?;
        let chain = order.certificate().await?.ok_or("certificate not ready")?;
        let candidate = Candidate {
            chain_pem: chain.into_bytes(),
            key_pem: self
                .journal
                .order
                .as_ref()
                .ok_or("ACME order missing during certificate download")?
                .key_pem
                .as_bytes()
                .to_vec(),
        };
        self.phase = "certificate-validation";
        let evidence = super::persist::BlockedCertificate::evidence(&candidate.chain_pem);
        let outcome = self
            .validator
            .download(candidate, now(), self.window)
            .unwrap_or_else(|error| {
                let category = if error.downcast_ref::<std::io::Error>().is_some() {
                    "local-trust-configuration-error"
                } else if error.to_string()
                    == "certificate chain, identity or validity verification failed"
                {
                    "chain-or-local-trust-needs-investigation"
                } else {
                    "invalid-certificate-material"
                };
                certificate::Download::Blocked {
                    category,
                    retry_at: None,
                }
            });
        let bundle = match outcome {
            certificate::Download::Usable(bundle) => bundle,
            certificate::Download::Blocked { category, retry_at } => {
                self.journal.blocked_certificate = Some(super::persist::BlockedCertificate {
                    category: category.into(),
                    retry_at,
                    ..evidence
                });
                self.journal.last_failure_phase = Some(category.into());
                self.persist()?;
                return Ok(Tick::RetryScheduled);
            }
            certificate::Download::Obsolete(lifetime) => {
                self.phase = "completed-certificate-obsolete";
                self.journal.retire_completed(
                    now(),
                    lifetime.not_after,
                    now()
                        .saturating_add(self.max_retry)
                        .max(self.http.retry_after.load(Ordering::Relaxed)),
                )?;
                // No new order until retirement and cooldown are durable. A failed
                // save suspends this manager; restart reconciles the old journal.
                self.persist()?;
                return Ok(Tick::RetryScheduled);
            }
        };
        let lifetime = bundle.lifetime();
        self.phase = "certificate-install";
        if let Err(failure) = self.store.install(&bundle) {
            if failure == StoreFailure::CommitUncertain {
                self.suspended = true;
            }
            return Err("certificate generation commit failed".into());
        }
        self.bundle = Some(bundle);
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
    // Manager owns durable scheduling; the library still owns every ACME/JWS request.
    // Persist before sleeping, including refresh waits, so cancellation cannot erase them.
    async fn poll_order(
        &mut self,
        order: &mut instant_acme::Order,
        waiting: OrderStatus,
    ) -> Result<OrderStatus> {
        // Preserve the library's default 250ms, 2x fallback; DNS propagation
        // has its separate configured poll interval.
        let mut fallback = Duration::from_millis(250);
        while order.state().status == waiting {
            let delay = match order.retry_after() {
                instant_acme::RetryAfter::At(at) => at
                    .duration_since(std::time::SystemTime::now())
                    .unwrap_or(Duration::ZERO),
                instant_acme::RetryAfter::Absent | instant_acme::RetryAfter::Malformed => {
                    let delay = fallback;
                    fallback = fallback.checked_mul(2).ok_or("order backoff overflow")?;
                    delay
                }
                instant_acme::RetryAfter::Unrepresentable => {
                    return Err("unrepresentable Retry-After".into());
                }
            };
            let next = tokio::time::Instant::now()
                .checked_add(delay)
                .ok_or("unrepresentable order deadline")?;
            self.journal.next_attempt = now()
                .checked_add(delay.as_secs())
                .and_then(|at| at.checked_add(u64::from(delay.subsec_nanos() != 0)))
                .ok_or("unrepresentable persisted order deadline")?
                .max(self.http.retry_after.load(Ordering::Relaxed));
            self.persist()?;
            if next > self.deadline {
                self.phase = "order-deferred";
                return Err("order wait exceeds operation deadline".into());
            }
            tokio::time::sleep_until(next).await;
            order.refresh().await?;
        }
        Ok(order.state().status)
    }
    fn certificate_id(&self) -> Option<CertificateIdentifier<'static>> {
        let bundle = self.current(now())?;
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
        let previous_wait = self.http.retry_after.swap(0, Ordering::Relaxed);
        let result = account.renewal_info(&id).await;
        let ari_wait = self.http.retry_after.swap(previous_wait, Ordering::Relaxed);
        let (info, check_after) = match result {
            Ok(info) => info,
            Err(_) => {
                // The local retry interval never overrides a remote not-before hint,
                // including one on an unsuccessful ARI response.
                self.journal.ari_check_at = self.journal.ari_check_at.max(ari_wait);
                return;
            }
        };
        // ARI is independent of order waits and certificate renew_at. A remote
        // delay can exceed the local recheck cadence without postponing renewal.
        let local = now().saturating_add(60);
        let Some(remote) = now().checked_add(check_after.as_secs()) else {
            return; // retain bounded local fallback; never persist a saturated date
        };
        self.journal.ari_check_at = local.max(remote).max(ari_wait);
        let (Ok(start), Ok(end)) = (
            u64::try_from(info.suggested_window.start.unix_timestamp()),
            u64::try_from(info.suggested_window.end.unix_timestamp()),
        ) else {
            return;
        };
        let Some(bundle) = self.current(now()) else {
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
