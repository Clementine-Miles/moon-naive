//! Porkbun v3 DNS-01: scoped TXT records, ownership notes and idempotent recovery.
use super::{
    Result,
    dns::{DnsProvider, authoritative_txt},
    http::Http,
    persist::Lease,
};
use async_trait::async_trait;
use serde::Deserialize;
use serde_json::{Value, json};
use std::time::Duration;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Credentials {
    apikey: String,
    secretapikey: String,
}
impl Credentials {
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        let value: Self = crate::acme::persist::parse_toml(bytes)?;
        value.validate()
    }
    pub fn new(apikey: String, secretapikey: String) -> Result<Self> {
        Self {
            apikey,
            secretapikey,
        }
        .validate()
    }
    fn validate(self) -> Result<Self> {
        let value = self;
        for key in [&value.apikey, &value.secretapikey] {
            if key.is_empty() || key.len() > 4096 || key.chars().any(char::is_control) {
                return Err("invalid Porkbun API credentials".into());
            }
        }
        Ok(value)
    }
}
pub struct Porkbun {
    http: Http,
    zone: String,
    credentials: Credentials,
    nameservers: Option<Vec<String>>,
    api_base: String,
}
impl Porkbun {
    pub fn new(http: Http, zone: &str, credentials: Credentials) -> Result<Self> {
        if !moon_naive_core::policy::valid_dns_name(zone) || !zone.contains('.') {
            return Err("invalid Porkbun DNS zone".into());
        }
        Ok(Self {
            http,
            zone: zone.to_ascii_lowercase(),
            credentials,
            nameservers: None,
            api_base: "https://api.porkbun.com/api/json/v3".into(),
        })
    }
    fn relative(&self, lease: &Lease) -> Result<String> {
        let name = lease.name.to_ascii_lowercase();
        let target = name
            .strip_prefix("_acme-challenge.")
            .ok_or("invalid DNS-01 name")?;
        if !moon_naive_core::policy::valid_dns_name(target)
            || (target != self.zone && !target.ends_with(&format!(".{}", self.zone)))
        {
            return Err("challenge is outside configured Porkbun zone".into());
        }
        Ok(name
            .strip_suffix(&format!(".{}", self.zone))
            .ok_or("invalid Porkbun relative name")?
            .into())
    }
    async fn api(&self, path: &str, mut body: Value, idempotency: Option<&str>) -> Result<Value> {
        body["apikey"] = self.credentials.apikey.clone().into();
        body["secretapikey"] = self.credentials.secretapikey.clone().into();
        let headers = idempotency
            .map(|key| vec![("Idempotency-Key", key)])
            .unwrap_or_default();
        let value = self
            .http
            .json_headers(
                "POST",
                &format!("{}{path}", self.api_base),
                None,
                Some(body),
                &headers,
            )
            .await?;
        if value["status"] != "SUCCESS" {
            return Err("Porkbun API reported failure".into());
        }
        Ok(value)
    }
    async fn discover(&mut self) -> Result<()> {
        let data = self
            .api(&format!("/domain/getNs/{}", self.zone), json!({}), None)
            .await?;
        let servers = data["ns"].as_array().ok_or("Porkbun registry NS missing")?;
        if servers.is_empty() || servers.len() > 16 {
            return Err("invalid Porkbun nameserver count".into());
        }
        let mut names = Vec::new();
        for host in servers {
            let host = host
                .as_str()
                .ok_or("invalid Porkbun nameserver")?
                .trim_end_matches('.')
                .to_ascii_lowercase();
            if !moon_naive_core::policy::valid_dns_name(&host) || !host.ends_with(".porkbun.com") {
                return Err(
                    "domain is not delegated to Porkbun DNS; registrar alone is insufficient"
                        .into(),
                );
            }
            names.push(host);
        }
        self.nameservers = Some(names);
        Ok(())
    }
    async fn records(&self, lease: &Lease) -> Result<Vec<Value>> {
        let relative = self.relative(lease)?;
        let data = self
            .api(
                &format!("/dns/retrieveByNameType/{}/TXT/{relative}", self.zone),
                json!({}),
                None,
            )
            .await?;
        let records = data["records"]
            .as_array()
            .ok_or("Porkbun DNS records missing")?;
        if records.len() > 1000 {
            return Err("too many Porkbun TXT records to reconcile safely".into());
        }
        Ok(records.clone())
    }
}
fn record_id(value: &Value) -> Result<String> {
    let id = value
        .as_str()
        .map(str::to_owned)
        .or_else(|| value.as_u64().map(|n| n.to_string()))
        .ok_or("Porkbun record ID missing")?;
    if id.is_empty() || id.len() > 64 || !id.bytes().all(|b| b.is_ascii_digit()) {
        return Err("invalid Porkbun record ID".into());
    }
    Ok(id)
}
#[async_trait]
impl DnsProvider for Porkbun {
    fn identity(&self) -> String {
        format!("porkbun:{}", self.zone)
    }
    async fn prepare(&mut self, lease: &mut Lease) -> Result<()> {
        tokio::time::timeout(Duration::from_secs(15), async {
            self.relative(lease)?;
            self.discover().await?;
            super::dns::adopt(&self.records(lease).await?, lease, "notes", record_id, true)?;
            Ok(())
        })
        .await
        .map_err(|_| "DNS preparation deadline")?
    }
    async fn present(&mut self, lease: &mut Lease) -> Result<()> {
        if lease.record_id.is_some() {
            return Ok(());
        }
        let relative = self.relative(lease)?;
        if self.nameservers.is_none() {
            return Err("DNS read-only preparation required".into());
        }
        let value = self
            .api(
                &format!("/dns/create/{}", self.zone),
                json!({"name":relative,"type":"TXT",
            "content":lease.value,"ttl":600,"notes":lease.marker}),
                Some(&lease.marker),
            )
            .await;
        if let Err(error) = &value
            && super::http::mutation_rejected(error)
        {
            lease.phase = super::persist::LeasePhase::Preparing;
        }
        let value = value?;
        lease.record_id = Some(record_id(&value["id"])?);
        lease.borrowed = false;
        if value
            .get("warnings")
            .is_some_and(|v| v.as_array().is_none_or(|w| !w.is_empty()))
        {
            return Err("Porkbun DNS write returned warnings; verify delegation".into());
        }
        Ok(())
    }
    async fn propagated(&mut self, lease: &Lease) -> Result<bool> {
        self.relative(lease)?;
        let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
        if self.nameservers.is_none() {
            tokio::time::timeout_at(deadline, self.discover())
                .await
                .map_err(|_| "DNS discovery deadline")??;
        }
        for host in self.nameservers.as_ref().unwrap() {
            let mut addresses: Vec<_> = tokio::time::timeout_at(
                deadline.min(tokio::time::Instant::now() + Duration::from_secs(5)),
                crate::resolve::lookup_control(host.as_str(), 53),
            )
            .await??
            .take(33)
            .collect();
            if addresses.len() > 32 {
                return Err("too many authoritative DNS candidates".into());
            }
            addresses.sort_by_key(|addr| !addr.is_ipv4());
            if addresses.is_empty() {
                return Err("Porkbun authoritative nameserver has no address".into());
            }
            let mut visible = false;
            for address in addresses {
                if matches!(
                    tokio::time::timeout_at(
                        deadline.min(tokio::time::Instant::now() + Duration::from_secs(1)),
                        authoritative_txt(address, &lease.name, &lease.value)
                    )
                    .await,
                    Ok(Ok(true))
                ) {
                    visible = true;
                    break;
                }
            }
            if !visible {
                return Ok(false);
            }
        }
        Ok(true)
    }
    async fn recover(&mut self, lease: &mut Lease) -> Result<()> {
        if lease.borrowed
            || lease.record_id.is_some()
            || lease.phase != super::persist::LeasePhase::CreateUncertain
        {
            return Ok(());
        }
        super::dns::recover_owned(&self.records(lease).await?, lease, "notes", record_id)
    }
    async fn cleanup(&mut self, lease: &Lease) -> Result<()> {
        if lease.borrowed {
            return Ok(());
        }
        let records = self.records(lease).await?;
        super::dns::cleanup_known(&records, lease, "notes")?;
        for record in records {
            if super::dns::matches_record(&record, lease) && record["notes"] == lease.marker {
                let id = record_id(&record["id"])?;
                self.api(&format!("/dns/delete/{}/{id}", self.zone), json!({}), None)
                    .await?;
            }
        }
        Ok(())
    }
}
