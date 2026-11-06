use super::{Result, http::Http, persist::Lease};
use async_trait::async_trait;
use hickory_proto::{
    op::{Message, MessageType, OpCode, Query, ResponseCode},
    rr::{Name, RData, RecordType},
};
use serde_json::{Value, json};
use std::{net::SocketAddr, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpStream, UdpSocket},
};

#[async_trait]
pub trait DnsProvider: Send {
    fn identity(&self) -> String;
    /// Read-only discovery and ownership lookup. Never mutate remote DNS here.
    async fn prepare(&mut self, _lease: &mut Lease) -> Result<()> {
        Ok(())
    }
    /// Intent is durable before this call. Recover ownership by marker after an
    /// uncertain API response; never adopt another record as owned.
    async fn present(&mut self, lease: &mut Lease) -> Result<()>;
    async fn propagated(&mut self, lease: &Lease) -> Result<bool>;
    /// Recover a confirmed creation before the manager durably enters deletion.
    async fn recover(&mut self, lease: &mut Lease) -> Result<()> {
        if lease.phase == super::persist::LeasePhase::CreateUncertain
            && lease.record_id.is_none()
            && !lease.borrowed
        {
            return Err("provider must establish uncertain DNS ownership".into());
        }
        Ok(())
    }
    async fn cleanup(&mut self, lease: &Lease) -> Result<()>;
}

#[async_trait]
impl<T: DnsProvider + ?Sized> DnsProvider for Box<T> {
    fn identity(&self) -> String {
        (**self).identity()
    }
    async fn prepare(&mut self, lease: &mut Lease) -> Result<()> {
        (**self).prepare(lease).await
    }
    async fn present(&mut self, lease: &mut Lease) -> Result<()> {
        (**self).present(lease).await
    }
    async fn propagated(&mut self, lease: &Lease) -> Result<bool> {
        (**self).propagated(lease).await
    }
    async fn recover(&mut self, lease: &mut Lease) -> Result<()> {
        (**self).recover(lease).await
    }
    async fn cleanup(&mut self, lease: &Lease) -> Result<()> {
        (**self).cleanup(lease).await
    }
}

pub fn provider_from_config(
    config: &moon_naive_core::config::Config,
    http: Http,
) -> Result<Box<dyn DnsProvider>> {
    use super::{persist::read_private, porkbun};
    match config.acme.dns_provider.as_str() {
        "cloudflare" => {
            #[derive(serde::Deserialize)]
            #[serde(deny_unknown_fields)]
            struct Credentials {
                api_token: String,
            }
            let credentials: Credentials = if let Some(c) = &config.acme.dns_credentials {
                Credentials {
                    api_token: c.api_token.clone().ok_or("Cloudflare api_token missing")?,
                }
            } else {
                crate::acme::persist::load_toml(&config.acme.dns_token_file, 16384)?
            };
            Ok(Box::new(Cloudflare::new(
                http,
                config
                    .acme
                    .dns_zone_id
                    .as_deref()
                    .ok_or("Cloudflare requires dns_zone_id")?,
                credentials.api_token,
            )?))
        }
        "porkbun" => {
            let credentials = if let Some(c) = &config.acme.dns_credentials {
                porkbun::Credentials::new(
                    c.apikey.clone().ok_or("Porkbun apikey missing")?,
                    c.secretapikey
                        .clone()
                        .ok_or("Porkbun secretapikey missing")?,
                )?
            } else {
                porkbun::Credentials::parse(&read_private(&config.acme.dns_token_file, 16384)?)?
            };
            Ok(Box::new(porkbun::Porkbun::new(
                http,
                config
                    .acme
                    .dns_zone
                    .as_deref()
                    .ok_or("Porkbun requires dns_zone")?,
                credentials,
            )?))
        }
        _ => Err("live DNS providers supported: porkbun, cloudflare".into()),
    }
}

pub struct Cloudflare {
    http: Http,
    token: String,
    zone: String,
    authorities: Option<(std::time::Instant, Vec<Vec<SocketAddr>>)>,
    api_base: String,
}
impl Cloudflare {
    pub fn new(http: Http, zone: &str, token: String) -> Result<Self> {
        if zone.len() != 32
            || !zone.bytes().all(|b| b.is_ascii_hexdigit())
            || token.is_empty()
            || token.chars().any(char::is_control)
        {
            return Err("Cloudflare requires a 32-character zone ID and valid API token".into());
        }
        Ok(Self {
            http,
            zone: zone.into(),
            token,
            authorities: None,
            api_base: "https://api.cloudflare.com/client/v4".into(),
        })
    }
    async fn api(&self, method: &str, path: &str, data: Option<Value>) -> Result<Value> {
        let value = self
            .http
            .json(
                method,
                &format!("{}/zones/{}{path}", self.api_base, self.zone),
                Some(&self.token),
                data,
            )
            .await?;
        if value.get("success").and_then(Value::as_bool) != Some(true) {
            return Err("Cloudflare API reported failure".into());
        }
        Ok(value)
    }
    async fn records(&self, lease: &Lease) -> Result<Vec<Value>> {
        if !moon_naive_core::policy::valid_dns_name(
            lease.name.trim_start_matches("_acme-challenge."),
        ) || !lease.name.starts_with("_acme-challenge.")
        {
            return Err("invalid challenge DNS name".into());
        }
        let value = self
            .api(
                "GET",
                &format!("/dns_records?type=TXT&name={}&per_page=1000", lease.name),
                None,
            )
            .await?;
        if value
            .pointer("/result_info/total_pages")
            .and_then(Value::as_u64)
            .unwrap_or(1)
            > 1
        {
            return Err("too many challenge records to safely reconcile".into());
        }
        Ok(value["result"]
            .as_array()
            .ok_or("Cloudflare records response malformed")?
            .clone())
    }
    async fn authorities(&mut self, lease: &Lease) -> Result<&[Vec<SocketAddr>]> {
        if self
            .authorities
            .as_ref()
            .is_none_or(|(until, _)| *until <= std::time::Instant::now())
        {
            let zone = self.api("GET", "", None).await?;
            let name = zone["result"]["name"]
                .as_str()
                .ok_or("Cloudflare zone name missing")?;
            let target = lease
                .name
                .strip_prefix("_acme-challenge.")
                .ok_or("invalid DNS-01 name")?;
            if target != name && !target.ends_with(&format!(".{name}")) {
                return Err("domain is outside configured DNS zone".into());
            }
            let servers = zone["result"]["name_servers"]
                .as_array()
                .ok_or("Cloudflare name servers missing")?;
            if servers.is_empty() || servers.len() > 16 {
                return Err("invalid authoritative DNS server count".into());
            }
            let mut addresses = Vec::new();
            for server in servers {
                let host = server.as_str().ok_or("invalid authoritative server")?;
                let resolved = tokio::time::timeout(
                    Duration::from_secs(5),
                    crate::resolve::lookup_control(host, 53),
                )
                .await??;
                let mut candidates = resolved.take(33).collect::<Vec<_>>();
                if candidates.is_empty() || candidates.len() > 32 {
                    return Err("invalid NS address count".into());
                }
                candidates.sort_by_key(|addr| !addr.is_ipv4());
                addresses.push(candidates);
            }
            self.authorities = Some((
                std::time::Instant::now() + Duration::from_secs(60),
                addresses,
            ));
        }
        Ok(&self.authorities.as_ref().unwrap().1)
    }
}
pub(super) fn matches_record(record: &Value, lease: &Lease) -> bool {
    record["type"] == "TXT"
        && record["content"] == lease.value
        && record["name"]
            .as_str()
            .is_some_and(|name| name.trim_end_matches('.').eq_ignore_ascii_case(&lease.name))
}
/// Common ownership policy; only field names and ID formats differ by provider.
pub(super) fn adopt(
    records: &[Value],
    lease: &mut Lease,
    marker: &str,
    id: fn(&Value) -> Result<String>,
    borrow: bool,
) -> Result<bool> {
    let owned = records
        .iter()
        .find(|r| matches_record(r, lease) && r[marker] == lease.marker);
    let found = owned.or_else(|| {
        if borrow {
            records.iter().find(|r| matches_record(r, lease))
        } else {
            None
        }
    });
    if let Some(record) = found {
        lease.record_id = Some(id(&record["id"])?);
        lease.borrowed = record[marker] != lease.marker;
        return Ok(true);
    }
    Ok(false)
}
/// Shared ownership transition; an empty read cannot resolve a durable send gap.
pub(super) fn recover_owned(
    records: &[Value],
    lease: &mut Lease,
    marker: &str,
    id: fn(&Value) -> Result<String>,
) -> Result<()> {
    if adopt(records, lease, marker, id, false)? {
        lease.phase = super::persist::LeasePhase::Created;
        return Ok(());
    }
    Err("DNS create outcome uncertain; retain marker and reconcile again".into())
}
pub(super) fn cleanup_known(records: &[Value], lease: &Lease, marker: &str) -> Result<()> {
    if lease.phase == super::persist::LeasePhase::CreateUncertain
        && lease.record_id.is_none()
        && !records
            .iter()
            .any(|r| matches_record(r, lease) && r[marker] == lease.marker)
    {
        return Err("DNS create outcome uncertain; retain lease and reconcile again".into());
    }
    Ok(())
}
fn record_id(value: &Value) -> Result<String> {
    let id = value.as_str().ok_or("Cloudflare record ID missing")?;
    if id.is_empty() || id.len() > 128 || !id.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("invalid Cloudflare record ID".into());
    }
    Ok(id.to_owned())
}
#[async_trait]
impl DnsProvider for Cloudflare {
    fn identity(&self) -> String {
        format!("cloudflare:{}", self.zone)
    }
    async fn prepare(&mut self, lease: &mut Lease) -> Result<()> {
        tokio::time::timeout(Duration::from_secs(15), async {
            self.authorities(lease).await?;
            adopt(
                &self.records(lease).await?,
                lease,
                "comment",
                record_id,
                true,
            )?;
            Ok(())
        })
        .await
        .map_err(|_| "DNS preparation deadline")?
    }
    async fn present(&mut self, lease: &mut Lease) -> Result<()> {
        if lease.record_id.is_some() {
            return Ok(());
        }
        if self.authorities.is_none() {
            return Err("DNS read-only preparation required".into());
        }
        let value = self
            .api(
                "POST",
                "/dns_records",
                Some(json!({"type":"TXT", "name":lease.name,
            "content":lease.value, "ttl":120, "comment":lease.marker})),
            )
            .await;
        if let Err(error) = &value
            && super::http::mutation_rejected(error)
        {
            lease.phase = super::persist::LeasePhase::Preparing;
        }
        let value = value?;
        lease.record_id = Some(record_id(&value["result"]["id"])?);
        lease.borrowed = false;
        Ok(())
    }
    async fn propagated(&mut self, lease: &Lease) -> Result<bool> {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
        let addresses = tokio::time::timeout_at(deadline, self.authorities(lease))
            .await
            .map_err(|_| "DNS discovery deadline")??
            .to_vec();
        for candidates in addresses {
            let mut visible = false;
            for address in candidates {
                let attempt = deadline.min(tokio::time::Instant::now() + Duration::from_secs(1));
                if matches!(
                    tokio::time::timeout_at(
                        attempt,
                        authoritative_txt(address, &lease.name, &lease.value)
                    )
                    .await,
                    Ok(Ok(true))
                ) {
                    visible = true;
                    break;
                }
                if tokio::time::Instant::now() >= deadline {
                    break;
                }
            }
            if !visible {
                self.authorities = None;
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
        recover_owned(&self.records(lease).await?, lease, "comment", record_id)
    }
    async fn cleanup(&mut self, lease: &Lease) -> Result<()> {
        if lease.borrowed {
            return Ok(());
        }
        let records = self.records(lease).await?;
        cleanup_known(&records, lease, "comment")?;
        for record in records {
            if !matches_record(&record, lease) || record["comment"] != lease.marker {
                continue;
            }
            let id = record_id(&record["id"])?;
            self.api("DELETE", &format!("/dns_records/{id}"), None)
                .await?;
        }
        Ok(())
    }
}

/// Query the authoritative server directly. Connected UDP validates source;
/// require ID, question, AA and matching TXT. TCP fallback handles truncation.
pub async fn authoritative_txt(server: SocketAddr, name: &str, value: &str) -> Result<bool> {
    tokio::time::timeout(Duration::from_secs(5), async {
        let id = super::random_below(65536)? as u16;
        let name = Name::from_ascii(format!("{}.", name.trim_end_matches('.')))?;
        let question = Query::query(name.clone(), RecordType::TXT);
        let mut query = Message::new(id, MessageType::Query, OpCode::Query);
        query.metadata.recursion_desired = false;
        query.add_query(question.clone());
        let wire = query.to_vec()?;
        let socket = UdpSocket::bind(if server.is_ipv4() {
            "0.0.0.0:0"
        } else {
            "[::]:0"
        })
        .await?;
        socket.connect(server).await?;
        socket.send(&wire).await?;
        let mut buffer = vec![0; 65535];
        let n = socket.recv(&mut buffer).await?;
        let mut response = Message::from_vec(&buffer[..n])?;
        // Validate the UDP transaction before allowing TCP fallback. A wrong
        // ID/question/opcode must not trigger another network operation.
        if response.id != id
            || response.message_type != MessageType::Response
            || response.op_code != OpCode::Query
            || response.queries != [question.clone()]
        {
            return Ok(false);
        }
        if response.truncation {
            let mut tcp = TcpStream::connect(server).await?;
            tcp.write_u16(wire.len() as u16).await?;
            tcp.write_all(&wire).await?;
            let len = tcp.read_u16().await? as usize;
            tcp.read_exact(&mut buffer[..len]).await?;
            response = Message::from_vec(&buffer[..len])?;
        }
        if response.id != id
            || response.response_code != ResponseCode::NoError
            || response.message_type != MessageType::Response
            || response.op_code != OpCode::Query
            || response.truncation
            || !response.authoritative
            || response.queries != [question]
        {
            return Ok(false);
        }
        Ok(response.answers.iter().any(|answer| {
            answer.name == name
                && answer.dns_class == hickory_proto::rr::DNSClass::IN
                && match &answer.data {
                    RData::TXT(txt) => txt
                        .txt_data
                        .iter()
                        .flat_map(|v| v.iter().copied())
                        .eq(value.bytes()),
                    _ => false,
                }
        }))
    })
    .await
    .map_err(|_| -> super::Error { "authoritative DNS query timed out".into() })?
}
