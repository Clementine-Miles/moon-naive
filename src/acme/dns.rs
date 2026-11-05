use super::{Result, http::Http, state::Lease};
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
    /// Intent is durable before this call. Recover ownership by marker after an
    /// uncertain API response; never adopt another record as owned.
    async fn present(&mut self, lease: &mut Lease) -> Result<()>;
    async fn propagated(&mut self, lease: &Lease) -> Result<bool>;
    async fn cleanup(&mut self, lease: &Lease) -> Result<()>;
}

#[async_trait]
impl<T: DnsProvider + ?Sized> DnsProvider for Box<T> {
    fn identity(&self) -> String {
        (**self).identity()
    }
    async fn present(&mut self, lease: &mut Lease) -> Result<()> {
        (**self).present(lease).await
    }
    async fn propagated(&mut self, lease: &Lease) -> Result<bool> {
        (**self).propagated(lease).await
    }
    async fn cleanup(&mut self, lease: &Lease) -> Result<()> {
        (**self).cleanup(lease).await
    }
}

pub fn provider_from_config(
    config: &moon_naive_core::config::Config,
    http: Http,
) -> Result<Box<dyn DnsProvider>> {
    use super::{porkbun, state::read_private};
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
                crate::acme::state::load_toml(&config.acme.dns_token_file, 16384)?
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
    authorities: Option<Vec<SocketAddr>>,
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
    async fn authorities(&mut self, lease: &Lease) -> Result<&[SocketAddr]> {
        if self.authorities.is_none() {
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
                    tokio::net::lookup_host((host, 53)),
                )
                .await??;
                // Query one reachable address for every authoritative server.
                let address = resolved
                    .min_by_key(|addr| !addr.is_ipv4())
                    .ok_or("authoritative server has no address")?;
                addresses.push(address);
            }
            self.authorities = Some(addresses);
        }
        Ok(self.authorities.as_deref().unwrap())
    }
}
fn matches_record(record: &Value, lease: &Lease) -> bool {
    record["type"] == "TXT"
        && record["name"]
            .as_str()
            .is_some_and(|v| v.trim_end_matches('.').eq_ignore_ascii_case(&lease.name))
        && record["content"] == lease.value
}
#[async_trait]
impl DnsProvider for Cloudflare {
    fn identity(&self) -> String {
        format!("cloudflare:{}", self.zone)
    }
    async fn present(&mut self, lease: &mut Lease) -> Result<()> {
        // Validate zone ownership before any write, also primes NS discovery.
        self.authorities(lease).await?;
        let records = self.records(lease).await?;
        if let Some(record) = records
            .iter()
            .find(|r| matches_record(r, lease) && r["comment"] == lease.marker)
        {
            lease.record_id = Some(record["id"].as_str().ok_or("record ID missing")?.into());
            lease.borrowed = false;
            return Ok(());
        }
        if let Some(record) = records.iter().find(|r| matches_record(r, lease)) {
            lease.record_id = Some(record["id"].as_str().ok_or("record ID missing")?.into());
            lease.borrowed = true;
            return Ok(());
        }
        let value = self
            .api(
                "POST",
                "/dns_records",
                Some(json!({"type":"TXT", "name":lease.name,
            "content":lease.value, "ttl":120, "comment":lease.marker})),
            )
            .await?;
        lease.record_id = Some(
            value["result"]["id"]
                .as_str()
                .ok_or("record ID missing after creation")?
                .into(),
        );
        lease.borrowed = false;
        Ok(())
    }
    async fn propagated(&mut self, lease: &Lease) -> Result<bool> {
        let addresses = self.authorities(lease).await?.to_vec();
        for address in addresses {
            if !authoritative_txt(address, &lease.name, &lease.value)
                .await
                .unwrap_or(false)
            {
                return Ok(false);
            }
        }
        Ok(true)
    }
    async fn cleanup(&mut self, lease: &Lease) -> Result<()> {
        if lease.borrowed {
            return Ok(());
        }
        for record in self.records(lease).await? {
            if !matches_record(&record, lease) || record["comment"] != lease.marker {
                continue;
            }
            let id = record["id"].as_str().ok_or("record ID missing")?;
            if !id.bytes().all(|b| b.is_ascii_hexdigit()) {
                return Err("invalid DNS record ID".into());
            }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::acme::tests::http_server;
    use bytes::Bytes;
    use http_body_util::Full;
    use std::sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    };

    #[tokio::test]
    async fn authoritative_txt_checks_transaction_before_tcp_and_validates_fallback() {
        use hickory_proto::rr::{DNSClass, Record, rdata::TXT};
        for case in 0..8 {
            let tcp = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = tcp.local_addr().unwrap();
            let udp = UdpSocket::bind(address).await.unwrap();
            let server = tokio::spawn(async move {
                let mut buffer = [0u8; 4096];
                let (n, peer) = udp.recv_from(&mut buffer).await.unwrap();
                let query = Message::from_vec(&buffer[..n]).unwrap();
                assert!(!query.recursion_desired);
                assert_eq!(query.queries.len(), 1);
                let mut reply = Message::response(query.id, OpCode::Query);
                reply.metadata.authoritative = true;
                reply.add_queries(query.queries.clone());
                reply.answers.push(Record::from_rdata(
                    Name::from_ascii("_acme-challenge.example.test.").unwrap(),
                    30,
                    RData::TXT(TXT::new(vec!["test-".into(), "token".into()])),
                ));
                if case == 2 {
                    reply.metadata.id = reply.id.wrapping_add(1);
                }
                if case == 3 {
                    reply.metadata.op_code = OpCode::Update;
                }
                if case == 4 {
                    reply.queries.clear();
                }
                if case == 5 {
                    reply.metadata.authoritative = false;
                }
                if case == 6 {
                    reply.answers[0].dns_class = DNSClass::CH;
                }
                reply.metadata.truncation = matches!(case, 1..=4 | 7);
                udp.send_to(&reply.to_vec().unwrap(), peer).await.unwrap();
                if case == 1 || case == 7 {
                    let (mut stream, _) =
                        tokio::time::timeout(Duration::from_secs(2), tcp.accept())
                            .await
                            .unwrap()
                            .unwrap();
                    let n = stream.read_u16().await.unwrap() as usize;
                    stream.read_exact(&mut buffer[..n]).await.unwrap();
                    assert_eq!(Message::from_vec(&buffer[..n]).unwrap().id, query.id);
                    reply.metadata.truncation = case == 7;
                    let bytes = reply.to_vec().unwrap();
                    stream.write_u16(bytes.len() as u16).await.unwrap();
                    stream.write_all(&bytes).await.unwrap();
                } else {
                    assert!(
                        tokio::time::timeout(Duration::from_millis(50), tcp.accept())
                            .await
                            .is_err(),
                        "invalid transaction triggered TCP fallback"
                    );
                }
            });
            assert_eq!(
                authoritative_txt(address, "_acme-challenge.example.test", "test-token")
                    .await
                    .unwrap(),
                case <= 1,
                "case {case}"
            );
            server.await.unwrap();
        }
    }

    #[tokio::test]
    async fn uncertain_create_recovers_by_marker_and_preserves_foreign_txt() {
        let foreign = json!({"id":"11111111111111111111111111111111","name":"_acme-challenge.example.test",
            "type":"TXT","content":"foreign-value","comment":"another application"});
        let records = Arc::new(Mutex::new(vec![foreign.clone()]));
        let posts = Arc::new(AtomicUsize::new(0));
        let server=http_server({let records=records.clone();let posts=posts.clone();move |request| {
            let records=records.clone();let posts=posts.clone();async move {
                let path=request.uri().path();
                let mut status=200;
                let result=if path.ends_with("/dns_records") {
                    if request.method()==http::Method::POST {
                        let mut record:Value=serde_json::from_slice(request.body()).unwrap();
                        record["id"]=json!("22222222222222222222222222222222");
                        records.lock().unwrap().push(record.clone());
                        if posts.fetch_add(1,Ordering::Relaxed)==0 {status=500;}
                        json!({"success":true,"result":record})
                    } else {json!({"success":true,"result":*records.lock().unwrap(),"result_info":{"total_pages":1}})}
                } else if request.method()==http::Method::DELETE {
                    let id=path.rsplit('/').next().unwrap();
                    records.lock().unwrap().retain(|record|record["id"]!=id);
                    json!({"success":true,"result":{"id":id}})
                } else {json!({"success":true,"result":{"name":"example.test","name_servers":["localhost"]}})};
                http::Response::builder().status(status).body(Full::new(Bytes::from(serde_json::to_vec(&result).unwrap()))).unwrap()
            }
        }}).await;
        let http = Http::new(None, Duration::from_secs(5))
            .unwrap()
            .with_loopback_http();
        let make_provider = || {
            let mut provider =
                Cloudflare::new(http.clone(), &"a".repeat(32), "test-token".into()).unwrap();
            provider.api_base = server.url.clone();
            provider
        };
        let mut lease = Lease {
            name: "_acme-challenge.example.test".into(),
            value: "own-value".into(),
            marker: "moon-naive-acme-test-unique".into(),
            record_id: None,
            borrowed: false,
        };
        let mut provider = make_provider();
        assert!(provider.present(&mut lease).await.is_err()); // DNS write happened; response failed.
        assert!(lease.record_id.is_none());
        let mut recovered = make_provider();
        recovered.present(&mut lease).await.unwrap();
        assert_eq!(posts.load(Ordering::Relaxed), 1); // No duplicate POST after restart.
        recovered.cleanup(&lease).await.unwrap();
        recovered.cleanup(&lease).await.unwrap(); // Idempotent cleanup.
        assert_eq!(*records.lock().unwrap(), [foreign]);
        lease.value = "foreign-value".into();
        lease.record_id = None;
        recovered.present(&mut lease).await.unwrap();
        assert!(lease.borrowed);
        recovered.cleanup(&lease).await.unwrap();
        assert_eq!(records.lock().unwrap().len(), 1);
    }
    #[tokio::test]
    async fn provider_retry_after_is_preserved() {
        let server = http_server(|_| async {
            http::Response::builder()
                .status(429)
                .header("Retry-After", "120")
                .body(Full::new(Bytes::from_static(b"{}")))
                .unwrap()
        })
        .await;
        let http = Http::new(None, Duration::from_secs(5))
            .unwrap()
            .with_loopback_http();
        let mut provider =
            Cloudflare::new(http.clone(), &"a".repeat(32), "test-token".into()).unwrap();
        provider.api_base = server.url.clone();
        assert!(provider.api("GET", "", None).await.is_err());
        assert!(http.retry_after.load(Ordering::Relaxed) >= crate::acme::now() + 119);
    }
}
