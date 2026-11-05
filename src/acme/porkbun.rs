//! Porkbun v3 DNS-01: scoped TXT records, ownership notes and idempotent recovery.
use super::{
    Result,
    dns::{DnsProvider, authoritative_txt},
    http::Http,
    state::Lease,
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
        let value: Self = crate::acme::state::parse_toml(bytes)?;
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
fn matches(record: &Value, lease: &Lease) -> bool {
    record["type"] == "TXT"
        && record["content"] == lease.value
        && record["name"]
            .as_str()
            .is_some_and(|name| name.trim_end_matches('.').eq_ignore_ascii_case(&lease.name))
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
    async fn present(&mut self, lease: &mut Lease) -> Result<()> {
        let relative = self.relative(lease)?;
        self.discover().await?;
        let records = self.records(lease).await?;
        if let Some(record) = records
            .iter()
            .find(|r| matches(r, lease) && r["notes"] == lease.marker)
        {
            lease.record_id = Some(record_id(&record["id"])?);
            lease.borrowed = false;
            return Ok(());
        }
        if let Some(record) = records.iter().find(|r| matches(r, lease)) {
            lease.record_id = Some(record_id(&record["id"])?);
            lease.borrowed = true;
            return Ok(());
        }
        let value = self
            .api(
                &format!("/dns/create/{}", self.zone),
                json!({"name":relative,"type":"TXT",
            "content":lease.value,"ttl":600,"notes":lease.marker}),
                Some(&lease.marker),
            )
            .await?;
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
        if self.nameservers.is_none() {
            self.discover().await?;
        }
        for host in self.nameservers.as_ref().unwrap() {
            let mut addresses: Vec<_> = tokio::time::timeout(
                Duration::from_secs(5),
                tokio::net::lookup_host((host.as_str(), 53)),
            )
            .await??
            .collect();
            addresses.sort_by_key(|addr| !addr.is_ipv4());
            if addresses.is_empty() {
                return Err("Porkbun authoritative nameserver has no address".into());
            }
            let mut visible = false;
            for address in addresses {
                if authoritative_txt(address, &lease.name, &lease.value)
                    .await
                    .unwrap_or(false)
                {
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
    async fn cleanup(&mut self, lease: &Lease) -> Result<()> {
        if lease.borrowed {
            return Ok(());
        }
        for record in self.records(lease).await? {
            if matches(&record, lease) && record["notes"] == lease.marker {
                let id = record_id(&record["id"])?;
                self.api(&format!("/dns/delete/{}/{id}", self.zone), json!({}), None)
                    .await?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::super::tests::http_server;
    use super::*;
    use bytes::Bytes;
    use http::Response;
    use http_body_util::Full;
    use std::sync::{Arc, Mutex};

    fn credentials() -> Credentials {
        Credentials::parse(b"apikey = 'test-api-key'\nsecretapikey = 'test-secret-key'\n").unwrap()
    }
    fn lease() -> Lease {
        Lease {
            name: "_acme-challenge.proxy.example.dev".into(),
            value: "challenge-value".into(),
            marker: "moon-naive-unique-intent".into(),
            record_id: None,
            borrowed: false,
        }
    }
    #[tokio::test]
    async fn lost_create_response_recovery_preserves_foreign_records_and_borrowed_values() {
        let foreign = json!({"id":"9","type":"TXT","name":"_acme-challenge.proxy.example.dev","content":"another-value","notes":null});
        let records = Arc::new(Mutex::new(vec![foreign.clone()]));
        let creates = Arc::new(Mutex::new(0));
        let server = http_server({
            let records=records.clone();let creates=creates.clone();
            move |request| {
                let records=records.clone();let creates=creates.clone();
                async move {
                    let body:Value=serde_json::from_slice(request.body()).unwrap();
                    assert_eq!(request.method(),"POST");
                    assert_eq!(body["apikey"],"test-api-key");
                    assert_eq!(body["secretapikey"],"test-secret-key");
                    let mut status=200;
                    let value=match request.uri().path() {
                        "/domain/getNs/example.dev"=>json!({"status":"SUCCESS","ns":["curitiba.ns.porkbun.com","salvador.ns.porkbun.com"]}),
                        "/dns/retrieveByNameType/example.dev/TXT/_acme-challenge.proxy"=>json!({"status":"SUCCESS","records":*records.lock().unwrap()}),
                        "/dns/create/example.dev"=>{
                            assert_eq!(request.headers()["Idempotency-Key"],"moon-naive-unique-intent");
                            assert_eq!(body["name"],"_acme-challenge.proxy");
                            assert_eq!(body["type"],"TXT");assert_eq!(body["ttl"],600);
                            *creates.lock().unwrap()+=1;
                            records.lock().unwrap().push(json!({"id":"10","type":"TXT","name":"_acme-challenge.proxy.example.dev","content":body["content"],"notes":body["notes"]}));
                            status=500;json!({"status":"ERROR"})
                        }
                        "/dns/delete/example.dev/10"=>{
                            records.lock().unwrap().retain(|r|r["id"]!="10");json!({"status":"SUCCESS"})
                        }
                        _=>panic!("unexpected API endpoint"),
                    };
                    Response::builder().status(status).body(Full::new(Bytes::from(serde_json::to_vec(&value).unwrap()))).unwrap()
                }
            }
        }).await;
        let http = Http::new(None, Duration::from_secs(2))
            .unwrap()
            .with_loopback_http();
        let mut provider = Porkbun::new(http.clone(), "example.dev", credentials()).unwrap();
        provider.api_base = server.url.clone();
        let intent = lease();
        assert!(provider.present(&mut intent.clone()).await.is_err());
        // New process, original durable intent: discover the owned record by notes.
        let mut provider = Porkbun::new(http, "example.dev", credentials()).unwrap();
        provider.api_base = server.url.clone();
        let mut recovered = intent.clone();
        provider.present(&mut recovered).await.unwrap();
        assert_eq!(recovered.record_id.as_deref(), Some("10"));
        assert!(!recovered.borrowed);
        assert_eq!(*creates.lock().unwrap(), 1);
        provider.cleanup(&intent).await.unwrap();
        provider.cleanup(&intent).await.unwrap();
        assert_eq!(*records.lock().unwrap(), vec![foreign]);
        records.lock().unwrap().push(json!({"id":"11","type":"TXT","name":intent.name,"content":intent.value,"notes":"another-owner"}));
        let mut borrowed = intent;
        provider.present(&mut borrowed).await.unwrap();
        assert!(borrowed.borrowed);
        provider.cleanup(&borrowed).await.unwrap();
        assert_eq!(records.lock().unwrap().len(), 2);
    }
    #[tokio::test]
    async fn refuses_external_delegation_before_mutation_and_checks_relative_names() {
        let server = http_server(|request| async move {
            assert_eq!(request.uri().path(), "/domain/getNs/example.dev");
            Response::new(Full::new(Bytes::from_static(
                br#"{"status":"SUCCESS","ns":["ns1.other-provider.dev"]}"#,
            )))
        })
        .await;
        let http = Http::new(None, Duration::from_secs(2))
            .unwrap()
            .with_loopback_http();
        let mut provider = Porkbun::new(http, "example.dev", credentials()).unwrap();
        provider.api_base = server.url.clone();
        assert_eq!(
            provider.relative(&lease()).unwrap(),
            "_acme-challenge.proxy"
        );
        let mut apex = lease();
        apex.name = "_acme-challenge.example.dev".into();
        assert_eq!(provider.relative(&apex).unwrap(), "_acme-challenge");
        let mut outside = lease();
        outside.name = "_acme-challenge.badexample.dev".into();
        assert!(provider.relative(&outside).is_err());
        assert!(provider.present(&mut lease()).await.is_err());
        assert!(Credentials::parse(b"apikey = 'a'\nsecretapikey = ''").is_err());
        assert!(record_id(&json!("../1")).is_err());
    }
}
