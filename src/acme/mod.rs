//! Live DNS-01 certificate management. All network crypto uses boring 5.
pub mod certificate;
pub mod crypto;
pub mod dns;
pub mod eab;
pub mod http;
pub mod manager;
pub mod porkbun;
pub mod state;
pub mod store;
#[cfg(test)]
mod tests;

pub type Error = Box<dyn std::error::Error + Send + Sync>;
pub type Result<T> = std::result::Result<T, Error>;

pub fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

pub fn random_below(bound: u64) -> Result<u64> {
    if bound == 0 {
        return Err("empty random range".into());
    }
    let limit = u64::MAX - (u64::MAX % bound);
    loop {
        let mut bytes = [0; 8];
        boring::rand::rand_bytes(&mut bytes)?;
        let n = u64::from_be_bytes(bytes);
        if n < limit {
            return Ok(n % bound);
        }
    }
}
