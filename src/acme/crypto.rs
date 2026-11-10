use boring::{
    bn::{BigNum, BigNumContext},
    ec::{EcGroup, EcKey},
    ecdsa::EcdsaSig,
    nid::Nid,
    pkey::{PKey, Private},
};
use instant_acme::{
    CryptoProvider, EcCurve, Error, HmacKey, HmacKeyProvider, Jwk, JwkThumbFields, Sha256,
    SigningAlgorithm, SigningKey, SigningKeyProvider,
};
use rustls_pki_types::PrivatePkcs8KeyDer;

struct Provider;
static PROVIDER: Provider = Provider;
pub static CRYPTO: CryptoProvider = CryptoProvider {
    key_provider: &PROVIDER,
    sha256: &PROVIDER,
    hmac: &PROVIDER,
};

pub fn p256() -> Result<PKey<Private>, boring::error::ErrorStack> {
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?;
    PKey::from_ec_key(EcKey::generate(&group)?)
}
struct Key {
    key: EcKey<Private>,
    x: Vec<u8>,
    y: Vec<u8>,
}
fn fixed(n: &boring::bn::BigNumRef) -> Result<Vec<u8>, Error> {
    let bytes = n.to_vec();
    if bytes.len() > 32 {
        return Err(Error::KeyRejected);
    }
    let mut out = vec![0; 32 - bytes.len()];
    out.extend(bytes);
    Ok(out)
}
fn load(key: PKey<Private>) -> Result<Box<dyn SigningKey>, Error> {
    let key = key.ec_key().map_err(|_| Error::KeyRejected)?;
    if key.group().curve_name() != Some(Nid::X9_62_PRIME256V1) {
        return Err(Error::KeyRejected);
    }
    key.check_key().map_err(|_| Error::KeyRejected)?;
    let (mut x, mut y, mut ctx) = (
        BigNum::new().map_err(|_| Error::Crypto)?,
        BigNum::new().map_err(|_| Error::Crypto)?,
        BigNumContext::new().map_err(|_| Error::Crypto)?,
    );
    key.public_key()
        .affine_coordinates_gfp(key.group(), &mut x, &mut y, &mut ctx)
        .map_err(|_| Error::Crypto)?;
    Ok(Box::new(Key {
        key,
        x: fixed(&x)?,
        y: fixed(&y)?,
    }))
}
impl SigningKeyProvider for Provider {
    fn load_key(&self, der: PrivatePkcs8KeyDer<'static>) -> Result<Box<dyn SigningKey>, Error> {
        load(PKey::private_key_from_pkcs8(der.secret_pkcs8_der()).map_err(|_| Error::KeyRejected)?)
    }
    fn generate_key(&self) -> Result<(Box<dyn SigningKey>, PrivatePkcs8KeyDer<'static>), Error> {
        let key = p256().map_err(|_| Error::Crypto)?;
        let der = key.private_key_to_der_pkcs8().map_err(|_| Error::Crypto)?;
        Ok((load(key)?, PrivatePkcs8KeyDer::from(der)))
    }
}
impl SigningKey for Key {
    fn sign(&self, data: &[u8]) -> Result<Vec<u8>, Error> {
        let sig =
            EcdsaSig::sign(&boring::sha::sha256(data), &self.key).map_err(|_| Error::Crypto)?;
        let mut out = fixed(sig.r())?;
        out.extend(fixed(sig.s())?);
        Ok(out)
    }
    fn as_jwk(&self) -> Jwk<'_> {
        Jwk {
            alg: SigningAlgorithm::Es256,
            r#use: "sig",
            key: JwkThumbFields::Ec {
                crv: EcCurve::P256,
                x: &self.x,
                y: &self.y,
            },
        }
    }
    fn algorithm(&self) -> SigningAlgorithm {
        SigningAlgorithm::Es256
    }
}
impl Sha256 for Provider {
    fn hash(&self, data: &[u8]) -> [u8; 32] {
        boring::sha::sha256(data)
    }
}
struct Hmac(Vec<u8>);
impl HmacKeyProvider for Provider {
    fn load_key(&self, bytes: &[u8]) -> Box<dyn HmacKey> {
        Box::new(Hmac(bytes.to_vec()))
    }
}
impl HmacKey for Hmac {
    fn sign(&self, data: &[u8]) -> Vec<u8> {
        boring::hash::hmac_sha256(&self.0, data)
            .expect("SHA-256 HMAC available")
            .to_vec()
    }
    fn algorithm(&self) -> SigningAlgorithm {
        SigningAlgorithm::Hs256
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn pkcs8_reload_and_raw_jws_signature_verify() {
        let (key, der) = PROVIDER.generate_key().unwrap();
        let public = PKey::private_key_from_pkcs8(der.secret_pkcs8_der())
            .unwrap()
            .ec_key()
            .unwrap();
        let reloaded = SigningKeyProvider::load_key(&PROVIDER, der).unwrap();
        let sig = reloaded.sign(b"independent JWS payload").unwrap();
        assert_eq!(sig.len(), 64);
        let signature = EcdsaSig::from_private_components(
            BigNum::from_slice(&sig[..32]).unwrap(),
            BigNum::from_slice(&sig[32..]).unwrap(),
        )
        .unwrap();
        assert!(
            signature
                .verify(&boring::sha::sha256(b"independent JWS payload"), &public)
                .unwrap()
        );
        assert!(
            !signature
                .verify(&boring::sha::sha256(b"different payload"), &public)
                .unwrap()
        );
        assert_eq!(
            serde_json::to_value(key.as_jwk()).unwrap(),
            serde_json::to_value(reloaded.as_jwk()).unwrap()
        );
    }
    #[test]
    fn rfc4231_hmac_sha256_vector() {
        let signature = HmacKeyProvider::load_key(&PROVIDER, &[0x0b; 20]).sign(b"Hi There");
        assert_eq!(
            signature,
            [
                0xb0, 0x34, 0x4c, 0x61, 0xd8, 0xdb, 0x38, 0x53, 0x5c, 0xa8, 0xaf, 0xce, 0xaf, 0x0b,
                0xf1, 0x2b, 0x88, 0x1d, 0xc2, 0x00, 0xc9, 0x83, 0x3d, 0xa7, 0x26, 0xe9, 0x37, 0x6c,
                0x2e, 0x32, 0xcf, 0xf7
            ]
        );
    }
}
