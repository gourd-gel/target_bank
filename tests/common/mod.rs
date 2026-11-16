use std::path::Path;

/// Install only a test public key. No private key is written to the bank folder.
pub fn provision(db: &Path) {
    use rsa::pkcs8::EncodePublicKey;
    static PEM: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    let pem = PEM.get_or_init(|| {
        rsa::RsaPrivateKey::new(&mut rand::rngs::OsRng, 2048)
            .unwrap()
            .to_public_key()
            .to_public_key_pem(Default::default())
            .unwrap()
    });
    std::fs::write(atm::processing::public_key_path(db), pem).unwrap();
}
