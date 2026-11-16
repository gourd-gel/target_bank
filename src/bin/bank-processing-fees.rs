//! Offline programmer tool. Never ship the private key to the bank.
#![forbid(unsafe_code)]
use rsa::pkcs8::{DecodePrivateKey, EncodePrivateKey, EncodePublicKey};
use rsa::{Oaep, RsaPrivateKey};
use std::{fs, io::Write, path::Path, process::ExitCode};

fn write_new(path: &Path, bytes: &[u8], private: bool) -> Result<(), Box<dyn std::error::Error>> {
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(if private { 0o600 } else { 0o644 });
    }
    let mut file = options.open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.as_slice() {
        [command, db, private] if command == "provision" => {
            let public = atm::processing::public_key_path(Path::new(db));
            if Path::new(private).exists() || public.exists() { return Err("key file already exists; refusing to overwrite".into()); }
            let key = RsaPrivateKey::new(&mut rand::rngs::OsRng, 2048)?;
            let secret = key.to_pkcs8_pem(Default::default())?;
            let pem = key.to_public_key().to_public_key_pem(Default::default())?;
            write_new(Path::new(private), secret.as_bytes(), true)?;
            write_new(&public, pem.as_bytes(), false)?;
            println!("Public key: {}. Keep the private key off the bank's machine. Restart the ATM to install the public key.", public.display());
        }
        [command, db, private] if command == "read" => {
            let pem = zeroize::Zeroizing::new(fs::read_to_string(private)?);
            let key = RsaPrivateKey::from_pkcs8_pem(&pem)?;
            let conn = rusqlite::Connection::open_with_flags(db, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)?;
            let mut stmt = conn.prepare("SELECT reference, ciphertext FROM records ORDER BY reference")?;
            let mut rows = stmt.query([])?;
            // Decrypt all records before printing, so a wrong key produces no partial output.
            let mut output = Vec::new();
            while let Some(row) = rows.next()? {
                let cipher: Vec<u8> = row.get(1)?;
                let plain = zeroize::Zeroizing::new(key.decrypt_blinded(&mut rand::rngs::OsRng, Oaep::new::<rsa::sha2::Sha256>(), &cipher)?);
                let data: serde_json::Value = serde_json::from_slice(&plain)?;
                output.push(serde_json::json!({"fee_reference": row.get::<_, i64>(0)?, "record": data}));
            }
            for record in output { println!("{record}"); }
        }
        _ => return Err("Usage: bank-processing-fees provision <bank.db> <private-key.pem> | read <bank.processing-fees.db> <private-key.pem>".into()),
    }
    Ok(())
}
fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("{e}");
            ExitCode::FAILURE
        }
    }
}
