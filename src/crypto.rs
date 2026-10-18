use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use rand::rngs::OsRng;
use rand::{Rng, RngCore};
use zeroize::Zeroizing;

// File layout: "KPVLT01\0" | m_cost u32 | t_cost u32 | p_cost u32 | salt | nonce | ciphertext+tag
const MAGIC: &[u8; 8] = b"KPVLT01\0";
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 12;
const KEY_LEN: usize = 32;
const HEADER_LEN: usize = 8 + 12 + SALT_LEN + NONCE_LEN;
const TAG_LEN: usize = 16;

// Argon2id cost: 64 MiB, 3 passes, single lane.
const M_COST: u32 = 64 * 1024;
const T_COST: u32 = 3;
const P_COST: u32 = 1;

// Derived key + salt kept in memory while the vault is unlocked, so saving only
// re-runs the (fast) AEAD step instead of the (slow) KDF on every keystroke.
pub struct EncKey {
    key: Zeroizing<[u8; KEY_LEN]>,
    salt: [u8; SALT_LEN],
}

fn random_bytes<const N: usize>() -> [u8; N] {
    let mut buf = [0u8; N];
    let mut rng = OsRng;
    rng.fill_bytes(&mut buf);
    buf
}

fn derive(
    password: &str,
    salt: &[u8],
    m: u32,
    t: u32,
    p: u32,
) -> anyhow::Result<Zeroizing<[u8; KEY_LEN]>> {
    let params = Params::new(m, t, p, Some(KEY_LEN))
        .map_err(|e| anyhow::anyhow!("invalid Argon2 parameters: {e}"))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    argon
        .hash_password_into(password.as_bytes(), salt, key.as_mut_slice())
        .map_err(|e| anyhow::anyhow!("key derivation failed: {e}"))?;
    Ok(key)
}

fn seal_with(key: &[u8; KEY_LEN], salt: &[u8; SALT_LEN], plaintext: &[u8]) -> anyhow::Result<Vec<u8>> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    let nonce = random_bytes::<NONCE_LEN>();
    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&nonce), plaintext)
        .map_err(|_| anyhow::anyhow!("encryption failed"))?;

    let mut out = Vec::with_capacity(HEADER_LEN + ciphertext.len());
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&M_COST.to_le_bytes());
    out.extend_from_slice(&T_COST.to_le_bytes());
    out.extend_from_slice(&P_COST.to_le_bytes());
    out.extend_from_slice(salt);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Fresh vault: new salt, derived key, one encryption.
pub fn create(password: &str, plaintext: &[u8]) -> anyhow::Result<(Vec<u8>, EncKey)> {
    let salt = random_bytes::<SALT_LEN>();
    let key = derive(password, &salt, M_COST, T_COST, P_COST)?;
    let blob = seal_with(&key, &salt, plaintext)?;
    Ok((blob, EncKey { key, salt }))
}

/// Re-encrypt with the cached key and a fresh nonce (no KDF).
pub fn reseal(enc: &EncKey, plaintext: &[u8]) -> anyhow::Result<Vec<u8>> {
    seal_with(&enc.key, &enc.salt, plaintext)
}

/// Decrypt a blob with an already-derived key (its salt must match `enc`).
/// Used to read back a vault this session exported; falls back to `unlock`.
pub fn open_with(enc: &EncKey, blob: &[u8]) -> anyhow::Result<Vec<u8>> {
    if blob.len() < HEADER_LEN + TAG_LEN || &blob[0..8] != MAGIC {
        anyhow::bail!("not a KP Vault file");
    }
    let nonce_start = 20 + SALT_LEN;
    let ct_start = nonce_start + NONCE_LEN;
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&enc.key[..]));
    cipher
        .decrypt(
            Nonce::from_slice(&blob[nonce_start..ct_start]),
            &blob[ct_start..],
        )
        .map_err(|_| anyhow::anyhow!("wrong key or damaged vault"))
}

/// Verify the password and return the plaintext plus the key to reuse for saves.
pub fn unlock(blob: &[u8], password: &str) -> anyhow::Result<(Vec<u8>, EncKey)> {
    if blob.len() < HEADER_LEN + TAG_LEN {
        anyhow::bail!("vault file is too small");
    }
    if &blob[0..8] != MAGIC {
        anyhow::bail!("not a KP Vault file");
    }

    let m = u32::from_le_bytes(blob[8..12].try_into().unwrap());
    let t = u32::from_le_bytes(blob[12..16].try_into().unwrap());
    let p = u32::from_le_bytes(blob[16..20].try_into().unwrap());

    let mut salt = [0u8; SALT_LEN];
    salt.copy_from_slice(&blob[20..20 + SALT_LEN]);
    let nonce_start = 20 + SALT_LEN;
    let ct_start = nonce_start + NONCE_LEN;

    let key = derive(password, &salt, m, t, p)?;
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key[..]));
    let plaintext = cipher
        .decrypt(Nonce::from_slice(&blob[nonce_start..ct_start]), &blob[ct_start..])
        .map_err(|_| anyhow::anyhow!("wrong password or damaged vault"))?;

    Ok((plaintext, EncKey { key, salt }))
}

const CHARSET: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%^&*-_=+";

pub fn gen_password(len: usize) -> String {
    let mut rng = OsRng;
    (0..len)
        .map(|_| CHARSET[rng.gen_range(0..CHARSET.len())] as char)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_unlock_roundtrip() {
        let (blob, _enc) = create("correct horse", b"hello vault").unwrap();
        let (plaintext, _) = unlock(&blob, "correct horse").unwrap();
        assert_eq!(plaintext, b"hello vault");
    }

    #[test]
    fn reseal_reuses_key() {
        let (_, enc) = create("pw", b"first").unwrap();
        let blob = reseal(&enc, b"second").unwrap();
        let (plaintext, _) = unlock(&blob, "pw").unwrap();
        assert_eq!(plaintext, b"second");
    }

    #[test]
    fn wrong_password_fails() {
        let (blob, _) = create("password-one", b"x").unwrap();
        assert!(unlock(&blob, "password-two").is_err());
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let (mut blob, _) = create("pw", b"secret").unwrap();
        let last = blob.len() - 1;
        blob[last] ^= 0xff;
        assert!(unlock(&blob, "pw").is_err());
    }

    #[test]
    fn fresh_nonce_each_seal() {
        let (_, enc) = create("pw", b"data").unwrap();
        assert_ne!(reseal(&enc, b"data").unwrap(), reseal(&enc, b"data").unwrap());
    }

    #[test]
    fn generated_password_length() {
        assert_eq!(gen_password(20).chars().count(), 20);
    }

    #[test]
    fn open_with_reuses_derived_key() {
        let (blob, enc) = create("pw", b"data").unwrap();
        assert_eq!(open_with(&enc, &blob).unwrap(), b"data");
    }

    #[test]
    fn open_with_rejects_foreign_key() {
        let (blob, _) = create("pw", b"data").unwrap();
        let (_, other) = create("other", b"x").unwrap();
        assert!(open_with(&other, &blob).is_err());
    }
}
