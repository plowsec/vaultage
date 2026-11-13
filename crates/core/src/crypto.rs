//! Primitives: XChaCha20-Poly1305, BLAKE3 (hash/KDF/MAC), Argon2id. Keys live in locked, zeroized memory.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use crate::error::{Error, Result};

pub const NONCE_LEN: usize = 24;
pub const TAG_LEN: usize = 16;

/// 32-byte secret: heap-pinned, mlock'd (never swapped), wiped on drop.
pub struct Key(Box<[u8; 32]>);

impl Key {
    pub fn from_bytes(mut b: [u8; 32]) -> Key {
        let boxed = Box::new(b);
        b.zeroize();
        #[cfg(unix)]
        unsafe {
            libc::mlock(boxed.as_ptr() as *const libc::c_void, 32);
        }
        Key(boxed)
    }
    pub fn from_slice(s: &[u8]) -> Result<Key> {
        let a: [u8; 32] = s.try_into().map_err(|_| Error::Invalid("key must be 32 bytes".into()))?;
        Ok(Key::from_bytes(a))
    }
    pub fn random() -> Key {
        Key::from_bytes(random::<32>())
    }
    pub fn expose(&self) -> &[u8; 32] {
        &self.0
    }
    /// Domain-separated subkey (BLAKE3 KDF).
    pub fn derive(&self, context: &str) -> Key {
        Key::from_bytes(blake3::derive_key(context, &self.0[..]))
    }
    /// Subkey bound to extra input (keyed BLAKE3).
    pub fn derive_with(&self, input: &[u8]) -> Key {
        Key::from_bytes(*blake3::keyed_hash(&self.0, input).as_bytes())
    }
    pub fn mac(&self, data: &[u8]) -> [u8; 32] {
        *blake3::keyed_hash(&self.0, data).as_bytes()
    }
}

impl Clone for Key {
    fn clone(&self) -> Key {
        Key::from_bytes(*self.0)
    }
}

impl Drop for Key {
    fn drop(&mut self) {
        self.0.zeroize();
        #[cfg(unix)]
        unsafe {
            libc::munlock(self.0.as_ptr() as *const libc::c_void, 32);
        }
    }
}

pub fn random<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N];
    getrandom::fill(&mut b).expect("system RNG unavailable");
    b
}

pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

fn cipher(key: &Key) -> XChaCha20Poly1305 {
    XChaCha20Poly1305::new_from_slice(key.expose()).expect("32-byte key")
}

fn seal_with_nonce(key: &Key, nonce: [u8; NONCE_LEN], aad: &[u8], pt: &[u8]) -> Vec<u8> {
    let ct = cipher(key)
        .encrypt(&XNonce::from(nonce), Payload { msg: pt, aad })
        .expect("encryption cannot fail");
    let mut out = Vec::with_capacity(NONCE_LEN + ct.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    out
}

/// nonce(24) || ciphertext || tag(16), random nonce.
pub fn seal(key: &Key, aad: &[u8], pt: &[u8]) -> Vec<u8> {
    seal_with_nonce(key, random::<NONCE_LEN>(), aad, pt)
}

/// Deterministic (SIV-style): nonce = MAC(nonce_key, plaintext). Same plaintext under the same
/// keys gives the same ciphertext, which is what lets unchanged chunks dedup across versions.
pub fn seal_deterministic(key: &Key, nonce_key: &Key, aad: &[u8], pt: &[u8]) -> Vec<u8> {
    let mut h = blake3::Hasher::new_keyed(nonce_key.expose());
    h.update(&(aad.len() as u64).to_le_bytes());
    h.update(aad);
    h.update(pt);
    let mut nonce = [0u8; NONCE_LEN];
    nonce.copy_from_slice(&h.finalize().as_bytes()[..NONCE_LEN]);
    seal_with_nonce(key, nonce, aad, pt)
}

pub fn open(key: &Key, aad: &[u8], sealed: &[u8]) -> Result<Vec<u8>> {
    if sealed.len() < NONCE_LEN + TAG_LEN {
        return Err(Error::Crypto("ciphertext too short"));
    }
    let (nonce, ct) = sealed.split_at(NONCE_LEN);
    let nonce: [u8; NONCE_LEN] = nonce.try_into().unwrap();
    cipher(key)
        .decrypt(&XNonce::from(nonce), Payload { msg: ct, aad })
        .map_err(|_| Error::Crypto("decryption failed (wrong key or tampered data)"))
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct KdfParams {
    pub m_kib: u32,
    pub t: u32,
    pub p: u32,
}

impl KdfParams {
    /// ~0.3 s on Apple silicon; 128 MiB makes GPU/ASIC guessing expensive.
    pub fn strong() -> Self {
        KdfParams { m_kib: 128 * 1024, t: 3, p: 1 }
    }
    /// Tests only.
    pub fn weak_for_tests() -> Self {
        KdfParams { m_kib: 64, t: 1, p: 1 }
    }
}

pub fn argon2id(password: &[u8], salt: &[u8], p: &KdfParams) -> Result<Key> {
    if p.m_kib > 1024 * 1024 || p.t > 64 || p.p > 16 {
        return Err(Error::Format("unreasonable KDF parameters".into()));
    }
    let params = argon2::Params::new(p.m_kib, p.t, p.p, Some(32)).map_err(|e| Error::Format(e.to_string()))?;
    let a = argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
    let mut out = [0u8; 32];
    a.hash_password_into(password, salt, &mut out).map_err(|e| Error::Format(e.to_string()))?;
    Ok(Key::from_bytes(out))
}

/// Padmé: pad to a length that leaks only O(log log n) bits, <= 12% overhead. Floor of 256.
pub fn padded_len(len: usize) -> usize {
    if len <= 256 {
        return 256;
    }
    let e = usize::BITS - 1 - len.leading_zeros();
    let s = u32::BITS - e.leading_zeros();
    let mask = (1usize << (e - s)) - 1;
    (len + mask) & !mask
}

// ---- recovery key: 32 random bytes + 2 check bytes, Crockford base32, groups of 5 ----

const B32: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

pub fn recovery_encode(secret: &[u8; 32]) -> String {
    let mut data = secret.to_vec();
    data.extend_from_slice(&blake3::hash(secret).as_bytes()[..2]);
    let (mut acc, mut bits, mut out) = (0u32, 0u32, String::new());
    for b in &data {
        acc = (acc << 8) | *b as u32;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(B32[((acc >> bits) & 31) as usize] as char);
        }
    }
    if bits > 0 {
        out.push(B32[((acc << (5 - bits)) & 31) as usize] as char);
    }
    data.zeroize();
    out.as_bytes().chunks(5).map(|c| std::str::from_utf8(c).unwrap()).collect::<Vec<_>>().join("-")
}

pub fn recovery_decode(text: &str) -> Result<Key> {
    let bad = || Error::Invalid("not a valid recovery key".into());
    let (mut acc, mut bits, mut data) = (0u32, 0u32, Vec::with_capacity(34));
    for c in text.chars() {
        let c = match c.to_ascii_uppercase() {
            '-' | ' ' | '\n' | '\t' | '\r' => continue,
            'O' => '0',
            'I' | 'L' => '1',
            c => c,
        };
        let v = B32.iter().position(|x| *x as char == c).ok_or_else(bad)? as u32;
        acc = (acc << 5) | v;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            data.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    if data.len() != 34 || !ct_eq(&blake3::hash(&data[..32]).as_bytes()[..2], &data[32..]) {
        data.zeroize();
        return Err(bad());
    }
    let k = Key::from_slice(&data[..32]);
    data.zeroize();
    k
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_roundtrip_and_tamper() {
        let k = Key::random();
        let s = seal(&k, b"aad", b"hello");
        assert_eq!(open(&k, b"aad", &s).unwrap(), b"hello");
        assert!(open(&k, b"other", &s).is_err());
        let mut t = s.clone();
        *t.last_mut().unwrap() ^= 1;
        assert!(open(&k, b"aad", &t).is_err());
        assert!(open(&Key::random(), b"aad", &s).is_err());
    }

    #[test]
    fn deterministic_seal_is_stable_and_key_bound() {
        let (k, n) = (Key::random(), Key::random());
        let a = seal_deterministic(&k, &n, b"x", b"data");
        assert_eq!(a, seal_deterministic(&k, &n, b"x", b"data"));
        assert_ne!(a, seal_deterministic(&k, &n, b"x", b"datb"));
        assert_ne!(a, seal_deterministic(&k, &Key::random(), b"x", b"data"));
        assert_eq!(open(&k, b"x", &a).unwrap(), b"data");
    }

    #[test]
    fn recovery_roundtrip() {
        let s = random::<32>();
        let text = recovery_encode(&s);
        assert_eq!(text.len(), 55 + 10);
        assert_eq!(recovery_decode(&text).unwrap().expose(), &s);
        assert_eq!(recovery_decode(&text.to_lowercase().replace('-', " ")).unwrap().expose(), &s);
        let mut bad = text.clone().into_bytes();
        bad[0] = if bad[0] == b'A' { b'B' } else { b'A' };
        assert!(recovery_decode(std::str::from_utf8(&bad).unwrap()).is_err());
    }

    #[test]
    fn padding_bounds() {
        for n in [0usize, 1, 255, 256, 257, 1000, 4096, 100_000, 4_000_000, 4 * 1024 * 1024] {
            let p = padded_len(n);
            assert!(p >= n && p >= 256);
            assert!(n <= 256 || (p - n) as f64 <= 0.12 * n as f64, "{n} -> {p}");
        }
    }

    #[test]
    fn argon2_known_shape() {
        let a = argon2id(b"pw", b"saltsaltsaltsalt", &KdfParams::weak_for_tests()).unwrap();
        let b = argon2id(b"pw", b"saltsaltsaltsalt", &KdfParams::weak_for_tests()).unwrap();
        let c = argon2id(b"pw2", b"saltsaltsaltsalt", &KdfParams::weak_for_tests()).unwrap();
        assert_eq!(a.expose(), b.expose());
        assert_ne!(a.expose(), c.expose());
    }
}
