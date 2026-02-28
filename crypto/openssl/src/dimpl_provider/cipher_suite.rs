//! Cipher suite implementations using OpenSSL.

use dimpl::crypto::SupportedDtls12CipherSuite;
use dimpl::crypto::SupportedDtls13CipherSuite;
use dimpl::crypto::{Aad, Cipher, Dtls12CipherSuite, HashAlgorithm, Nonce};
use dimpl::crypto::{Buf, Dtls13CipherSuite, TmpBuf};

use openssl::cipher::CipherRef;
use openssl::cipher_ctx::CipherCtx;

const AES_GCM_TAG_LEN: usize = 16;

/// AES-GCM cipher implementation using OpenSSL.
struct AesGcm {
    key: Vec<u8>,
}

impl std::fmt::Debug for AesGcm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AesGcm").finish_non_exhaustive()
    }
}

impl AesGcm {
    fn new(key: &[u8]) -> Result<Self, String> {
        if key.len() != 16 && key.len() != 32 {
            return Err(format!("Invalid key size for AES-GCM: {}", key.len()));
        }
        Ok(Self { key: key.to_vec() })
    }

    fn cipher(&self) -> &'static CipherRef {
        if self.key.len() == 16 {
            openssl::cipher::Cipher::aes_128_gcm()
        } else {
            openssl::cipher::Cipher::aes_256_gcm()
        }
    }
}

impl Cipher for AesGcm {
    fn encrypt(&mut self, plaintext: &mut Buf, aad: Aad, nonce: Nonce) -> Result<(), String> {
        let mut ctx = CipherCtx::new().map_err(|e| format!("{e}"))?;

        ctx.encrypt_init(Some(self.cipher()), Some(&self.key), Some(&nonce))
            .map_err(|e| format!("{e}"))?;

        // Set AAD
        ctx.cipher_update(&aad, None).map_err(|e| format!("{e}"))?;

        // Encrypt plaintext
        // OpenSSL may write up to one extra block (16 bytes) during cipher_update/cipher_final.
        let mut ciphertext = vec![0u8; plaintext.len() + AES_GCM_TAG_LEN + 16];
        let count = ctx
            .cipher_update(plaintext, Some(&mut ciphertext))
            .map_err(|e| format!("{e}"))?;
        let final_count = ctx
            .cipher_final(&mut ciphertext[count..])
            .map_err(|e| format!("{e}"))?;

        let ct_len = count + final_count;

        // Get the tag
        let mut tag = [0u8; AES_GCM_TAG_LEN];
        ctx.tag(&mut tag).map_err(|e| format!("{e}"))?;

        plaintext.clear();
        plaintext.extend_from_slice(&ciphertext[..ct_len]);
        plaintext.extend_from_slice(&tag);
        Ok(())
    }

    fn decrypt(&mut self, ciphertext: &mut TmpBuf, aad: Aad, nonce: Nonce) -> Result<(), String> {
        if ciphertext.len() < AES_GCM_TAG_LEN {
            return Err("Ciphertext too short for GCM tag".into());
        }

        let ct_len = ciphertext.len() - AES_GCM_TAG_LEN;
        let (ct, tag) = ciphertext.as_ref().split_at(ct_len);

        let mut ctx = CipherCtx::new().map_err(|e| format!("{e}"))?;

        ctx.decrypt_init(Some(self.cipher()), Some(&self.key), Some(&nonce))
            .map_err(|e| format!("{e}"))?;

        // Set AAD
        ctx.cipher_update(&aad, None).map_err(|e| format!("{e}"))?;

        // Decrypt ciphertext
        // OpenSSL may write up to one extra block (16 bytes) during cipher_update/cipher_final.
        let mut plaintext = vec![0u8; ct_len + 16];
        let count = ctx
            .cipher_update(ct, Some(&mut plaintext))
            .map_err(|e| format!("{e}"))?;

        // Set tag before finalization
        ctx.set_tag(tag).map_err(|e| format!("{e}"))?;

        let final_count = ctx
            .cipher_final(&mut plaintext[count..])
            .map_err(|e| format!("{e}"))?;

        let pt_len = count + final_count;
        ciphertext.truncate(pt_len);
        ciphertext.as_mut().copy_from_slice(&plaintext[..pt_len]);
        Ok(())
    }
}

/// TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 cipher suite.
#[derive(Debug)]
struct Aes128GcmSha256;

impl SupportedDtls12CipherSuite for Aes128GcmSha256 {
    fn suite(&self) -> Dtls12CipherSuite {
        Dtls12CipherSuite::ECDHE_ECDSA_AES128_GCM_SHA256
    }

    fn hash_algorithm(&self) -> HashAlgorithm {
        HashAlgorithm::SHA256
    }

    fn key_lengths(&self) -> (usize, usize, usize) {
        (0, 16, 4)
    }

    fn create_cipher(&self, key: &[u8]) -> Result<Box<dyn Cipher>, String> {
        Ok(Box::new(AesGcm::new(key)?))
    }
}

/// TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 cipher suite.
#[derive(Debug)]
struct Aes256GcmSha384;

impl SupportedDtls12CipherSuite for Aes256GcmSha384 {
    fn suite(&self) -> Dtls12CipherSuite {
        Dtls12CipherSuite::ECDHE_ECDSA_AES256_GCM_SHA384
    }

    fn hash_algorithm(&self) -> HashAlgorithm {
        HashAlgorithm::SHA384
    }

    fn key_lengths(&self) -> (usize, usize, usize) {
        (0, 32, 4)
    }

    fn create_cipher(&self, key: &[u8]) -> Result<Box<dyn Cipher>, String> {
        Ok(Box::new(AesGcm::new(key)?))
    }
}

static AES_128_GCM_SHA256: Aes128GcmSha256 = Aes128GcmSha256;
static AES_256_GCM_SHA384: Aes256GcmSha384 = Aes256GcmSha384;

pub(super) static ALL_CIPHER_SUITES: &[&dyn SupportedDtls12CipherSuite] =
    &[&AES_128_GCM_SHA256, &AES_256_GCM_SHA384];

/// TLS_AES_128_GCM_SHA256 cipher suite (TLS 1.3 / DTLS 1.3).
#[derive(Debug)]
struct Tls13Aes128GcmSha256;

impl SupportedDtls13CipherSuite for Tls13Aes128GcmSha256 {
    fn suite(&self) -> Dtls13CipherSuite {
        Dtls13CipherSuite::AES_128_GCM_SHA256
    }

    fn hash_algorithm(&self) -> HashAlgorithm {
        HashAlgorithm::SHA256
    }

    fn key_len(&self) -> usize {
        16 // AES-128
    }

    fn iv_len(&self) -> usize {
        12 // GCM IV
    }

    fn tag_len(&self) -> usize {
        16 // GCM tag
    }

    fn create_cipher(&self, key: &[u8]) -> Result<Box<dyn Cipher>, String> {
        Ok(Box::new(AesGcm::new(key)?))
    }

    fn encrypt_sn(&self, sn_key: &[u8], sample: &[u8; 16]) -> [u8; 16] {
        aes_ecb_encrypt(sn_key, sample)
    }
}

/// TLS_AES_256_GCM_SHA384 cipher suite (TLS 1.3 / DTLS 1.3).
#[derive(Debug)]
struct Tls13Aes256GcmSha384;

impl SupportedDtls13CipherSuite for Tls13Aes256GcmSha384 {
    fn suite(&self) -> Dtls13CipherSuite {
        Dtls13CipherSuite::AES_256_GCM_SHA384
    }

    fn hash_algorithm(&self) -> HashAlgorithm {
        HashAlgorithm::SHA384
    }

    fn key_len(&self) -> usize {
        32 // AES-256
    }

    fn iv_len(&self) -> usize {
        12 // GCM IV
    }

    fn tag_len(&self) -> usize {
        16 // GCM tag
    }

    fn create_cipher(&self, key: &[u8]) -> Result<Box<dyn Cipher>, String> {
        Ok(Box::new(AesGcm::new(key)?))
    }

    fn encrypt_sn(&self, sn_key: &[u8], sample: &[u8; 16]) -> [u8; 16] {
        aes_ecb_encrypt(sn_key, sample)
    }
}

/// Static instances of supported DTLS 1.3 cipher suites.
static TLS13_AES_128_GCM_SHA256: Tls13Aes128GcmSha256 = Tls13Aes128GcmSha256;
static TLS13_AES_256_GCM_SHA384: Tls13Aes256GcmSha384 = Tls13Aes256GcmSha384;

/// All supported DTLS 1.3 cipher suites.
pub(super) static ALL_DTLS13_CIPHER_SUITES: &[&dyn SupportedDtls13CipherSuite] =
    &[&TLS13_AES_128_GCM_SHA256, &TLS13_AES_256_GCM_SHA384];

/// AES-ECB single block encryption for record number protection.
fn aes_ecb_encrypt(key: &[u8], input: &[u8; 16]) -> [u8; 16] {
    let cipher = match key.len() {
        16 => openssl::cipher::Cipher::aes_128_ecb(),
        32 => openssl::cipher::Cipher::aes_256_ecb(),
        n => panic!("Invalid AES key length for ECB: {n} (expected 16 or 32)"),
    };

    let mut ctx = CipherCtx::new().expect("CipherCtx::new");
    ctx.encrypt_init(Some(cipher), Some(key), None)
        .expect("encrypt_init");
    ctx.set_padding(false);

    let mut output = [0u8; 32]; // Extra space for block cipher
    let count = ctx
        .cipher_update(input, Some(&mut output))
        .expect("cipher_update");
    let _ = ctx
        .cipher_final(&mut output[count..])
        .expect("cipher_final");

    let mut result = [0u8; 16];
    result.copy_from_slice(&output[..16]);
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use dimpl::crypto::Cipher;

    #[test]
    fn aes128_gcm_encrypt_decrypt_roundtrip() {
        let key = [0x42u8; 16];
        let nonce = Nonce([0x01u8; 12]);
        let plaintext = b"hello world, this is a test message for AES-GCM";

        let mut cipher = AesGcm::new(&key).unwrap();

        // Encrypt
        let mut buf = Buf::new();
        buf.extend_from_slice(plaintext);
        cipher
            .encrypt(&mut buf, Aad([0u8; 13].into()), nonce)
            .unwrap();

        // Ciphertext should be plaintext_len + 16 (tag)
        assert_eq!(buf.len(), plaintext.len() + AES_GCM_TAG_LEN);
        // Should differ from plaintext
        assert_ne!(&buf.as_ref()[..plaintext.len()], &plaintext[..]);

        // Decrypt
        let mut backing = buf.as_ref().to_vec();
        let mut tmp = TmpBuf::new(&mut backing);
        cipher
            .decrypt(&mut tmp, Aad([0u8; 13].into()), nonce)
            .unwrap();
        assert_eq!(tmp.as_ref(), plaintext);
    }

    #[test]
    fn aes256_gcm_encrypt_decrypt_roundtrip() {
        let key = [0x42u8; 32];
        let nonce = Nonce([0x02u8; 12]);
        let plaintext = b"AES-256-GCM test";

        let mut cipher = AesGcm::new(&key).unwrap();

        let mut buf = Buf::new();
        buf.extend_from_slice(plaintext);
        cipher
            .encrypt(&mut buf, Aad([0u8; 13].into()), nonce)
            .unwrap();

        let mut backing = buf.as_ref().to_vec();
        let mut tmp = TmpBuf::new(&mut backing);
        cipher
            .decrypt(&mut tmp, Aad([0u8; 13].into()), nonce)
            .unwrap();
        assert_eq!(tmp.as_ref(), plaintext);
    }

    #[test]
    fn aes_gcm_wrong_key_fails_decrypt() {
        let key1 = [0x42u8; 16];
        let key2 = [0x43u8; 16];
        let nonce = Nonce([0x01u8; 12]);
        let plaintext = b"secret";

        let mut cipher1 = AesGcm::new(&key1).unwrap();
        let mut cipher2 = AesGcm::new(&key2).unwrap();

        let mut buf = Buf::new();
        buf.extend_from_slice(plaintext);
        cipher1
            .encrypt(&mut buf, Aad([0u8; 13].into()), nonce)
            .unwrap();

        let mut backing = buf.as_ref().to_vec();
        let mut tmp = TmpBuf::new(&mut backing);
        assert!(cipher2
            .decrypt(&mut tmp, Aad([0u8; 13].into()), nonce)
            .is_err());
    }

    #[test]
    fn aes_gcm_invalid_key_size_rejected() {
        assert!(AesGcm::new(&[0u8; 15]).is_err());
        assert!(AesGcm::new(&[0u8; 24]).is_err());
        assert!(AesGcm::new(&[0u8; 16]).is_ok());
        assert!(AesGcm::new(&[0u8; 32]).is_ok());
    }

    #[test]
    fn aes_ecb_encrypt_deterministic() {
        let key = [0u8; 16];
        let input = [0u8; 16];
        let result = aes_ecb_encrypt(&key, &input);
        assert_eq!(result.len(), 16);
        // Different input produces different output
        let input2 = [0x01u8; 16];
        let result2 = aes_ecb_encrypt(&key, &input2);
        assert_ne!(result, result2);
    }
}
