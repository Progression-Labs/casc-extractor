//! TACT encryption support for BLTE mode-E blocks.
//!
//! Blizzard uses TACT (Trusted Application Content Transfer) to encrypt
//! sensitive game data inside BLTE containers. Each encrypted block carries
//! an encryption header that names the key (a `u64` key name), provides an
//! IV, and identifies the cipher:
//!
//! - **Salsa20** (`S`) - Salsa20/20 with the 16-byte TACT key as a 128-bit key (the
//!   `expand 16-byte k` setup), and an 8-byte nonce: the IV padded to 8 bytes, its low four
//!   bytes XORed with the frame's index.
//! - **ARC4** (`A`) - RC4 with the standard WoW 1024-byte keystream skip.
//!
//! Keys are stored in a [`TactKeyStore`](crate::blte::encryption::TactKeyStore) which can be populated from the
//! bundled community-known key list or loaded from a text key file.

use std::collections::HashMap;
use std::path::Path;

use crate::error::{CascError, Result};

// ---------------------------------------------------------------------------
// TactKeyStore
// ---------------------------------------------------------------------------

/// Stores TACT encryption keys (key_name u64 -> 16-byte key value).
pub struct TactKeyStore {
    keys: HashMap<u64, [u8; 16]>,
}

impl Default for TactKeyStore {
    fn default() -> Self {
        Self::new()
    }
}

impl TactKeyStore {
    /// Create an empty key store.
    pub fn new() -> Self {
        Self {
            keys: HashMap::new(),
        }
    }

    /// Create a key store pre-populated with community-known WoW TACT keys.
    pub fn with_known_keys() -> Self {
        let mut keys = HashMap::new();
        for (name, value) in known_keys() {
            keys.insert(name, value);
        }
        Self { keys }
    }

    /// Load a key store from a text file.
    ///
    /// Format: one key per line as `hex_key_name hex_key_value`.
    /// Lines starting with `#` and blank lines are ignored.
    pub fn load_keyfile(path: &Path) -> Result<Self> {
        let content = std::fs::read_to_string(path)?;
        let mut keys = HashMap::new();

        for line in content.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }

            let parts: Vec<&str> = trimmed.split_whitespace().collect();
            if parts.len() < 2 {
                return Err(CascError::InvalidFormat(format!(
                    "invalid keyfile line: {}",
                    trimmed
                )));
            }

            let key_name = u64::from_str_radix(parts[0], 16).map_err(|e| {
                CascError::InvalidFormat(format!("invalid key name '{}': {}", parts[0], e))
            })?;

            let key_value = hex_to_key_result(parts[1])?;
            keys.insert(key_name, key_value);
        }

        Ok(Self { keys })
    }

    /// Merge keys from another store into this one.
    /// Existing keys are overwritten if the other store has the same key name.
    pub fn merge(&mut self, other: &TactKeyStore) {
        for (&name, &value) in &other.keys {
            self.keys.insert(name, value);
        }
    }

    /// Look up a key by name.
    pub fn get(&self, key_name: u64) -> Option<&[u8; 16]> {
        self.keys.get(&key_name)
    }

    /// Return the number of keys in the store.
    pub fn len(&self) -> usize {
        self.keys.len()
    }

    /// Return true if the store contains no keys.
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }
}

// ---------------------------------------------------------------------------
// Encryption header types
// ---------------------------------------------------------------------------

/// Encryption algorithm used by a BLTE encrypted block.
#[derive(Debug, PartialEq)]
pub enum EncryptionAlgorithm {
    /// Salsa20 stream cipher (mode byte `S`). The 16-byte key is doubled to 32 bytes.
    Salsa20,
    /// ARC4 (RC4) stream cipher with 1024-byte keystream skip (mode byte `A`).
    ARC4,
}

/// Parsed encryption header from a BLTE mode-E block.
#[derive(Debug)]
pub struct EncryptionHeader {
    /// 64-bit key name used to look up the decryption key in the [`TactKeyStore`].
    pub key_name: u64,
    /// Initialization vector for the cipher.
    pub iv: Vec<u8>,
    /// The encryption algorithm used (Salsa20 or ARC4).
    pub algorithm: EncryptionAlgorithm,
}

// ---------------------------------------------------------------------------
// Header parsing
// ---------------------------------------------------------------------------

/// Parse an encryption header from the data following the `E` mode byte.
///
/// The layout is `u8 key_name_size (8)`, `key_name[8]` (u64 LE), `u8 iv_size`, `iv[iv_size]`,
/// `u8 type` (`S` Salsa20, `A` ARC4), then the encrypted payload.
///
/// Returns the parsed header and a slice of the remaining encrypted payload.
pub fn parse_encryption_header(data: &[u8]) -> Result<(EncryptionHeader, &[u8])> {
    let truncated = |what: &str| CascError::InvalidFormat(format!("encryption header: {what}"));
    let mut pos = 0;

    let key_name_size = *data.get(pos).ok_or_else(|| truncated("empty data"))? as usize;
    pos += 1;
    if key_name_size != 8 {
        return Err(CascError::InvalidFormat(format!(
            "encryption header: expected key_name_size 8, got {key_name_size}"
        )));
    }
    let key_name_bytes = data
        .get(pos..pos + 8)
        .ok_or_else(|| truncated("truncated key_name"))?;
    let key_name = u64::from_le_bytes(key_name_bytes.try_into().expect("8 bytes"));
    pos += 8;

    let iv_size = *data
        .get(pos)
        .ok_or_else(|| truncated("truncated IV size"))? as usize;
    pos += 1;
    let iv = data
        .get(pos..pos + iv_size)
        .ok_or_else(|| truncated("truncated IV"))?
        .to_vec();
    pos += iv_size;

    let algorithm = match data
        .get(pos)
        .ok_or_else(|| truncated("missing encryption type"))?
    {
        b'S' => EncryptionAlgorithm::Salsa20,
        b'A' => EncryptionAlgorithm::ARC4,
        other => {
            return Err(CascError::InvalidFormat(format!(
                "encryption header: unknown algorithm 0x{other:02X}"
            )));
        }
    };
    pos += 1;

    Ok((
        EncryptionHeader {
            key_name,
            iv,
            algorithm,
        },
        &data[pos..],
    ))
}

// ---------------------------------------------------------------------------
// ARC4 (RC4 with 1024-byte skip)
// ---------------------------------------------------------------------------

struct Arc4 {
    s: [u8; 256],
    i: u8,
    j: u8,
}

impl Arc4 {
    fn new(key: &[u8]) -> Self {
        let mut s = [0u8; 256];
        for (i, slot) in s.iter_mut().enumerate() {
            *slot = i as u8;
        }
        // KSA requires in-place swaps driven by computed j, so indexing is necessary
        let mut j: u8 = 0;
        #[allow(clippy::needless_range_loop)]
        for i in 0..256 {
            j = j.wrapping_add(s[i]).wrapping_add(key[i % key.len()]);
            s.swap(i, j as usize);
        }
        // WoW-specific: skip first 1024 bytes of keystream
        let mut arc4 = Arc4 { s, i: 0, j: 0 };
        let mut discard = [0u8; 1024];
        arc4.process(&mut discard);
        arc4
    }

    fn process(&mut self, data: &mut [u8]) {
        for byte in data.iter_mut() {
            self.i = self.i.wrapping_add(1);
            self.j = self.j.wrapping_add(self.s[self.i as usize]);
            self.s.swap(self.i as usize, self.j as usize);
            let k =
                self.s[(self.s[self.i as usize].wrapping_add(self.s[self.j as usize])) as usize];
            *byte ^= k;
        }
    }
}

// ---------------------------------------------------------------------------
// Salsa20 decryption helper
// ---------------------------------------------------------------------------

/// One Salsa20/20 keystream block for a 128-bit key (`expand 16-byte k`).
fn salsa20_block(key: &[u8; 16], nonce: &[u8; 8], counter: u64) -> [u8; 64] {
    let word = |b: &[u8]| u32::from_le_bytes(b.try_into().expect("4 bytes"));
    let input: [u32; 16] = [
        0x6170_7865,
        word(&key[0..4]),
        word(&key[4..8]),
        word(&key[8..12]),
        word(&key[12..16]),
        0x3120_646e,
        word(&nonce[0..4]),
        word(&nonce[4..8]),
        counter as u32,
        (counter >> 32) as u32,
        0x7962_2d36,
        word(&key[0..4]),
        word(&key[4..8]),
        word(&key[8..12]),
        word(&key[12..16]),
        0x6b20_6574,
    ];
    let mut x = input;
    macro_rules! qr {
        ($a:expr, $b:expr, $c:expr, $d:expr) => {
            x[$b] ^= x[$a].wrapping_add(x[$d]).rotate_left(7);
            x[$c] ^= x[$b].wrapping_add(x[$a]).rotate_left(9);
            x[$d] ^= x[$c].wrapping_add(x[$b]).rotate_left(13);
            x[$a] ^= x[$d].wrapping_add(x[$c]).rotate_left(18);
        };
    }
    for _ in 0..10 {
        qr!(0, 4, 8, 12);
        qr!(5, 9, 13, 1);
        qr!(10, 14, 2, 6);
        qr!(15, 3, 7, 11);
        qr!(0, 1, 2, 3);
        qr!(5, 6, 7, 4);
        qr!(10, 11, 8, 9);
        qr!(15, 12, 13, 14);
    }
    let mut out = [0u8; 64];
    for (i, (a, b)) in x.iter().zip(input.iter()).enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&a.wrapping_add(*b).to_le_bytes());
    }
    out
}

/// Apply the Salsa20 keystream of a TACT key, IV and frame index to `data` (it encrypts and
/// decrypts alike).
pub fn apply_salsa20(key: &[u8; 16], iv: &[u8], frame_index: u32, data: &mut [u8]) {
    // The IV padded to the 8-byte nonce, its low four bytes XORed with the frame index.
    let mut nonce = [0u8; 8];
    let copy_len = iv.len().min(8);
    nonce[..copy_len].copy_from_slice(&iv[..copy_len]);
    for (byte, index_byte) in nonce.iter_mut().zip(frame_index.to_le_bytes()) {
        *byte ^= index_byte;
    }
    for (counter, chunk) in data.chunks_mut(64).enumerate() {
        let stream = salsa20_block(key, &nonce, counter as u64);
        for (byte, k) in chunk.iter_mut().zip(stream) {
            *byte ^= k;
        }
    }
}

// ---------------------------------------------------------------------------
// Public decrypt entry point
// ---------------------------------------------------------------------------

/// Decrypt a BLTE mode-E block.
///
/// `data` is everything after the `E` mode byte. Returns the decrypted
/// payload whose first byte is the inner compression mode (N, Z, 4, etc.).
/// `frame_index` is the block's index in its BLTE stream (0 for a single block): it is mixed
/// into the Salsa20 IV.
pub fn decrypt_block(data: &[u8], keystore: &TactKeyStore, frame_index: u32) -> Result<Vec<u8>> {
    let (header, encrypted) = parse_encryption_header(data)?;

    let key = keystore
        .get(header.key_name)
        .ok_or_else(|| CascError::EncryptionKeyMissing(format!("0x{:016X}", header.key_name)))?;

    let mut output = encrypted.to_vec();
    match header.algorithm {
        EncryptionAlgorithm::Salsa20 => {
            apply_salsa20(key, &header.iv, frame_index, &mut output);
        }
        EncryptionAlgorithm::ARC4 => {
            let mut cipher = Arc4::new(key);
            cipher.process(&mut output);
        }
    }

    Ok(output)
}

// ---------------------------------------------------------------------------
// Known TACT keys
// ---------------------------------------------------------------------------

/// Convert a hex string to a 16-byte key. Panics on invalid input.
fn hex_to_key(hex_str: &str) -> [u8; 16] {
    let bytes = hex::decode(hex_str).expect("invalid hex in known key");
    let mut key = [0u8; 16];
    key.copy_from_slice(&bytes);
    key
}

/// Convert a hex string to a 16-byte key, returning an error on failure.
fn hex_to_key_result(hex_str: &str) -> Result<[u8; 16]> {
    let bytes = hex::decode(hex_str).map_err(|e| {
        CascError::InvalidFormat(format!("invalid hex key value '{}': {}", hex_str, e))
    })?;
    if bytes.len() != 16 {
        return Err(CascError::InvalidFormat(format!(
            "key value must be 16 bytes, got {}",
            bytes.len()
        )));
    }
    let mut key = [0u8; 16];
    key.copy_from_slice(&bytes);
    Ok(key)
}

fn known_keys() -> Vec<(u64, [u8; 16])> {
    vec![
        (
            0xFA505078126ACB3E,
            hex_to_key("BDC51862ABED79B2DE48C8E7E66C6200"),
        ),
        (
            0xFF813F7D062AC0BC,
            hex_to_key("AA0B5C77F088CCC2D39049BD267F066D"),
        ),
        (
            0xD1E9B5EDF9283668,
            hex_to_key("8E4A2579894E38B4AB9058BA5C7328EE"),
        ),
        (
            0xB76729641141CB34,
            hex_to_key("9849D1AA7B1FD09819C5C66283A326EC"),
        ),
        (
            0xFFB9469FF16E6BF8,
            hex_to_key("D514BD1909A9E5DC8703F4B8BB1DFD9A"),
        ),
        (
            0x23C5B5DF837A226C,
            hex_to_key("1406E2D873B6FC99217A180881DA8D62"),
        ),
        (
            0x3AE403EF40AC3037,
            hex_to_key("EB31B554C67D603E2F10AA8C4584F1CE"),
        ),
        (
            0xE2854509C471C381,
            hex_to_key("A970FEF382CE86A53A1674C8F36C8F1B"),
        ),
        (
            0x8EE2CB82178C995A,
            hex_to_key("5FA43C8E204D2F1BFAF1FB26FFE5A34B"),
        ),
        (
            0x5813810F4EC9B005,
            hex_to_key("7F3DDA67B4A94DE6D3F3B8D4E45FC076"),
        ),
        (
            0x7F3DDA67B4A94DE6,
            hex_to_key("13AC5E1474618778916727B21F37B31E"),
        ),
        (
            0x402CD9D8D6BFED98,
            hex_to_key("AEB0EADFE24A0742C24B8FFC2DC28C69"),
        ),
        (
            0xFB680CB6A8BF81F3,
            hex_to_key("62D90EFA7F36D71C398AE2F1FE37C5F5"),
        ),
        (
            0xDBD3371554F60306,
            hex_to_key("34E397ACE6DD30EEFDC98A2AB093CD3C"),
        ),
        (
            0x11A9203C9A2D0DC8,
            hex_to_key("2E609EA137A31F85DE06A14A9FF04AA1"),
        ),
        (
            0x279C3FFB7E3229BC,
            hex_to_key("53D25B2053C58F053AA4A6EA4E2D1625"),
        ),
        (
            0xC7459A25DC3B7A4C,
            hex_to_key("C54CF38B19EA7ABCB17B1D5086423A90"),
        ),
    ]
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // TactKeyStore tests
    // -----------------------------------------------------------------------

    #[test]
    fn keystore_new_is_empty() {
        let ks = TactKeyStore::new();
        assert!(ks.is_empty());
        assert_eq!(ks.len(), 0);
    }

    #[test]
    fn keystore_with_known_keys_not_empty() {
        let ks = TactKeyStore::with_known_keys();
        assert!(!ks.is_empty());
        assert!(ks.len() >= 10);
    }

    #[test]
    fn keystore_get_known_key() {
        let ks = TactKeyStore::with_known_keys();
        let key = ks.get(0xFA505078126ACB3E);
        assert!(key.is_some());
        assert_eq!(key.unwrap().len(), 16);
    }

    #[test]
    fn keystore_get_unknown_returns_none() {
        let ks = TactKeyStore::with_known_keys();
        assert!(ks.get(0xDEADBEEFCAFEBABE).is_none());
    }

    #[test]
    fn keystore_merge() {
        let mut ks1 = TactKeyStore::new();
        let mut ks2 = TactKeyStore::new();
        ks2.keys.insert(0x1234, [0xAA; 16]);
        ks1.merge(&ks2);
        assert!(ks1.get(0x1234).is_some());
        assert_eq!(ks1.get(0x1234).unwrap(), &[0xAA; 16]);
    }

    #[test]
    fn keystore_load_keyfile() {
        use std::io::Write;

        let dir = std::env::temp_dir().join("casc_test_keyfile");
        std::fs::create_dir_all(&dir).ok();
        let path = dir.join("test.keys");
        let mut f = std::fs::File::create(&path).unwrap();
        writeln!(f, "# Comment line").unwrap();
        writeln!(f, "FA505078126ACB3E BDC51862ABED79B2DE48C8E7E66C6200").unwrap();
        writeln!(f).unwrap(); // blank line
        writeln!(f, "FF813F7D062AC0BC AA0B5C77F088CCC2D39049BD267F066D").unwrap();
        drop(f);

        let ks = TactKeyStore::load_keyfile(&path).unwrap();
        assert_eq!(ks.len(), 2);
        assert!(ks.get(0xFA505078126ACB3E).is_some());
        assert!(ks.get(0xFF813F7D062AC0BC).is_some());

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn keystore_load_keyfile_missing_file_errors() {
        let path = Path::new("nonexistent_keyfile.txt");
        assert!(TactKeyStore::load_keyfile(path).is_err());
    }

    #[test]
    fn keystore_load_keyfile_invalid_hex_errors() {
        use std::io::Write;

        let dir = std::env::temp_dir().join("casc_test_keyfile_bad");
        std::fs::create_dir_all(&dir).ok();
        let path = dir.join("bad.keys");
        let mut f = std::fs::File::create(&path).unwrap();
        writeln!(f, "ZZZZ INVALID_HEX_VALUE_HERE_TOO").unwrap();
        drop(f);

        assert!(TactKeyStore::load_keyfile(&path).is_err());
        std::fs::remove_dir_all(&dir).ok();
    }

    // -----------------------------------------------------------------------
    // Encryption header parsing tests
    // -----------------------------------------------------------------------

    /// Header bytes after the `E` mode byte of wowf `dbfilesclient/light.db2`, frame 2.
    const REAL_HEADER: [u8; 15] = [
        0x08, 0xa9, 0xb2, 0x6f, 0xb3, 0x0d, 0x67, 0xa4, 0x0d, 0x04, 0x90, 0xc9, 0x0e, 0x8a, 0x53,
    ];

    /// A header in the TACT layout: `key_name_size`, key name, `iv_size`, IV, type.
    fn header_bytes(key_name: u64, iv: &[u8], kind: u8) -> Vec<u8> {
        let mut data = vec![8u8];
        data.extend_from_slice(&key_name.to_le_bytes());
        data.push(iv.len() as u8);
        data.extend_from_slice(iv);
        data.push(kind);
        data
    }

    #[test]
    fn parse_encryption_header_real_sample() {
        let mut data = REAL_HEADER.to_vec();
        data.extend_from_slice(b"payload");
        let (header, remaining) = parse_encryption_header(&data).unwrap();
        assert_eq!(header.key_name, 0x0DA4_670D_B36F_B2A9);
        assert_eq!(header.iv, vec![0x90, 0xc9, 0x0e, 0x8a]);
        assert_eq!(header.algorithm, EncryptionAlgorithm::Salsa20);
        assert_eq!(remaining, b"payload");
    }

    #[test]
    fn parse_encryption_header_salsa20() {
        let mut data = header_bytes(0xFA505078126ACB3E, &[1, 2, 3, 4], b'S');
        data.extend_from_slice(b"encrypted_payload");
        let (header, remaining) = parse_encryption_header(&data).unwrap();
        assert_eq!(header.key_name, 0xFA505078126ACB3E);
        assert_eq!(header.iv, vec![0x01, 0x02, 0x03, 0x04]);
        assert_eq!(header.algorithm, EncryptionAlgorithm::Salsa20);
        assert_eq!(remaining, b"encrypted_payload");
    }

    #[test]
    fn parse_encryption_header_arc4() {
        let mut data = header_bytes(0xDEADBEEF, &[0x0A, 0x0B, 0x0C, 0x0D], b'A');
        data.extend_from_slice(b"payload");
        let (header, remaining) = parse_encryption_header(&data).unwrap();
        assert_eq!(header.algorithm, EncryptionAlgorithm::ARC4);
        assert_eq!(header.key_name, 0xDEADBEEF);
        assert_eq!(remaining, b"payload");
    }

    #[test]
    fn parse_encryption_header_empty_errors() {
        assert!(parse_encryption_header(&[]).is_err());
    }

    #[test]
    fn parse_encryption_header_truncated_errors() {
        for len in 0..REAL_HEADER.len() {
            assert!(
                parse_encryption_header(&REAL_HEADER[..len]).is_err(),
                "{len} bytes"
            );
        }
    }

    #[test]
    fn parse_encryption_header_unknown_algo_errors() {
        assert!(parse_encryption_header(&header_bytes(0, &[0; 4], b'X')).is_err());
    }

    #[test]
    fn parse_encryption_header_wrong_key_name_size_errors() {
        let mut data = header_bytes(0, &[0; 4], b'S');
        data[0] = 4;
        assert!(parse_encryption_header(&data).is_err());
    }

    // -----------------------------------------------------------------------
    // ARC4 tests
    // -----------------------------------------------------------------------

    #[test]
    fn arc4_round_trip() {
        let key = b"test_key_16bytes"; // 16 bytes
        let plaintext = b"Hello World! This is a test of ARC4 encryption.";

        let mut encrypted = plaintext.to_vec();
        let mut cipher1 = Arc4::new(key);
        cipher1.process(&mut encrypted);

        // encrypted should differ from plaintext
        assert_ne!(&encrypted[..], &plaintext[..]);

        // Decrypt with fresh cipher
        let mut decrypted = encrypted.clone();
        let mut cipher2 = Arc4::new(key);
        cipher2.process(&mut decrypted);

        assert_eq!(&decrypted[..], &plaintext[..]);
    }

    #[test]
    fn arc4_empty_data() {
        let key = b"some_key_16bytes";
        let mut data = Vec::new();
        let mut cipher = Arc4::new(key);
        cipher.process(&mut data);
        assert!(data.is_empty());
    }

    // -----------------------------------------------------------------------
    // Salsa20 tests
    // -----------------------------------------------------------------------

    #[test]
    fn salsa20_128_bit_key_matches_ecrypt_vector() {
        // ECRYPT Salsa20/20 128-bit key, set 1 vector 0: key 80 00.., IV 0, first 64 bytes.
        let mut key = [0u8; 16];
        key[0] = 0x80;
        let expected = hex::decode(
            "4DFA5E481DA23EA09A31022050859936DA52FCEE218005164F267CB65F5CFD7F\
             2B4F97E0FF16924A52DF269515110A07F9E460BC65EF95DA58F740B7D1DBB0AA",
        )
        .unwrap();
        let mut data = [0u8; 64];
        apply_salsa20(&key, &[0; 8], 0, &mut data);
        assert_eq!(&data[..], &expected[..]);
    }

    #[test]
    fn salsa20_round_trip_across_blocks() {
        let key = [0x42u8; 16];
        let iv = [0x01, 0x02, 0x03, 0x04];
        let plaintext: Vec<u8> = (0..200u32).map(|i| i as u8).collect();

        let mut data = plaintext.clone();
        apply_salsa20(&key, &iv, 0, &mut data);
        assert_ne!(data, plaintext);
        apply_salsa20(&key, &iv, 0, &mut data);
        assert_eq!(data, plaintext);
    }

    #[test]
    fn salsa20_frame_index_changes_the_stream() {
        let key = [0x42u8; 16];
        let iv = [0x01, 0x02, 0x03, 0x04];
        let mut a = [0u8; 16];
        let mut b = [0u8; 16];
        apply_salsa20(&key, &iv, 0, &mut a);
        apply_salsa20(&key, &iv, 1, &mut b);
        assert_ne!(a, b);

        // Index 1 XORs the first IV byte with 1: the same as IV [0x00, 0x02, 0x03, 0x04] at 0.
        let mut c = [0u8; 16];
        apply_salsa20(&key, &[0x00, 0x02, 0x03, 0x04], 0, &mut c);
        assert_eq!(b, c);
    }

    // -----------------------------------------------------------------------
    // Full decrypt_block tests
    // -----------------------------------------------------------------------

    #[test]
    fn decrypt_block_missing_key_errors() {
        let ks = TactKeyStore::new(); // empty - no keys
        let mut data = header_bytes(0xDEADBEEF, &[0; 4], b'S');
        data.extend_from_slice(b"encrypted");

        let result = decrypt_block(&data, &ks, 0);
        assert!(result.is_err());
        match result.unwrap_err() {
            CascError::EncryptionKeyMissing(_) => {}
            e => panic!("Expected EncryptionKeyMissing, got: {:?}", e),
        }
    }

    #[test]
    fn decrypt_block_salsa20_round_trip() {
        let key_name: u64 = 0xFA505078126ACB3E;
        let ks = TactKeyStore::with_known_keys();
        let key = ks.get(key_name).unwrap();

        // Prepare a "plaintext" that starts with an inner mode byte
        let plaintext = b"Nhello world inner content";
        let iv_bytes = [0x10, 0x20, 0x30, 0x40];

        for frame_index in [0u32, 3] {
            let mut encrypted_payload = plaintext.to_vec();
            apply_salsa20(key, &iv_bytes, frame_index, &mut encrypted_payload);

            let mut block_data = header_bytes(key_name, &iv_bytes, b'S');
            block_data.extend_from_slice(&encrypted_payload);

            let decrypted = decrypt_block(&block_data, &ks, frame_index).unwrap();
            assert_eq!(&decrypted[..], &plaintext[..]);
        }
    }

    #[test]
    fn decrypt_block_arc4_round_trip() {
        let key_name: u64 = 0xFA505078126ACB3E;
        let ks = TactKeyStore::with_known_keys();
        let key = ks.get(key_name).unwrap();

        let plaintext = b"Zcompressed inner data here";

        let mut encrypted_payload = plaintext.to_vec();
        let mut cipher = Arc4::new(key);
        cipher.process(&mut encrypted_payload);

        let mut block_data = header_bytes(key_name, &[1, 2, 3, 4], b'A');
        block_data.extend_from_slice(&encrypted_payload);

        let decrypted = decrypt_block(&block_data, &ks, 0).unwrap();
        assert_eq!(&decrypted[..], &plaintext[..]);
    }

    #[test]
    fn hex_to_key_result_valid() {
        let key = hex_to_key_result("BDC51862ABED79B2DE48C8E7E66C6200").unwrap();
        assert_eq!(key.len(), 16);
        assert_eq!(key[0], 0xBD);
        assert_eq!(key[15], 0x00);
    }

    #[test]
    fn hex_to_key_result_invalid_hex_errors() {
        assert!(hex_to_key_result("ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ").is_err());
    }

    #[test]
    fn hex_to_key_result_wrong_length_errors() {
        assert!(hex_to_key_result("AABB").is_err());
    }

    #[test]
    fn known_keys_all_valid() {
        let keys = known_keys();
        assert!(keys.len() >= 15);
        for (name, value) in &keys {
            assert_ne!(*name, 0, "key name should not be zero");
            assert_ne!(*value, [0u8; 16], "key value should not be all zeros");
        }
    }
}
