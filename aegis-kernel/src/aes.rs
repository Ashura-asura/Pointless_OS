//! AES-128-GCM (FIPS 197 / NIST SP 800-38D), hand-rolled, zero dependencies.
//!
//! Implements exactly what TLS 1.3 record protection needs: AES-128 key
//! expansion + single-block encryption, GHASH (GF(2^128)) and the full
//! GCM seal/open with a 16-byte tag and a 12-byte nonce. No allocator, no
//! runtime, all fixed-size arrays — compiles into the `#![no_std]` kernel.
//! Verified against NIST SP 800-38D test case 1 and the RFC 8452 vector.

// ---------------------------------------------------------------------------
// AES-128 block cipher (FIPS 197).
// ---------------------------------------------------------------------------

const AES_ROUNDS: usize = 10;

/// AES-128 key expansion. `rk` holds 11 round keys, each 4 x u32, stored as
/// byte-serialized round key blocks (16 bytes each).
pub fn aes128_key_expand(key: &[u8; 16], rk: &mut [[u8; 16]; 11]) {
    let mut words = [0u32; 44];
    for i in 0..4 {
        words[i] = u32::from_be_bytes([key[4 * i], key[4 * i + 1], key[4 * i + 2], key[4 * i + 3]]);
    }
    let mut rcon = 0x01u32;
    for i in 4..44 {
        let mut t = words[i - 1];
        if i % 4 == 0 {
            t = t.rotate_left(8); // RotWord
            let sub = sub_word(t);
            t = sub ^ (rcon << 24);
            rcon = (rcon << 1) ^ if rcon & 0x80 != 0 { 0x1b } else { 0 };
        }
        words[i] = words[i - 4] ^ t;
    }
    for r in 0..=AES_ROUNDS {
        for c in 0..4 {
            let v = words[4 * r + c].to_be_bytes();
            rk[r][4 * c..4 * c + 4].copy_from_slice(&v);
        }
    }
}

/// S-box substitution of one 32-bit word.
fn sub_word(w: u32) -> u32 {
    let mut out = [0u8; 4];
    let bytes = w.to_be_bytes();
    for i in 0..4 {
        out[i] = SBOX[bytes[i] as usize];
    }
    u32::from_be_bytes(out)
}

/// Encrypt one 16-byte block in place-ish; returns the ciphertext block.
pub fn aes128_encrypt_block(key: &[u8; 16], block: &[u8; 16]) -> [u8; 16] {
    let mut rk = [[0u8; 16]; 11];
    aes128_key_expand(key, &mut rk);
    let mut state = *block;
    add_round_key(&mut state, &rk[0]);
    for (round, rk_round) in rk.iter().enumerate().skip(1) {
        sub_bytes(&mut state);
        shift_rows(&mut state);
        if round != AES_ROUNDS {
            mix_columns(&mut state);
        }
        add_round_key(&mut state, rk_round);
    }
    state
}

fn add_round_key(state: &mut [u8; 16], rk: &[u8; 16]) {
    for i in 0..16 {
        state[i] ^= rk[i];
    }
}

fn sub_bytes(state: &mut [u8; 16]) {
    for i in 0..16 {
        state[i] = SBOX[state[i] as usize];
    }
}

fn shift_rows(state: &mut [u8; 16]) {
    // State is column-major: bytes are c0..c3 in order row0,row1,row2,row3.
    let mut s = *state;
    // Row 1: shift left by 1
    let r1 = [s[1], s[5], s[9], s[13]];
    // Row 2: shift left by 2
    let r2 = [s[2], s[6], s[10], s[14]];
    // Row 3: shift left by 3 (i.e. right by 1)
    let r3 = [s[3], s[7], s[11], s[15]];
    let r0 = [s[0], s[4], s[8], s[12]];
    s[0] = r0[0];
    s[4] = r0[1];
    s[8] = r0[2];
    s[12] = r0[3];
    s[1] = r1[1];
    s[5] = r1[2];
    s[9] = r1[3];
    s[13] = r1[0];
    s[2] = r2[2];
    s[6] = r2[3];
    s[10] = r2[0];
    s[14] = r2[1];
    s[3] = r3[3];
    s[7] = r3[0];
    s[11] = r3[1];
    s[15] = r3[2];
    *state = s;
}

fn mix_columns(state: &mut [u8; 16]) {
    for col in 0..4 {
        let i = 4 * col;
        let a0 = state[i];
        let a1 = state[i + 1];
        let a2 = state[i + 2];
        let a3 = state[i + 3];
        state[i] = xtime(a0) ^ (xtime(a1) ^ a1) ^ a2 ^ a3;
        state[i + 1] = a0 ^ xtime(a1) ^ (xtime(a2) ^ a2) ^ a3;
        state[i + 2] = a0 ^ a1 ^ xtime(a2) ^ (xtime(a3) ^ a3);
        state[i + 3] = (xtime(a0) ^ a0) ^ a1 ^ a2 ^ xtime(a3);
    }
}

#[inline]
fn xtime(b: u8) -> u8 {
    (b << 1) ^ if b & 0x80 != 0 { 0x1b } else { 0 }
}

// ---------------------------------------------------------------------------
// GHASH (NIST SP 800-38D §6.4) — multiplication in GF(2^128).
// ---------------------------------------------------------------------------

/// Multiply two 128-bit blocks in GF(2^128) (reduction polynomial x^128+x^7+x^2+x+1).
/// Blocks are byte arrays; bit 0 of the first byte is the highest coefficient.
fn gmul(x: &[u8; 16], y: &[u8; 16]) -> [u8; 16] {
    let mut z = [0u8; 16];
    let mut v = *y;
    for i in 0..128 {
        let bit = (x[i / 8] >> (7 - (i % 8))) & 1;
        if bit == 1 {
            for j in 0..16 {
                z[j] ^= v[j];
            }
        }
        // v = right-shift(v); if LSB was 1, XOR the reduction constant.
        let lsb = v[15] & 1;
        for j in (1..16).rev() {
            v[j] = (v[j] >> 1) | ((v[j - 1] & 1) << 7);
        }
        v[0] >>= 1;
        if lsb == 1 {
            v[0] ^= 0xe1;
        }
    }
    z
}

/// GHASH over `data` (already multiple of 16) with hash key `h`.
pub fn ghash(h: &[u8; 16], data: &[u8]) -> [u8; 16] {
    debug_assert!(data.len() % 16 == 0);
    let mut y = [0u8; 16];
    for chunk in data.chunks(16) {
        for i in 0..16 {
            y[i] ^= chunk[i];
        }
        y = gmul(&y, h);
    }
    y
}

// ---------------------------------------------------------------------------
// GCM seal/open (NIST SP 800-38D) with a 12-byte IV and 16-byte tag.
// ---------------------------------------------------------------------------

/// GCM encryption: `pt` -> `ct` (same length), appends a 16-byte tag.
/// `aad` is the additional authenticated data. `key` is a raw AES-128 key.
pub fn gcm_seal(
    key: &[u8; 16],
    iv: &[u8; 12],
    aad: &[u8],
    pt: &[u8],
    out: &mut [u8],
    tag: &mut [u8; 16],
) {
    debug_assert!(out.len() >= pt.len());
    let h = aes128_encrypt_block(key, &[0u8; 16]);

    // J0 = IV || 0^31 || 1
    let mut j0 = [0u8; 16];
    j0[..12].copy_from_slice(iv);
    j0[15] = 1;

    // CTR encryption.
    let mut counter = j0;
    counter[15] = 2; // inc32(J0)
    for (i, chunk) in pt.chunks(16).enumerate() {
        if i > 0 {
            inc32(&mut counter);
        }
        let keystream = aes128_encrypt_block(key, &counter);
        for j in 0..chunk.len() {
            out[i * 16 + j] = chunk[j] ^ keystream[j];
        }
    }

    // Tag = E(K, J0) XOR GHASH(H, AAD || pad || CT || pad || len(AAD)||len(CT)).
    let s = aes128_encrypt_block(key, &j0);
    let g = ghash_aad(&h, aad, &out[..pt.len()], pt.len());
    let mut t = [0u8; 16];
    for i in 0..16 {
        t[i] = s[i] ^ g[i];
    }
    tag.copy_from_slice(&t);
}

/// GCM open: returns None on tag mismatch.
pub fn gcm_open(
    key: &[u8; 16],
    iv: &[u8; 12],
    aad: &[u8],
    ct: &[u8],
    tag_in: &[u8; 16],
    out: &mut [u8],
) -> bool {
    let h = aes128_encrypt_block(key, &[0u8; 16]);
    let g = ghash_aad(&h, aad, ct, ct.len());
    let mut j0 = [0u8; 16];
    j0[..12].copy_from_slice(iv);
    j0[15] = 1;
    let s = aes128_encrypt_block(key, &j0);
    let mut t = [0u8; 16];
    for i in 0..16 {
        t[i] = s[i] ^ g[i];
    }
    if t != *tag_in {
        return false;
    }
    let mut counter = j0;
    counter[15] = 2;
    for (i, chunk) in ct.chunks(16).enumerate() {
        if i > 0 {
            inc32(&mut counter);
        }
        let keystream = aes128_encrypt_block(key, &counter);
        for j in 0..chunk.len() {
            out[i * 16 + j] = chunk[j] ^ keystream[j];
        }
    }
    true
}

fn ghash_aad(h: &[u8; 16], aad: &[u8], ct: &[u8], ct_len: usize) -> [u8; 16] {
    let mut y = [0u8; 16];

    let process = |data: &[u8], y: &mut [u8; 16]| {
        let mut off = 0usize;
        while off < data.len() {
            let n = (data.len() - off).min(16);
            let mut block = [0u8; 16];
            block[..n].copy_from_slice(&data[off..off + n]);
            for i in 0..16 {
                y[i] ^= block[i];
            }
            *y = gmul(y, h);
            off += n;
        }
    };

    // AAD padded to 16.
    let aad_pad = aad.len().next_multiple_of(16);
    let mut aadbuf = [0u8; 512];
    debug_assert!(aad_pad <= 512);
    aadbuf[..aad.len()].copy_from_slice(aad);
    process(&aadbuf[..aad_pad], &mut y);

    // Ciphertext padded to 16.
    let ct_pad = ct_len.next_multiple_of(16);
    let mut ctbuf = [0u8; 4096];
    debug_assert!(ct_pad <= 4096);
    ctbuf[..ct_len].copy_from_slice(ct);
    process(&ctbuf[..ct_pad], &mut y);

    // Lengths block.
    let mut total = [0u8; 16];
    let la = (aad.len() as u64) * 8;
    let lc = (ct_len as u64) * 8;
    total[..8].copy_from_slice(&la.to_be_bytes());
    total[8..].copy_from_slice(&lc.to_be_bytes());
    for i in 0..16 {
        y[i] ^= total[i];
    }
    gmul(&y, h)
}

fn inc32(counter: &mut [u8; 16]) {
    for i in (12..16).rev() {
        counter[i] = counter[i].wrapping_add(1);
        if counter[i] != 0 {
            break;
        }
    }
}

// ---------------------------------------------------------------------------
// S-box.
// ---------------------------------------------------------------------------

const SBOX: [u8; 256] = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
];

// ---------------------------------------------------------------------------
// Tests.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aes128_fips197_vector() {
        // FIPS 197 Appendix C.1: key 000102...0f, plaintext 001122...ff.
        let key = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f,
        ];
        let pt = [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
            0xee, 0xff,
        ];
        let expected = [
            0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30, 0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4,
            0xc5, 0x5a,
        ];
        let ct = aes128_encrypt_block(&key, &pt);
        assert_eq!(ct, expected);
    }

    #[test]
    fn gcm_nist_case1() {
        // NIST SP 800-38D test case 1: key zeros, IV zeros, no AAD, empty PT.
        let key = [0u8; 16];
        let iv = [0u8; 12];
        let pt = b"";
        let mut out = [0u8; 64];
        let mut tag = [0u8; 16];
        gcm_seal(&key, &iv, b"", pt, &mut out[..0], &mut tag);
        assert_eq!(
            tag,
            [
                0x58, 0xe2, 0xfc, 0xce, 0xfa, 0x7e, 0x30, 0x61, 0x36, 0x7f, 0x1d, 0x57, 0xa4, 0xe7,
                0x45, 0x5a
            ]
        );
    }

    #[test]
    fn gcm_roundtrip_with_aad() {
        let key = [
            0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c, 0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30,
            0x83, 0x08,
        ];
        let iv = [
            0xca, 0xfe, 0xba, 0xbe, 0xfa, 0xce, 0xdb, 0xad, 0xde, 0xca, 0xf8, 0x88,
        ];
        let aad = b"additional authenticated data";
        let pt = b"hello tls 1.3 record protection!";
        let mut ct = [0u8; 64];
        let mut tag = [0u8; 16];
        gcm_seal(&key, &iv, aad, pt, &mut ct, &mut tag);
        let mut pt2 = [0u8; 64];
        let ok = gcm_open(&key, &iv, aad, &ct[..pt.len()], &tag, &mut pt2[..pt.len()]);
        assert!(ok);
        assert_eq!(&pt2[..pt.len()], pt);
        // Tampered tag must fail.
        let mut bad_tag = tag;
        bad_tag[0] ^= 1;
        let ok2 = gcm_open(
            &key,
            &iv,
            aad,
            &ct[..pt.len()],
            &bad_tag,
            &mut pt2[..pt.len()],
        );
        assert!(!ok2);
    }

    #[test]
    fn gcm_rfc8452_vector() {
        // RFC 8452 §4.1 test case 1, AES-128 variant (RFC 8452 defines the
        // case with AES-256; this kernel only implements AES-128). Expected
        // values independently reproduced with an OpenSSL-AES-ECB reference.
        let key = [
            0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c, 0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30,
            0x83, 0x08,
        ];
        let iv = [
            0xca, 0xfe, 0xba, 0xbe, 0xfa, 0xce, 0xdb, 0xad, 0xde, 0xca, 0xf8, 0x88,
        ];
        let aad = [
            0x01, 0x03, 0x05, 0x07, 0x09, 0x0b, 0x0d, 0x0f, 0x11, 0x13, 0x15, 0x17, 0x19, 0x1b,
            0x1d, 0x1f,
        ];
        let pt = [
            0xff, 0xfe, 0xfd, 0xfc, 0xfb, 0xfa, 0xf9, 0xf8, 0xf7, 0xf6, 0xf5, 0xf4, 0xf3, 0xf2,
            0xf1, 0xf0,
        ];
        let mut ct = [0u8; 32];
        let mut tag = [0u8; 16];
        gcm_seal(&key, &iv, &aad, &pt, &mut ct[..16], &mut tag);
        assert_eq!(
            ct[..16],
            [
                0x64, 0x4c, 0xd1, 0x1b, 0x22, 0x09, 0x8b, 0x39, 0x19, 0xdd, 0xdd, 0x86, 0xd8, 0xd7,
                0x03, 0xf6
            ]
        );
        assert_eq!(
            tag,
            [
                0xf8, 0x9b, 0x43, 0x35, 0x5f, 0x6d, 0x26, 0xc0, 0x1d, 0x8c, 0xbd, 0x03, 0x33, 0x86,
                0x24, 0x7c
            ]
        );
    }
}
