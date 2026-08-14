//! TLS 1.3 client (RFC 8446) — hand-rolled, zero dependencies, no allocator.
//!
//! This milestone: record layer, ClientHello, ServerHello parsing, X25519
//! (RFC 7748) and HKDF-SHA256 (RFC 5869 / RFC 8446 §7.1), all Vec-free so the
//! whole module compiles into the `#![no_std]` kernel. Later milestones add
//! the TLS 1.3 key schedule, AES-128-GCM record protection, Certificate /
//! CertificateVerify parsing + RSA verification, and the Finished handshake.
//!
//! Honest limits: the kernel has no CSPRNG, so the ephemeral X25519 scalar and
//! the ClientHello random are fixed constants (documented below). Every
//! primitive is verified against published test vectors.

use crate::store::sha256;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

// TLS record content types (RFC 8446 §5).
pub const CT_CHANGE_CIPHER_SPEC: u8 = 20;
pub const CT_ALERT: u8 = 21;
pub const CT_HANDSHAKE: u8 = 22;
pub const CT_APPLICATION_DATA: u8 = 23;

// TLS versions.
pub const TLS13_VERSION: u16 = 0x0304;
pub const TLS12_VERSION: u16 = 0x0303;

// TLS 1.3 cipher suite (RFC 8446 §B.4).
pub const CIPHER_AES_128_GCM_SHA256: u16 = 0x1301;

// TLS 1.3 named groups (RFC 8446 §B.3.1).
pub const GROUP_X25519: u16 = 0x001d;

// TLS 1.3 signature schemes (RFC 8446 §B.3.1.3).
pub const SIG_RSA_PKCS1_SHA256: u16 = 0x0401;
pub const SIG_RSA_PSS_RSAE_SHA256: u16 = 0x0804;

// Handshake message types (RFC 8446 §4).
pub const HS_CLIENT_HELLO: u8 = 1;
pub const HS_SERVER_HELLO: u8 = 2;
pub const HS_NEW_SESSION_TICKET: u8 = 4;
pub const HS_ENCRYPTED_EXTENSIONS: u8 = 8;
pub const HS_CERTIFICATE: u8 = 11;
pub const HS_CERTIFICATE_VERIFY: u8 = 15;
pub const HS_FINISHED: u8 = 20;

// Extension types (RFC 8446 §4.2).
pub const EXT_SERVER_NAME: u16 = 0x0000;
pub const EXT_SUPPORTED_GROUPS: u16 = 0x000a;
pub const EXT_SIGNATURE_ALGORITHMS: u16 = 0x000d;
pub const EXT_KEY_SHARE: u16 = 0x0033;
pub const EXT_SUPPORTED_VERSIONS: u16 = 0x002b;

// The kernel's fixed, documented ephemeral scalar (no CSPRNG). Its public half
// goes on the wire in the ClientHello key_share.
pub const EPHEMERAL_SCALAR: [u8; 32] = [
    0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00,
    0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00,
];

/// Deterministic ClientHello random (RFC 8446 §4.1.2 requires 32 random
/// bytes; the kernel cannot supply real entropy, so these are fixed).
pub const CLIENT_HELLO_RANDOM: [u8; 32] = [
    0xa6, 0x07, 0x6f, 0x3e, 0x1b, 0x2c, 0x4d, 0x5e, 0x6f, 0x70, 0x81, 0x92, 0xa3, 0xb4, 0xc5, 0xd6,
    0xe7, 0xf8, 0x09, 0x1a, 0x2b, 0x3c, 0x4d, 0x5e, 0x6f, 0x70, 0x81, 0x92, 0xa3, 0xb4, 0xc5, 0xd6,
];

// ---------------------------------------------------------------------------
// X25519 (RFC 7748) — 5 x 51-bit limbs, constant-time ladder.
// ---------------------------------------------------------------------------

const M51: u128 = (1u128 << 51) - 1;
const M51U: u64 = (1u64 << 51) - 1;

// 2^255 - 19 in 51-bit limbs (little-limb order).
const P: [u64; 5] = [
    0x7ffffffffffed,
    0x7ffffffffffff,
    0x7ffffffffffff,
    0x7ffffffffffff,
    0x7ffffffffffff,
];

#[inline]
fn fadd(a: &[u64; 5], b: &[u64; 5]) -> [u64; 5] {
    [
        a[0].wrapping_add(b[0]),
        a[1].wrapping_add(b[1]),
        a[2].wrapping_add(b[2]),
        a[3].wrapping_add(b[3]),
        a[4].wrapping_add(b[4]),
    ]
}

#[inline]
fn fsub(a: &[u64; 5], b: &[u64; 5]) -> [u64; 5] {
    let p2 = [
        0xfffffffffffdau64,
        0xffffffffffffeu64,
        0xffffffffffffeu64,
        0xffffffffffffeu64,
        0xffffffffffffeu64,
    ];
    [
        a[0].wrapping_add(p2[0]).wrapping_sub(b[0]),
        a[1].wrapping_add(p2[1]).wrapping_sub(b[1]),
        a[2].wrapping_add(p2[2]).wrapping_sub(b[2]),
        a[3].wrapping_add(p2[3]).wrapping_sub(b[3]),
        a[4].wrapping_add(p2[4]).wrapping_sub(b[4]),
    ]
}

fn fmul(a: &[u64; 5], b: &[u64; 5]) -> [u64; 5] {
    let a0 = a[0] as u128;
    let a1 = a[1] as u128;
    let a2 = a[2] as u128;
    let a3 = a[3] as u128;
    let a4 = a[4] as u128;
    let b0 = b[0] as u128;
    let b1 = b[1] as u128;
    let b2 = b[2] as u128;
    let b3 = b[3] as u128;
    let b4 = b[4] as u128;

    let mut r: [u128; 9] = [
        a0 * b0,
        a0 * b1 + a1 * b0,
        a0 * b2 + a1 * b1 + a2 * b0,
        a0 * b3 + a1 * b2 + a2 * b1 + a3 * b0,
        a0 * b4 + a1 * b3 + a2 * b2 + a3 * b1 + a4 * b0,
        a1 * b4 + a2 * b3 + a3 * b2 + a4 * b1,
        a2 * b4 + a3 * b3 + a4 * b2,
        a3 * b4 + a4 * b3,
        a4 * b4,
    ];

    // Propagate 51-bit carries.
    for i in 0..8 {
        let c = r[i] >> 51;
        r[i] &= M51;
        r[i + 1] += c;
    }
    // Fold the high limbs into the low ones with the 19 multiplier
    // (2^255 ≡ 19): 2^(51*(5+k)) ≡ 19 * 2^(51k).
    r[0] += r[5] * 19;
    r[1] += r[6] * 19;
    r[2] += r[7] * 19;
    r[3] += r[8] * 19;
    // Clear the folded limbs (never fold them again).
    r[5] = 0;
    r[6] = 0;
    r[7] = 0;
    r[8] = 0;
    // Propagate carries; fold any overflow out of limb 4 back with 19,
    // repeating until the result is stable.
    loop {
        for i in 0..4 {
            let c = r[i] >> 51;
            r[i] &= M51;
            r[i + 1] += c;
        }
        let c = r[4] >> 51;
        if c == 0 {
            break;
        }
        r[4] &= M51;
        r[0] += c * 19;
    }

    [
        r[0] as u64,
        r[1] as u64,
        r[2] as u64,
        r[3] as u64,
        r[4] as u64,
    ]
}

fn fsquare(a: &[u64; 5]) -> [u64; 5] {
    fmul(a, a)
}

/// Full reduction to canonical (< p) form with one conditional subtraction.
fn freduce(x: &mut [u64; 5]) {
    for i in 0..4 {
        let c = x[i] >> 51;
        x[i] &= M51U;
        x[i + 1] = x[i + 1].wrapping_add(c);
    }
    let hi = x[4] >> 51;
    x[4] &= M51U;
    if hi > 0 {
        x[0] = x[0].wrapping_add(hi.wrapping_mul(19));
        for i in 0..4 {
            let c = x[i] >> 51;
            x[i] &= M51U;
            x[i + 1] = x[i + 1].wrapping_add(c);
        }
        x[4] &= M51U;
    }
    // Now x < 2*p. Subtract p once if needed (compare limbs high to low).
    let mut ge = true;
    for i in (0..5).rev() {
        if x[i] > P[i] {
            break;
        }
        if x[i] < P[i] {
            ge = false;
            break;
        }
    }
    if ge {
        let mut borrow = 0u64;
        for i in 0..5 {
            let (d, b1) = x[i].overflowing_sub(P[i]);
            let (d, b2) = d.overflowing_sub(borrow);
            x[i] = d;
            borrow = (b1 || b2) as u64;
        }
    }
}

fn decode_u(u: &[u8; 32]) -> [u64; 5] {
    // 51-bit limbs are not byte-aligned; extract bit-by-bit (little-endian).
    let mut x = [0u64; 5];
    for (i, limb) in x.iter_mut().enumerate() {
        let bit_off = 51 * i;
        for b in 0..51 {
            let src_bit = bit_off + b;
            let byte = src_bit / 8;
            let bit = src_bit % 8;
            if byte < 32 && (u[byte] >> bit) & 1 == 1 {
                *limb |= 1u64 << b;
            }
        }
    }
    x[4] &= M51U;
    x
}

fn encode(x: &[u64; 5]) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (i, limb) in x.iter().enumerate() {
        let bit_off = 51 * i;
        for b in 0..51 {
            let dst_bit = bit_off + b;
            let byte = dst_bit / 8;
            if byte < 32 && (limb >> b) & 1 == 1 {
                out[byte] |= 1u8 << (dst_bit % 8);
            }
        }
    }
    out
}

fn cswap(sel: u64, a: &mut [u64; 5], b: &mut [u64; 5]) {
    let mask = 0u64.wrapping_sub(sel);
    for i in 0..5 {
        let t = mask & (a[i] ^ b[i]);
        a[i] ^= t;
        b[i] ^= t;
    }
}

/// X25519 shared secret (RFC 7748 §5): `scalar * u`, with all-zero-output
/// rejection (low-order point defence).
pub fn x25519(scalar: &[u8; 32], u_point: &[u8; 32]) -> Option<[u8; 32]> {
    let mut k = *scalar;
    k[0] &= 248;
    k[31] &= 127;
    k[31] |= 64;

    let x1 = decode_u(u_point);
    let mut x2 = [1u64, 0, 0, 0, 0];
    let mut z2 = [0u64, 0, 0, 0, 0];
    let mut x3 = x1;
    let mut z3 = [1u64, 0, 0, 0, 0];
    let mut swap = 0u64;

    for t in (0..255).rev() {
        let kt = ((k[t >> 3] >> (t & 7)) & 1) as u64;
        swap ^= kt;
        cswap(swap, &mut x2, &mut x3);
        cswap(swap, &mut z2, &mut z3);
        swap = kt;

        let a = fadd(&x2, &z2);
        let aa = fsquare(&a);
        let b = fsub(&x2, &z2);
        let bb = fsquare(&b);
        let e = fsub(&aa, &bb);
        let c = fadd(&x3, &z3);
        let d = fsub(&x3, &z3);
        let da = fmul(&d, &a);
        let cb = fmul(&c, &b);
        let s0 = fadd(&da, &cb);
        let s0 = fsquare(&s0);
        let s1 = fsub(&da, &cb);
        let s1 = fsquare(&s1);
        x3 = s0;
        z3 = fmul(&x1, &s1);
        x2 = fmul(&aa, &bb);
        let a24 = [121665u64, 0, 0, 0, 0];
        z2 = fmul(&e, &fadd(&aa, &fmul(&e, &a24)));
    }
    cswap(swap, &mut x2, &mut x3);
    cswap(swap, &mut z2, &mut z3);

    // result = x2 * z2^(p-2).
    freduce(&mut x2);
    freduce(&mut z2);
    let zinv = fpow_p_minus_2(&z2);
    let out = fmul(&x2, &zinv);
    let out = encode(&out);

    if out.iter().all(|&b| b == 0) {
        return None;
    }
    Some(out)
}

/// z^(p-2) — inversion via square-and-multiply over the fixed bit pattern of
/// 2^255 - 21 (= p - 2). In binary the exponent is all 1s except bits 2 and 4
/// (low byte 0b11101011 = 235): bits 0,1,3,5..254 set, bits 2,4 clear.
fn fpow_p_minus_2(z: &[u64; 5]) -> [u64; 5] {
    let mut out = [1u64, 0, 0, 0, 0];
    for bit in (0..255).rev() {
        out = fsquare(&out);
        if bit != 2 && bit != 4 {
            out = fmul(&out, z);
        }
    }
    out
}

/// Public key from a scalar (RFC 7748 §6.1): base u = 9.
pub fn x25519_base(scalar: &[u8; 32]) -> [u8; 32] {
    let mut base = [0u8; 32];
    base[0] = 9;
    x25519(scalar, &base).unwrap_or([0u8; 32])
}

// ---------------------------------------------------------------------------
// HKDF-SHA256 (RFC 5869) + TLS 1.3 label expansion (RFC 8446 §7.1).
// ---------------------------------------------------------------------------

/// HMAC-SHA256 with a pre-padded (64-byte) key.
fn hmac_sha256(key: &[u8; 64], msg: &[u8]) -> [u8; 32] {
    let mut ipad = [0x36u8; 64];
    let mut opad = [0x5cu8; 64];
    for i in 0..64 {
        ipad[i] ^= key[i];
        opad[i] ^= key[i];
    }
    let mut inner = [0u8; 64 + 4096];
    inner[..64].copy_from_slice(&ipad);
    inner[64..64 + msg.len()].copy_from_slice(msg);
    let ih = sha256(&inner[..64 + msg.len()]);
    let mut outer = [0u8; 96];
    outer[..64].copy_from_slice(&opad);
    outer[64..96].copy_from_slice(&ih);
    sha256(&outer[..96])
}

/// HKDF-Extract (RFC 5869 §2.2). A salt shorter than 64 bytes is zero-padded.
pub fn hkdf_extract(salt: &[u8], ikm: &[u8]) -> [u8; 32] {
    let mut key = [0u8; 64];
    let salt_len = salt.len().min(64);
    key[..salt_len].copy_from_slice(&salt[..salt_len]);
    hmac_sha256(&key, ikm)
}

/// HKDF-Expand (RFC 5869 §2.3), at most 48 output bytes (TLS 1.3 needs 12/16/32;
/// 48 covers a possible two-block output).
pub fn hkdf_expand(prk: &[u8; 32], info: &[u8], len: usize) -> [u8; 48] {
    debug_assert!(len <= 48);
    let mut out = [0u8; 48];
    let mut t = [0u8; 32];
    let mut cur = [0u8; 66];
    for i in 1..=len.div_ceil(32) {
        let mut n = 0usize;
        if i > 1 {
            cur[..32].copy_from_slice(&t);
            n = 32;
        }
        cur[n..n + info.len()].copy_from_slice(info);
        cur[n + info.len()] = i as u8;
        let mut key = [0u8; 64];
        key[..32].copy_from_slice(prk);
        t = hmac_sha256(&key, &cur[..n + info.len() + 1]);
        let start = (i - 1) * 32;
        let take = (len - start).min(32);
        out[start..start + take].copy_from_slice(&t[..take]);
    }
    out
}

/// TLS 1.3 Hkdf-Expand-Label (RFC 8446 §7.1) — the `Derive-Secret` machinery.
pub fn hkdf_expand_label(secret: &[u8; 32], label: &[u8], context: &[u8], len: usize) -> [u8; 48] {
    // info = u16(len) || u8(6 + label.len()) || "tls13 " || label ||
    //         u8(ctx.len) || ctx    (RFC 8446 §7.1 HkdfLabel)
    let mut info = [0u8; 80];
    let label_len = 6 + label.len();
    let info_len = 2 + 1 + label_len + 1 + context.len();
    info[0] = (len >> 8) as u8;
    info[1] = len as u8;
    info[2] = label_len as u8;
    info[3..9].copy_from_slice(b"tls13 ");
    info[9..9 + label.len()].copy_from_slice(label);
    info[9 + label.len()] = context.len() as u8;
    info[10 + label.len()..10 + label.len() + context.len()].copy_from_slice(context);
    hkdf_expand(secret, &info[..info_len], len)
}

// ---------------------------------------------------------------------------
// TLS 1.3 key schedule (RFC 8446 §7.1) + record protection (RFC 8446 §5).
// ---------------------------------------------------------------------------

/// Derive-Secret (RFC 8446 §7.1): HKDF-Expand-Label(secret, label,
/// Transcript-Hash(transcript), Hash.length). `transcript` is the raw
/// concatenation of handshake messages; the transcript hash is computed here.
pub fn derive_secret(secret: &[u8; 32], label: &[u8], transcript: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    let th = sha256(transcript);
    let d = hkdf_expand_label(secret, label, &th, 32);
    out.copy_from_slice(&d[..32]);
    out
}

/// A running transcript: the concatenation of all handshake messages so far,
/// hashed with SHA-256 on demand. Bounded at 4 KiB (the whole TLS 1.3
/// handshake transcript is well under that).
pub struct Transcript {
    buf: [u8; 4096],
    len: usize,
}

impl Transcript {
    pub const fn new() -> Transcript {
        Transcript {
            buf: [0u8; 4096],
            len: 0,
        }
    }

    /// Append a full handshake message (type byte + 3-byte length + body).
    /// Returns false if the transcript buffer would overflow.
    pub fn push_message(&mut self, msg: &[u8]) -> bool {
        if self.len + msg.len() > self.buf.len() {
            return false;
        }
        self.buf[self.len..self.len + msg.len()].copy_from_slice(msg);
        self.len += msg.len();
        true
    }

    /// Append a handshake message given as (type, body) — serializes the
    /// 4-byte header then appends.
    pub fn push(&mut self, ty: u8, body: &[u8]) -> bool {
        let mut hdr = [0u8; 4];
        hdr[0] = ty;
        hdr[1] = ((body.len() >> 16) & 0xff) as u8;
        hdr[2] = ((body.len() >> 8) & 0xff) as u8;
        hdr[3] = body.len() as u8;
        if !self.push_message(&hdr) || !self.push_message(body) {
            return false;
        }
        true
    }

    pub fn hash(&self) -> [u8; 32] {
        sha256(&self.buf[..self.len])
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.buf[..self.len]
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

impl Default for Transcript {
    fn default() -> Self {
        Self::new()
    }
}

/// A TLS 1.3 traffic key/IV pair derived from a traffic secret.
#[derive(Clone, Copy, Debug)]
pub struct TrafficKey {
    pub key: [u8; 16],
    pub iv: [u8; 12],
    pub secret: [u8; 32],
}

/// Derive the write/read traffic key + IV for AES-128-GCM-SHA256 from a
/// traffic secret (RFC 8446 §7.3): "key" -> 16 bytes, "iv" -> 12 bytes.
pub fn traffic_key_from_secret(secret: &[u8; 32]) -> TrafficKey {
    let mut key = [0u8; 16];
    let mut iv = [0u8; 12];
    let k = hkdf_expand_label(secret, b"key", &[], 16);
    key.copy_from_slice(&k[..16]);
    let i = hkdf_expand_label(secret, b"iv", &[], 12);
    iv.copy_from_slice(&i[..12]);
    TrafficKey {
        key,
        iv,
        secret: *secret,
    }
}

/// Compute the TLS 1.3 handshake traffic secrets given the ECDHE shared
/// secret and the ClientHello..ServerHello transcript (RFC 8446 §7.1).
/// Returns (client_handshake, server_handshake) secrets.
pub fn derive_handshake_traffic_secrets(
    shared_secret: &[u8; 32],
    transcript: &[u8],
) -> ([u8; 32], [u8; 32]) {
    // early_secret = HKDF-Extract(0, 0) — salt and IKM are 32 zero bytes
    // (RFC 8446 §7.1, RFC 5869).
    let early = hkdf_extract(&[0u8; 32], &[0u8; 32]);
    // derived = Derive-Secret(early, "derived", "")
    let derived = derive_secret(&early, b"derived", &[]);
    // handshake_secret = HKDF-Extract(derived, ECDHE)
    let hs = hkdf_extract(&derived, shared_secret);
    // c/s hs traffic = Derive-Secret(hs, label, CH..SH)
    let c = derive_secret(&hs, b"c hs traffic", transcript);
    let s = derive_secret(&hs, b"s hs traffic", transcript);
    (c, s)
}

/// Derive the application traffic secrets from the master secret and the full
/// handshake transcript (RFC 8446 §7.1). Returns (client, server).
pub fn derive_application_traffic_secrets(
    handshake_secret: &[u8; 32],
    transcript: &[u8],
) -> ([u8; 32], [u8; 32]) {
    let derived = derive_secret(handshake_secret, b"derived", &[]);
    let master = hkdf_extract(&derived, &[0u8; 32]);
    let c = derive_secret(&master, b"c ap traffic", transcript);
    let s = derive_secret(&master, b"s ap traffic", transcript);
    (c, s)
}

/// Finished verify_data (RFC 8446 §4.4.4): first derive the finished key
/// `HKDF-Expand-Label(secret, "finished", "", Hash.length)`, then
/// `verify_data = HMAC(finished_key, Transcript-Hash(...))`. `transcript` is
/// the raw concatenation of handshake messages; the transcript hash is
/// computed here.
pub fn finished_verify_data(traffic_secret: &[u8; 32], transcript: &[u8]) -> [u8; 32] {
    let mut fk = [0u8; 32];
    let k = hkdf_expand_label(traffic_secret, b"finished", &[], 32);
    fk.copy_from_slice(&k[..32]);
    // HMAC-SHA256 with a 32-byte key (pad to 64 with zeros, then standard).
    let mut key = [0u8; 64];
    key[..32].copy_from_slice(&fk);
    let th = sha256(transcript);
    hmac_sha256(&key, &th)
}

/// TLS 1.3 record protection: the nonce is the IV XOR the sequence number
/// (as 8 big-endian bytes, low 8 bytes of the 12-byte nonce) (RFC 8446
/// §5.3).
fn record_nonce(iv: &[u8; 12], seq: u64) -> [u8; 12] {
    let mut nonce = *iv;
    let s = seq.to_be_bytes();
    for i in 0..8 {
        nonce[4 + i] ^= s[i];
    }
    nonce
}

/// Encrypt one record's inner plaintext into a protected record. Returns the
/// total record length or None if the output is too small.
pub fn protect_record(
    key: &TrafficKey,
    seq: u64,
    ct: u8,
    plaintext: &[u8],
    out: &mut [u8],
) -> Option<usize> {
    if out.len() < 5 + plaintext.len() + 16 {
        return None;
    }
    // Inner content type is the real record content type (RFC 8446 §5.4):
    // a bare inner plaintext must append the real content type byte and a
    // 2-byte zero padding length.
    let mut inner = [0u8; 16384];
    debug_assert!(plaintext.len() + 3 <= inner.len());
    inner[..plaintext.len()].copy_from_slice(plaintext);
    inner[plaintext.len()] = ct;
    let inner_len = plaintext.len() + 1;
    let iv = record_nonce(&key.iv, seq);
    let mut aad = [0u8; 5];
    aad[0] = CT_APPLICATION_DATA;
    aad[1] = 0x03;
    aad[2] = 0x03;
    let body_len = inner_len + 16;
    aad[3] = (body_len >> 8) as u8;
    aad[4] = body_len as u8;

    out[0] = CT_APPLICATION_DATA;
    out[1] = 0x03;
    out[2] = 0x03;
    out[3] = (body_len >> 8) as u8;
    out[4] = body_len as u8;
    let mut tag = [0u8; 16];
    crate::aes::gcm_seal(
        &key.key,
        &iv,
        &aad,
        &inner[..inner_len],
        &mut out[5..],
        &mut tag,
    );
    out[5 + inner_len..5 + inner_len + 16].copy_from_slice(&tag);
    Some(5 + body_len)
}

/// Decrypt one protected record. `record` is the full record (header +
/// ciphertext + tag). Returns the inner plaintext content type and the
/// plaintext slice (borrowed from `buf`). Returns None on auth failure.
pub fn unprotect_record<'a>(
    key: &TrafficKey,
    seq: u64,
    record: &'a [u8],
    buf: &'a mut [u8],
) -> Option<(u8, &'a [u8])> {
    if record.len() < 5 + 16 {
        return None;
    }
    let ct_len = record.len() - 5 - 16;
    let iv = record_nonce(&key.iv, seq);
    let mut aad = [0u8; 5];
    aad[0] = record[0];
    aad[1] = record[1];
    aad[2] = record[2];
    aad[3] = record[3];
    aad[4] = record[4];
    let mut tag = [0u8; 16];
    tag.copy_from_slice(&record[5 + ct_len..5 + ct_len + 16]);
    if buf.len() < ct_len {
        return None;
    }
    if !crate::aes::gcm_open(
        &key.key,
        &iv,
        &aad,
        &record[5..5 + ct_len],
        &tag,
        &mut buf[..ct_len],
    ) {
        return None;
    }
    // The inner plaintext has the real content type appended as its final
    // byte (RFC 8446 §5.4); the ciphertext length equals the inner length.
    let real_ct = buf[ct_len - 1];
    Some((real_ct, &buf[..ct_len - 1]))
}

// ---------------------------------------------------------------------------
// Client handshake state machine (RFC 8446 §4).
// ---------------------------------------------------------------------------

/// A running TLS 1.3 client. Owns the transcript and all derived traffic
/// keys, and drives the post-ServerHello handshake: unprotect the encrypted
/// server flight, verify the server Finished, send the client Finished, and
/// protect/unprotect application data.
pub struct Tls13Client {
    pub transcript: Transcript,
    pub shared: [u8; 32],
    pub hs_secret: [u8; 32],
    pub c_hs: TrafficKey,
    pub s_hs: TrafficKey,
    pub c_hs_seq: u64,
    pub s_hs_seq: u64,
    pub c_ap: Option<TrafficKey>,
    pub s_ap: Option<TrafficKey>,
    pub c_ap_seq: u64,
    pub s_ap_seq: u64,
    pub server_finished_verified: bool,
}

impl Tls13Client {
    /// Start the client with the ECDHE shared secret. The ClientHello must
    /// already be in the transcript (the ServerHello gets pushed by
    /// `on_server_hello`).
    pub fn new(shared: [u8; 32], transcript: Transcript) -> Tls13Client {
        let (c, s) = derive_handshake_traffic_secrets(&shared, transcript.as_bytes());
        let c_hs = traffic_key_from_secret(&c);
        let s_hs = traffic_key_from_secret(&s);
        let early = hkdf_extract(&[0u8; 32], &[0u8; 32]);
        let derived = derive_secret(&early, b"derived", &[]);
        let hs_secret = hkdf_extract(&derived, &shared);
        Tls13Client {
            transcript,
            shared,
            hs_secret,
            c_hs,
            s_hs,
            c_hs_seq: 0,
            s_hs_seq: 0,
            c_ap: None,
            s_ap: None,
            c_ap_seq: 0,
            s_ap_seq: 0,
            server_finished_verified: false,
        }
    }

    /// The master secret (RFC 8446 §7.1), cached from the handshake secret.
    pub fn master_secret(&self) -> [u8; 32] {
        let derived = derive_secret(&self.hs_secret, b"derived", &[]);
        hkdf_extract(&derived, &[0u8; 32])
    }

    /// Decrypt one server record using the current handshake read key (seq
    /// tracked internally). Records of type ChangeCipherSpec (20) are legacy
    /// no-ops and are passed through untouched so the caller can skip them
    /// without burning a sequence number.
    pub fn unprotect_server_hs<'a>(
        &mut self,
        record: &'a [u8],
        buf: &'a mut [u8],
    ) -> Option<(u8, &'a [u8])> {
        if record.first() == Some(&CT_CHANGE_CIPHER_SPEC) {
            return Some((CT_CHANGE_CIPHER_SPEC, &[]));
        }
        let r = unprotect_record(&self.s_hs, self.s_hs_seq, record, buf)?;
        self.s_hs_seq += 1;
        Some(r)
    }

    /// Feed one decrypted server handshake payload (one or more handshake
    /// messages with 4-byte headers, no trailing content-type byte) into the
    /// transcript. When the server Finished is seen its verify_data is
    /// checked against the transcript hash of everything so far. Returns
    /// false on any structural or MAC failure.
    pub fn on_server_handshake_payload(&mut self, payload: &[u8]) -> bool {
        let mut pos = 0usize;
        while pos + 4 <= payload.len() {
            let ty = payload[pos];
            let body_len = ((payload[pos + 1] as usize) << 16)
                | ((payload[pos + 2] as usize) << 8)
                | payload[pos + 3] as usize;
            if pos + 4 + body_len > payload.len() {
                return false;
            }
            let msg = &payload[pos..pos + 4 + body_len];
            if ty == HS_FINISHED {
                if self.server_finished_verified {
                    return false;
                }
                let vd = finished_verify_data(&self.s_hs.secret, self.transcript.as_bytes());
                if body_len != 32 || msg[4..36] != vd[..] {
                    return false;
                }
                self.server_finished_verified = true;
            }
            if !self.transcript.push_message(msg) {
                return false;
            }
            pos += 4 + body_len;
        }
        true
    }

    /// Build the client Finished handshake message (36 bytes: type 20,
    /// length 32, verify_data) and derive the application traffic secrets.
    /// Must be called after the server Finished is verified. Returns the
    /// message length (always 36) or None.
    pub fn build_client_finished(&mut self, out: &mut [u8]) -> Option<usize> {
        if !self.server_finished_verified || out.len() < 36 {
            return None;
        }
        // Both client_ and server_application_traffic_secret_0 are derived
        // over the transcript through the server Finished (RFC 8446 §7.1);
        // the client Finished is NOT part of either transcript.
        let master = self.master_secret();
        let c_ap = derive_secret(&master, b"c ap traffic", self.transcript.as_bytes());
        let s_ap = derive_secret(&master, b"s ap traffic", self.transcript.as_bytes());
        let vd = finished_verify_data(&self.c_hs.secret, self.transcript.as_bytes());
        out[0] = HS_FINISHED;
        out[1] = 0;
        out[2] = 0;
        out[3] = 32;
        out[4..36].copy_from_slice(&vd);
        if !self.transcript.push_message(&out[..36]) {
            return None;
        }
        self.c_ap = Some(traffic_key_from_secret(&c_ap));
        self.s_ap = Some(traffic_key_from_secret(&s_ap));
        Some(36)
    }

    /// Protect one application-data record with the client write key.
    pub fn protect_app(&mut self, plaintext: &[u8], out: &mut [u8]) -> Option<usize> {
        let key = self.c_ap.as_ref()?;
        let n = protect_record(key, self.c_ap_seq, CT_APPLICATION_DATA, plaintext, out)?;
        self.c_ap_seq += 1;
        Some(n)
    }

    /// Protect one handshake record (the client Finished) with the client
    /// handshake write key.
    pub fn protect_hs(&mut self, msg: &[u8], out: &mut [u8]) -> Option<usize> {
        let n = protect_record(&self.c_hs, self.c_hs_seq, CT_HANDSHAKE, msg, out)?;
        self.c_hs_seq += 1;
        Some(n)
    }

    /// Decrypt one application-data record with the server read key.
    pub fn unprotect_server_app<'a>(
        &mut self,
        record: &'a [u8],
        buf: &'a mut [u8],
    ) -> Option<(u8, &'a [u8])> {
        let key = self.s_ap.as_ref()?;
        let r = unprotect_record(key, self.s_ap_seq, record, buf)?;
        self.s_ap_seq += 1;
        Some(r)
    }
}

// ---------------------------------------------------------------------------
// TLS record layer (RFC 8446 §5).
// ---------------------------------------------------------------------------

/// Parse a TLS record at `buf[0..]`. Returns `(content_type, fragment)` if a
/// complete record is present.
pub fn parse_record(buf: &[u8]) -> Option<(u8, &[u8])> {
    if buf.len() < 5 {
        return None;
    }
    let ct = buf[0];
    let len = ((buf[3] as usize) << 8) | buf[4] as usize;
    if buf.len() < 5 + len {
        return None;
    }
    Some((ct, &buf[5..5 + len]))
}

/// Write a TLS record (header + fragment) into `out`; returns total length.
pub fn make_record(ct: u8, body: &[u8], out: &mut [u8]) -> usize {
    debug_assert!(out.len() >= 5 + body.len());
    out[0] = ct;
    out[1] = 0x03;
    out[2] = 0x01;
    out[3] = (body.len() >> 8) as u8;
    out[4] = body.len() as u8;
    out[5..5 + body.len()].copy_from_slice(body);
    5 + body.len()
}

// ---------------------------------------------------------------------------
// ClientHello (RFC 8446 §4.1.2).
// ---------------------------------------------------------------------------

/// Build a TLS 1.3 ClientHello into `out`. `keyshare` is the client's X25519
/// public key. Returns the total record length.
pub fn build_client_hello(keyshare: &[u8; 32], out: &mut [u8]) -> usize {
    let mut b = [0u8; 512];
    let mut o = 0usize;

    // legacy_version = 0x0303
    b[o] = 0x03;
    b[o + 1] = 0x03;
    o += 2;
    // random
    b[o..o + 32].copy_from_slice(&CLIENT_HELLO_RANDOM);
    o += 32;
    // legacy_session_id: empty
    b[o] = 0;
    o += 1;
    // cipher_suites
    b[o] = 0;
    b[o + 1] = 2;
    b[o + 2] = (CIPHER_AES_128_GCM_SHA256 >> 8) as u8;
    b[o + 3] = CIPHER_AES_128_GCM_SHA256 as u8;
    o += 4;
    // legacy_compression_methods
    b[o] = 1;
    b[o + 1] = 0;
    o += 2;

    let ext_start = o;
    o += 2;

    // server_name: host "aegis"
    b[o] = 0;
    b[o + 1] = 0;
    b[o + 2] = 0;
    b[o + 3] = 10;
    b[o + 4] = 0;
    b[o + 5] = 8;
    b[o + 6] = 0;
    b[o + 7] = 0;
    b[o + 8] = 5;
    b[o + 9..o + 14].copy_from_slice(b"aegis");
    o += 14;

    // supported_versions: 0x0304 (u8 list length inside)
    b[o] = (EXT_SUPPORTED_VERSIONS >> 8) as u8;
    b[o + 1] = EXT_SUPPORTED_VERSIONS as u8;
    b[o + 2] = 0;
    b[o + 3] = 3;
    b[o + 4] = 2;
    b[o + 5] = (TLS13_VERSION >> 8) as u8;
    b[o + 6] = TLS13_VERSION as u8;
    o += 7;

    // signature_algorithms: rsa_pkcs1_sha256, rsa_pss_rsae_sha256
    b[o] = (EXT_SIGNATURE_ALGORITHMS >> 8) as u8;
    b[o + 1] = EXT_SIGNATURE_ALGORITHMS as u8;
    b[o + 2] = 0;
    b[o + 3] = 6;
    b[o + 4] = 0;
    b[o + 5] = 4;
    b[o + 6] = (SIG_RSA_PKCS1_SHA256 >> 8) as u8;
    b[o + 7] = SIG_RSA_PKCS1_SHA256 as u8;
    b[o + 8] = (SIG_RSA_PSS_RSAE_SHA256 >> 8) as u8;
    b[o + 9] = SIG_RSA_PSS_RSAE_SHA256 as u8;
    o += 10;

    // supported_groups: x25519 (u16 list length inside)
    b[o] = (EXT_SUPPORTED_GROUPS >> 8) as u8;
    b[o + 1] = EXT_SUPPORTED_GROUPS as u8;
    b[o + 2] = 0;
    b[o + 3] = 4;
    b[o + 4] = 0;
    b[o + 5] = 2;
    b[o + 6] = (GROUP_X25519 >> 8) as u8;
    b[o + 7] = GROUP_X25519 as u8;
    o += 8;

    // key_share: x25519, 32-byte public (u16 client_shares length, u16 key length)
    b[o] = (EXT_KEY_SHARE >> 8) as u8;
    b[o + 1] = EXT_KEY_SHARE as u8;
    b[o + 2] = 0;
    b[o + 3] = 2 + 36;
    b[o + 4] = 0;
    b[o + 5] = 36;
    b[o + 6] = (GROUP_X25519 >> 8) as u8;
    b[o + 7] = GROUP_X25519 as u8;
    b[o + 8] = 0;
    b[o + 9] = 32;
    b[o + 10..o + 10 + 32].copy_from_slice(keyshare);
    o += 42;

    let ext_len = o - (ext_start + 2);
    b[ext_start] = (ext_len >> 8) as u8;
    b[ext_start + 1] = ext_len as u8;

    let body_len = o;
    let mut inner = [0u8; 516];
    inner[0] = HS_CLIENT_HELLO;
    inner[1] = (body_len >> 16) as u8;
    inner[2] = (body_len >> 8) as u8;
    inner[3] = body_len as u8;
    inner[4..4 + body_len].copy_from_slice(&b[..body_len]);
    make_record(CT_HANDSHAKE, &inner[..4 + body_len], out)
}

// ---------------------------------------------------------------------------
// ServerHello (RFC 8446 §4.1.3).
// ---------------------------------------------------------------------------

pub struct ServerHello {
    pub random: [u8; 32],
    pub cipher_suite: u16,
    pub version: u16,
    pub key_share_group: u16,
    pub key_share_key: [u8; 32],
}

/// Parse a ServerHello body (handshake type/length header already consumed).
pub fn parse_server_hello(msg: &[u8]) -> Option<ServerHello> {
    if msg.len() < 4 + 32 + 1 + 2 + 1 + 2 {
        return None;
    }
    let legacy_version = u16::from_be_bytes([msg[0], msg[1]]);
    let mut random = [0u8; 32];
    random.copy_from_slice(&msg[2..34]);
    let sid_len = msg[34] as usize;
    let p = 35 + sid_len;
    if p + 3 > msg.len() {
        return None;
    }
    let cipher_suite = u16::from_be_bytes([msg[p], msg[p + 1]]);
    let compression = msg[p + 2];
    let q = p + 3;
    if compression != 0 || q + 2 > msg.len() {
        return None;
    }
    let ext_len = u16::from_be_bytes([msg[q], msg[q + 1]]) as usize;
    let mut r = q + 2;
    let end = r + ext_len;
    if end > msg.len() {
        return None;
    }
    let mut key_share_group = 0u16;
    let mut key_share_key = [0u8; 32];
    let mut version = legacy_version;
    while r < end {
        if r + 4 > end {
            return None;
        }
        let ext_type = u16::from_be_bytes([msg[r], msg[r + 1]]);
        let elen = u16::from_be_bytes([msg[r + 2], msg[r + 3]]) as usize;
        let s = r + 4;
        let e = s + elen;
        if e > end {
            return None;
        }
        match ext_type {
            EXT_SUPPORTED_VERSIONS => {
                if elen >= 2 {
                    version = u16::from_be_bytes([msg[s], msg[s + 1]]);
                }
            }
            EXT_KEY_SHARE if elen >= 4 => {
                key_share_group = u16::from_be_bytes([msg[s], msg[s + 1]]);
                // KeyShareEntry: group(2) + opaque key_exchange<1..2^16-1>
                // (u16 length), so the key length is a 16-bit field.
                let klen = u16::from_be_bytes([msg[s + 2], msg[s + 3]]) as usize;
                if klen == 32 && s + 4 + 32 <= e {
                    key_share_key.copy_from_slice(&msg[s + 4..s + 4 + 32]);
                }
            }
            _ => {}
        }
        r = e;
    }
    Some(ServerHello {
        random,
        cipher_suite,
        version,
        key_share_group,
        key_share_key,
    })
}

// ---------------------------------------------------------------------------
// Tests.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn x25519_rfc7748_section6_1() {
        // RFC 7748 §6.1: X25519 scalar mult of the BASE POINT (u = 9).
        // Alice's private key -> Alice's public key.
        let scalar = [
            0x77, 0x07, 0x6d, 0x0a, 0x73, 0x18, 0xa5, 0x7d, 0x3c, 0x16, 0xc1, 0x72, 0x51, 0xb2,
            0x66, 0x45, 0xdf, 0x4c, 0x2f, 0x87, 0xeb, 0xc0, 0x99, 0x2a, 0xb1, 0x77, 0xfb, 0xa5,
            0x1d, 0xb9, 0x2c, 0x2a,
        ];
        let expected = [
            0x85, 0x20, 0xf0, 0x09, 0x89, 0x30, 0xa7, 0x54, 0x74, 0x8b, 0x7d, 0xdc, 0xb4, 0x3e,
            0xf7, 0x5a, 0x0d, 0xbf, 0x3a, 0x0d, 0x26, 0x38, 0x1a, 0xf4, 0xeb, 0xa4, 0xa9, 0x8e,
            0xaa, 0x9b, 0x4e, 0x6a,
        ];
        let out = x25519(
            &scalar,
            &[
                0x09, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0,
            ],
        )
        .expect("base point mult");
        assert_eq!(out, expected);
    }

    #[test]
    fn x25519_rfc7748_vector1() {
        // RFC 7748 §5.2 vector 1.
        let scalar = [
            0xa5, 0x46, 0xe3, 0x6b, 0xf0, 0x52, 0x7c, 0x9d, 0x3b, 0x16, 0x15, 0x4b, 0x82, 0x46,
            0x5e, 0xdd, 0x62, 0x14, 0x4c, 0x0a, 0xc1, 0xfc, 0x5a, 0x18, 0x50, 0x6a, 0x22, 0x44,
            0xba, 0x44, 0x9a, 0xc4,
        ];
        let u = [
            0xe6, 0xdb, 0x68, 0x67, 0x58, 0x30, 0x30, 0xdb, 0x35, 0x94, 0xc1, 0xa4, 0x24, 0xb1,
            0x5f, 0x7c, 0x72, 0x66, 0x24, 0xec, 0x26, 0xb3, 0x35, 0x3b, 0x10, 0xa9, 0x03, 0xa6,
            0xd0, 0xab, 0x1c, 0x4c,
        ];
        let expected = [
            0xc3, 0xda, 0x55, 0x37, 0x9d, 0xe9, 0xc6, 0x90, 0x8e, 0x94, 0xea, 0x4d, 0xf2, 0x8d,
            0x08, 0x4f, 0x32, 0xec, 0xcf, 0x03, 0x49, 0x1c, 0x71, 0xf7, 0x54, 0xb4, 0x07, 0x55,
            0x77, 0xa2, 0x85, 0x52,
        ];
        let out = x25519(&scalar, &u).expect("shared secret");
        assert_eq!(out, expected);
    }

    #[test]
    fn x25519_rfc7748_vector2() {
        // RFC 7748 §5.2 vector 2.
        let scalar = [
            0x4b, 0x66, 0xe9, 0xd4, 0xd1, 0xb4, 0x67, 0x3c, 0x5a, 0xd2, 0x26, 0x91, 0x95, 0x7d,
            0x6a, 0xf5, 0xc1, 0x1b, 0x64, 0x21, 0xe0, 0xea, 0x01, 0xd4, 0x2c, 0xa4, 0x16, 0x9e,
            0x79, 0x18, 0xba, 0x0d,
        ];
        let u = [
            0xe5, 0x21, 0x0f, 0x12, 0x78, 0x68, 0x11, 0xd3, 0xf4, 0xb7, 0x95, 0x9d, 0x05, 0x38,
            0xae, 0x2c, 0x31, 0xdb, 0xe7, 0x10, 0x6f, 0xc0, 0x3c, 0x3e, 0xfc, 0x4c, 0xd5, 0x49,
            0xc7, 0x15, 0xa4, 0x93,
        ];
        let expected = [
            0x95, 0xcb, 0xde, 0x94, 0x76, 0xe8, 0x90, 0x7d, 0x7a, 0xad, 0xe4, 0x5c, 0xb4, 0xb8,
            0x73, 0xf8, 0x8b, 0x59, 0x5a, 0x68, 0x79, 0x9f, 0xa1, 0x52, 0xe6, 0xf8, 0xf7, 0x64,
            0x7a, 0xac, 0x79, 0x57,
        ];
        let out = x25519(&scalar, &u).expect("shared secret");
        assert_eq!(out, expected);
    }

    #[test]
    fn x25519_base_point_gives_all_zero_rejection() {
        // u = 0 is a low-order point; the shared secret must be rejected.
        assert!(x25519(&EPHEMERAL_SCALAR, &[0u8; 32]).is_none());
    }

    #[test]
    fn hkdf_rfc5869_case1() {
        // RFC 5869 A.1: SHA-256.
        let ikm = [
            0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
            0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
        ];
        let salt = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
        ];
        let info = [0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9];
        let prk = hkdf_extract(&salt, &ikm);
        let expected_prk = [
            0x07, 0x77, 0x09, 0x36, 0x2c, 0x2e, 0x32, 0xdf, 0x0d, 0xdc, 0x3f, 0x0d, 0xc4, 0x7b,
            0xba, 0x63, 0x90, 0xb6, 0xc7, 0x3b, 0xb5, 0x0f, 0x9c, 0x31, 0x22, 0xec, 0x84, 0x4a,
            0xd7, 0xc2, 0xb3, 0xe5,
        ];
        assert_eq!(prk, expected_prk);
        let okm = hkdf_expand(&prk, &info, 42);
        let expected_okm = [
            0x3c, 0xb2, 0x5f, 0x25, 0xfa, 0xac, 0xd5, 0x7a, 0x90, 0x43, 0x4f, 0x64, 0xd0, 0x36,
            0x2f, 0x2a, 0x2d, 0x2d, 0x0a, 0x90, 0xcf, 0x1a, 0x5a, 0x4c, 0x5d, 0xb0, 0x2d, 0x56,
            0xec, 0xc4, 0xc5, 0xbf, 0x34, 0x00, 0x72, 0x08, 0xd5, 0xb8, 0x87, 0x18, 0x58, 0x65,
        ];
        assert_eq!(&okm[..42], &expected_okm[..]);
    }

    #[test]
    fn hkdf_expand_label_structure() {
        // The label info for "c hs traffic" (13-byte label => 19 with the
        // "tls13 " prefix) and a 32-byte output must match the RFC 8446 §7.1
        // HkdfLabel construction: u16(32) || u8(19) || "tls13 c hs traffic"
        // || u8(0).
        let secret = [0x42u8; 32];
        let out = hkdf_expand_label(&secret, b"c hs traffic", &[], 32);
        assert_eq!(out.len(), 48);
        assert_ne!(out, [0u8; 48]);
    }

    #[test]
    fn rfc8448_key_schedule_vectors() {
        // RFC 8448 §3 "Example Handshake Traces for TLS 1.3" — AES-128-GCM
        // (TLS_AES_128_GCM_SHA256) variant. The published intermediate values
        // validate our whole key schedule (hkdf_expand_label layout, the
        // Transcript-Hash context in derive_secret, and the finished key).
        let shared = [
            0x8b, 0xd4, 0x05, 0x4f, 0xb5, 0x5b, 0x9d, 0x63, 0xfd, 0xfb, 0xac, 0xf9, 0xf0, 0x4b,
            0x9f, 0x0d, 0x35, 0xe6, 0xd6, 0x3f, 0x53, 0x75, 0x63, 0xef, 0xd4, 0x62, 0x72, 0x90,
            0x0f, 0x89, 0x49, 0x2d,
        ];
        // The raw ClientHello..ServerHello handshake messages (RFC 8448 §3)
        // — hashed here to drive derive_secret's Transcript-Hash context.
        let ch = [
            0x01, 0x00, 0x00, 0xc0, 0x03, 0x03, 0xcb, 0x34, 0xec, 0xb1, 0xe7, 0x81, 0x63, 0xba,
            0x1c, 0x38, 0xc6, 0xda, 0xcb, 0x19, 0x6a, 0x6d, 0xff, 0xa2, 0x1a, 0x8d, 0x99, 0x12,
            0xec, 0x18, 0xa2, 0xef, 0x62, 0x83, 0x02, 0x4d, 0xec, 0xe7, 0x00, 0x00, 0x06, 0x13,
            0x01, 0x13, 0x03, 0x13, 0x02, 0x01, 0x00, 0x00, 0x91, 0x00, 0x00, 0x00, 0x0b, 0x00,
            0x09, 0x00, 0x00, 0x06, 0x73, 0x65, 0x72, 0x76, 0x65, 0x72, 0xff, 0x01, 0x00, 0x01,
            0x00, 0x00, 0x0a, 0x00, 0x14, 0x00, 0x12, 0x00, 0x1d, 0x00, 0x17, 0x00, 0x18, 0x00,
            0x19, 0x01, 0x00, 0x01, 0x01, 0x01, 0x02, 0x01, 0x03, 0x01, 0x04, 0x00, 0x23, 0x00,
            0x00, 0x00, 0x33, 0x00, 0x26, 0x00, 0x24, 0x00, 0x1d, 0x00, 0x20, 0x99, 0x38, 0x1d,
            0xe5, 0x60, 0xe4, 0xbd, 0x43, 0xd2, 0x3d, 0x8e, 0x43, 0x5a, 0x7d, 0xba, 0xfe, 0xb3,
            0xc0, 0x6e, 0x51, 0xc1, 0x3c, 0xae, 0x4d, 0x54, 0x13, 0x69, 0x1e, 0x52, 0x9a, 0xaf,
            0x2c, 0x00, 0x2b, 0x00, 0x03, 0x02, 0x03, 0x04, 0x00, 0x0d, 0x00, 0x20, 0x00, 0x1e,
            0x04, 0x03, 0x05, 0x03, 0x06, 0x03, 0x02, 0x03, 0x08, 0x04, 0x08, 0x05, 0x08, 0x06,
            0x04, 0x01, 0x05, 0x01, 0x06, 0x01, 0x02, 0x01, 0x04, 0x02, 0x05, 0x02, 0x06, 0x02,
            0x02, 0x02, 0x00, 0x2d, 0x00, 0x02, 0x01, 0x01, 0x00, 0x1c, 0x00, 0x02, 0x40, 0x01,
        ];
        let sh = [
            0x02, 0x00, 0x00, 0x56, 0x03, 0x03, 0xa6, 0xaf, 0x06, 0xa4, 0x12, 0x18, 0x60, 0xdc,
            0x5e, 0x6e, 0x60, 0x24, 0x9c, 0xd3, 0x4c, 0x95, 0x93, 0x0c, 0x8a, 0xc5, 0xcb, 0x14,
            0x34, 0xda, 0xc1, 0x55, 0x77, 0x2e, 0xd3, 0xe2, 0x69, 0x28, 0x00, 0x13, 0x01, 0x00,
            0x00, 0x2e, 0x00, 0x33, 0x00, 0x24, 0x00, 0x1d, 0x00, 0x20, 0xc9, 0x82, 0x88, 0x76,
            0x11, 0x20, 0x95, 0xfe, 0x66, 0x76, 0x2b, 0xdb, 0xf7, 0xc6, 0x72, 0xe1, 0x56, 0xd6,
            0xcc, 0x25, 0x3b, 0x83, 0x3d, 0xf1, 0xdd, 0x69, 0xb1, 0xb0, 0x4e, 0x75, 0x1f, 0x0f,
            0x00, 0x2b, 0x00, 0x02, 0x03, 0x04,
        ];
        let mut transcript = [0u8; 320];
        transcript[..ch.len()].copy_from_slice(&ch);
        transcript[ch.len()..ch.len() + sh.len()].copy_from_slice(&sh);
        let transcript = &transcript[..ch.len() + sh.len()];
        // Sanity: the hash matches RFC 8448's published CH..SH hash.
        assert_eq!(
            sha256(transcript),
            [
                0x86, 0x0c, 0x06, 0xed, 0xc0, 0x78, 0x58, 0xee, 0x8e, 0x78, 0xf0, 0xe7, 0x42, 0x8c,
                0x58, 0xed, 0xd6, 0xb4, 0x3f, 0x2c, 0xa3, 0xe6, 0xe9, 0x5f, 0x02, 0xed, 0x06, 0x3c,
                0xf0, 0xe1, 0xca, 0xd8,
            ]
        );
        let early = hkdf_extract(&[0u8; 32], &[0u8; 32]);
        assert_eq!(
            early,
            [
                0x33, 0xad, 0x0a, 0x1c, 0x60, 0x7e, 0xc0, 0x3b, 0x09, 0xe6, 0xcd, 0x98, 0x93, 0x68,
                0x0c, 0xe2, 0x10, 0xad, 0xf3, 0x00, 0xaa, 0x1f, 0x26, 0x60, 0xe1, 0xb2, 0x2e, 0x10,
                0xf1, 0x70, 0xf9, 0x2a,
            ]
        );
        let derived = derive_secret(&early, b"derived", &[]);
        assert_eq!(
            derived,
            [
                0x6f, 0x26, 0x15, 0xa1, 0x08, 0xc7, 0x02, 0xc5, 0x67, 0x8f, 0x54, 0xfc, 0x9d, 0xba,
                0xb6, 0x97, 0x16, 0xc0, 0x76, 0x18, 0x9c, 0x48, 0x25, 0x0c, 0xeb, 0xea, 0xc3, 0x57,
                0x6c, 0x36, 0x11, 0xba,
            ]
        );
        let hs = hkdf_extract(&derived, &shared);
        assert_eq!(
            hs,
            [
                0x1d, 0xc8, 0x26, 0xe9, 0x36, 0x06, 0xaa, 0x6f, 0xdc, 0x0a, 0xad, 0xc1, 0x2f, 0x74,
                0x1b, 0x01, 0x04, 0x6a, 0xa6, 0xb9, 0x9f, 0x69, 0x1e, 0xd2, 0x21, 0xa9, 0xf0, 0xca,
                0x04, 0x3f, 0xbe, 0xac,
            ]
        );
        // c/s hs traffic with the CH..SH transcript hash as context.
        let c = derive_secret(&hs, b"c hs traffic", transcript);
        assert_eq!(
            c,
            [
                0xb3, 0xed, 0xdb, 0x12, 0x6e, 0x06, 0x7f, 0x35, 0xa7, 0x80, 0xb3, 0xab, 0xf4, 0x5e,
                0x2d, 0x8f, 0x3b, 0x1a, 0x95, 0x07, 0x38, 0xf5, 0x2e, 0x96, 0x00, 0x74, 0x6a, 0x0e,
                0x27, 0xa5, 0x5a, 0x21,
            ]
        );
        let s = derive_secret(&hs, b"s hs traffic", transcript);
        assert_eq!(
            s,
            [
                0xb6, 0x7b, 0x7d, 0x69, 0x0c, 0xc1, 0x6c, 0x4e, 0x75, 0xe5, 0x42, 0x13, 0xcb, 0x2d,
                0x37, 0xb4, 0xe9, 0xc9, 0x12, 0xbc, 0xde, 0xd9, 0x10, 0x5d, 0x42, 0xbe, 0xfd, 0x59,
                0xd3, 0x91, 0xad, 0x38,
            ]
        );
        // Server write key/IV.
        let sk = traffic_key_from_secret(&s);
        assert_eq!(
            sk.key,
            [
                0x3f, 0xce, 0x51, 0x60, 0x09, 0xc2, 0x17, 0x27, 0xd0, 0xf2, 0xe4, 0xe8, 0x6e, 0xe4,
                0x03, 0xbc,
            ]
        );
        assert_eq!(
            sk.iv,
            [0x5d, 0x31, 0x3e, 0xb2, 0x67, 0x12, 0x76, 0xee, 0x13, 0x00, 0x0b, 0x30]
        );
        // Finished key for the server handshake secret.
        let s_fk = {
            let mut fk = [0u8; 32];
            let k = hkdf_expand_label(&s, b"finished", &[], 32);
            fk.copy_from_slice(&k[..32]);
            fk
        };
        assert_eq!(
            s_fk,
            [
                0x00, 0x8d, 0x3b, 0x66, 0xf8, 0x16, 0xea, 0x55, 0x9f, 0x96, 0xb5, 0x37, 0xe8, 0x85,
                0xc3, 0x1f, 0xc0, 0x68, 0xbf, 0x49, 0x2c, 0x65, 0x2f, 0x01, 0xf2, 0x88, 0xa1, 0xd8,
                0xcd, 0xc1, 0x9f, 0xc8,
            ]
        );
        // Master secret.
        let mderived = derive_secret(&hs, b"derived", &[]);
        assert_eq!(
            mderived,
            [
                0x43, 0xde, 0x77, 0xe0, 0xc7, 0x77, 0x13, 0x85, 0x9a, 0x94, 0x4d, 0xb9, 0xdb, 0x25,
                0x90, 0xb5, 0x31, 0x90, 0xa6, 0x5b, 0x3e, 0xe2, 0xe4, 0xf1, 0x2d, 0xd7, 0xa0, 0xbb,
                0x7c, 0xe2, 0x54, 0xb4,
            ]
        );
        let master = hkdf_extract(&mderived, &[0u8; 32]);
        assert_eq!(
            master,
            [
                0x18, 0xdf, 0x06, 0x84, 0x3d, 0x13, 0xa0, 0x8b, 0xf2, 0xa4, 0x49, 0x84, 0x4c, 0x5f,
                0x8a, 0x47, 0x80, 0x01, 0xbc, 0x4d, 0x4c, 0x62, 0x79, 0x84, 0xd5, 0xa4, 0x1d, 0xa8,
                0xd0, 0x40, 0x29, 0x19,
            ]
        );
        // Client write key/IV (client handshake traffic secret).
        let ck = traffic_key_from_secret(&c);
        assert_eq!(
            ck.key,
            [
                0xdb, 0xfa, 0xa6, 0x93, 0xd1, 0x76, 0x2c, 0x5b, 0x66, 0x6a, 0xf5, 0xd9, 0x50, 0x25,
                0x8d, 0x01,
            ]
        );
        assert_eq!(
            ck.iv,
            [0x5b, 0xd3, 0xc7, 0x1b, 0x83, 0x6e, 0x0b, 0x76, 0xbb, 0x73, 0x26, 0x5f]
        );
    }

    #[test]
    fn rfc8448_application_traffic_secrets() {
        // RFC 8448 §3, after the server Finished: both application traffic
        // secrets derive over the SAME transcript hash (through the server
        // Finished — 96 08 10 2a .. — NOT the client Finished). The published
        // values are the ground truth for the s_ap derivation bug this module
        // shipped with (the old code derived s_ap over a transcript that
        // already contained the client Finished).
        let master = [
            0x18, 0xdf, 0x06, 0x84, 0x3d, 0x13, 0xa0, 0x8b, 0xf2, 0xa4, 0x49, 0x84, 0x4c, 0x5f,
            0x8a, 0x47, 0x80, 0x01, 0xbc, 0x4d, 0x4c, 0x62, 0x79, 0x84, 0xd5, 0xa4, 0x1d, 0xa8,
            0xd0, 0x40, 0x29, 0x19,
        ];
        // RFC 8448 §3 "hash (32 octets)" for both c/s ap traffic: the
        // Transcript-Hash through the server Finished.
        let th: [u8; 32] = [
            0x96, 0x08, 0x10, 0x2a, 0x0f, 0x1c, 0xcc, 0x6d, 0xb6, 0x25, 0x0b, 0x7b, 0x7e, 0x41,
            0x7b, 0x1a, 0x00, 0x0e, 0xaa, 0xda, 0x3d, 0xaa, 0xe4, 0x77, 0x7a, 0x76, 0x86, 0xc9,
            0xff, 0x83, 0xdf, 0x13,
        ];
        // hkdf_expand_label(master, label, Transcript-Hash, 32) for each label.
        let c = hkdf_expand_label(&master, b"c ap traffic", &th, 32);
        assert_eq!(
            &c[..32],
            &[
                0x9e, 0x40, 0x64, 0x6c, 0xe7, 0x9a, 0x7f, 0x9d, 0xc0, 0x5a, 0xf8, 0x88, 0x9b, 0xce,
                0x65, 0x52, 0x87, 0x5a, 0xfa, 0x0b, 0x06, 0xdf, 0x00, 0x87, 0xf7, 0x92, 0xeb, 0xb7,
                0xc1, 0x75, 0x04, 0xa5,
            ]
        );
        let s = hkdf_expand_label(&master, b"s ap traffic", &th, 32);
        assert_eq!(
            &s[..32],
            &[
                0xa1, 0x1a, 0xf9, 0xf0, 0x55, 0x31, 0xf8, 0x56, 0xad, 0x47, 0x11, 0x6b, 0x45, 0xa9,
                0x50, 0x32, 0x82, 0x04, 0xb4, 0xf4, 0x4b, 0xfb, 0x6b, 0x3a, 0x4b, 0x4f, 0x1f, 0x3f,
                0xcb, 0x63, 0x16, 0x43,
            ]
        );
        // And the traffic keys/IVs derived from those secrets (RFC 8448 §3
        // "derive write/read traffic keys for application data").
        let ck = traffic_key_from_secret(&c[..32].try_into().unwrap());
        assert_eq!(
            ck.key,
            [
                0x17, 0x42, 0x2d, 0xda, 0x59, 0x6e, 0xd5, 0xd9, 0xac, 0xd8, 0x90, 0xe3, 0xc6, 0x3f,
                0x50, 0x51,
            ]
        );
        assert_eq!(
            ck.iv,
            [0x5b, 0x78, 0x92, 0x3d, 0xee, 0x08, 0x57, 0x90, 0x33, 0xe5, 0x23, 0xd9]
        );
        let sk = traffic_key_from_secret(&s[..32].try_into().unwrap());
        assert_eq!(
            sk.key,
            [
                0x9f, 0x02, 0x28, 0x3b, 0x6c, 0x9c, 0x07, 0xef, 0xc2, 0x6b, 0xb9, 0xf2, 0xac, 0x92,
                0xe3, 0x56,
            ]
        );
        assert_eq!(
            sk.iv,
            [0xcf, 0x78, 0x2b, 0x88, 0xdd, 0x83, 0x54, 0x9a, 0xad, 0xf1, 0xe9, 0x84]
        );
    }

    #[test]
    fn rfc8448_full_transcript_app_secrets() {
        // The authoritative end-to-end check: build the FULL RFC 8448 §3
        // handshake transcript (ClientHello + ServerHello + the whole 657-byte
        // encrypted server flight = EncryptedExtensions + Certificate +
        // CertificateVerify + Finished) out of the RFC's published bytes, and
        // drive the kernel's actual `derive_application_traffic_secrets` over
        // it. RFC 8448 §3 publishes the resulting c_ap and s_ap application
        // traffic secrets, so this validates the master-secret derivation,
        // the "c/s ap traffic" labels, AND — critically for the bug this
        // module shipped with — that BOTH secrets derive over the transcript
        // through the server Finished, NOT over one that contains the client
        // Finished. The vectors were extracted programmatically from the RFC
        // text (rfc-editor.org/rfc/rfc8448) into rfc8448_vec.rs, not
        // hand-transcribed.
        use crate::rfc8448_vec::*;
        let mut trans = Transcript::new();
        assert!(trans.push_message(&RFC8448_CH));
        assert!(trans.push_message(&RFC8448_SH));
        // Sanity: CH..SH hash matches the RFC's published c_hs-traffic hash.
        assert_eq!(sha256(trans.as_bytes()), RFC8448_CHSH_HASH);
        // Sanity: full transcript through the server Finished matches the
        // RFC's published app-traffic transcript hash (byte-level, so we
        // don't pollute the client transcript with the flight).
        let mut full = Vec::new();
        full.extend_from_slice(trans.as_bytes());
        full.extend_from_slice(&RFC8448_FLIGHT);
        assert_eq!(sha256(&full), RFC8448_APP_HASH);

        // The shared secret used to build the handshake schedule. The RFC
        // publishes the server's ephemeral public key; the client derives the
        // ECDHE shared secret from it with its own private key.
        let client_priv = [
            0x49, 0xaf, 0x42, 0xba, 0x7f, 0x79, 0x94, 0x85, 0x2d, 0x71, 0x3e, 0xf2, 0x78, 0x4b,
            0xcb, 0xca, 0xa7, 0x91, 0x1d, 0xe2, 0x6a, 0xdc, 0x56, 0x42, 0xcb, 0x63, 0x45, 0x40,
            0xe7, 0xea, 0x50, 0x05,
        ];
        let server_pub = [
            0xc9, 0x82, 0x88, 0x76, 0x11, 0x20, 0x95, 0xfe, 0x66, 0x76, 0x2b, 0xdb, 0xf7, 0xc6,
            0x72, 0xe1, 0x56, 0xd6, 0xcc, 0x25, 0x3b, 0x83, 0x3d, 0xf1, 0xdd, 0x69, 0xb1, 0xb0,
            0x4e, 0x75, 0x1f, 0x0f,
        ];
        let shared = x25519(&client_priv, &server_pub).expect("x25519");
        // RFC 8448 §3 handshake-secret IKM (published; guards the X25519 path).
        assert_eq!(
            shared,
            [
                0x8b, 0xd4, 0x05, 0x4f, 0xb5, 0x5b, 0x9d, 0x63, 0xfd, 0xfb, 0xac, 0xf9, 0xf0, 0x4b,
                0x9f, 0x0d, 0x35, 0xe6, 0xd6, 0x3f, 0x53, 0x75, 0x63, 0xef, 0xd4, 0x62, 0x72, 0x90,
                0x0f, 0x89, 0x49, 0x2d,
            ]
        );

        // Full client state machine over the RFC transcript: handshake
        // secrets, then app secrets derived over the pre-Finished transcript.
        let mut client = Tls13Client::new(shared, trans);
        assert!(client.on_server_handshake_payload(&RFC8448_FLIGHT));
        assert!(client.server_finished_verified);
        let mut fin = [0u8; 64];
        let n = client
            .build_client_finished(&mut fin)
            .expect("client Finished");
        assert_eq!(n, 36);

        // The app secrets must match RFC 8448's published values byte-for-byte.
        let c_ap = client.c_ap.expect("c_ap");
        let s_ap = client.s_ap.expect("s_ap");
        assert_eq!(
            c_ap.key,
            [
                0x17, 0x42, 0x2d, 0xda, 0x59, 0x6e, 0xd5, 0xd9, 0xac, 0xd8, 0x90, 0xe3, 0xc6, 0x3f,
                0x50, 0x51,
            ]
        );
        assert_eq!(
            s_ap.key,
            [
                0x9f, 0x02, 0x28, 0x3b, 0x6c, 0x9c, 0x07, 0xef, 0xc2, 0x6b, 0xb9, 0xf2, 0xac, 0x92,
                0xe3, 0x56,
            ]
        );
        // And the regression guard: if s_ap had been derived over a transcript
        // that includes the client Finished (the old bug), its key would not
        // match the RFC value. Re-derive the master + s_ap over
        // transcript+Finished and confirm it differs.
        let master = client.master_secret();
        let wrong_s = derive_secret(&master, b"s ap traffic", client.transcript.as_bytes());
        let right_s = derive_secret(
            &master,
            b"s ap traffic",
            &client.transcript.as_bytes()[..client.transcript.len() - 36],
        );
        assert_ne!(
            wrong_s, right_s,
            "s_ap over Finished-inclusive transcript must differ"
        );
        assert_eq!(right_s, s_ap.secret);
    }

    #[test]
    fn client_hello_structure() {
        let keyshare = x25519_base(&EPHEMERAL_SCALAR);
        let mut out = [0u8; 600];
        let n = build_client_hello(&keyshare, &mut out);
        let (ct, frag) = parse_record(&out[..n]).expect("record");
        assert_eq!(ct, CT_HANDSHAKE);
        assert_eq!(frag[0], HS_CLIENT_HELLO);
        let body_len = ((frag[1] as usize) << 16) | ((frag[2] as usize) << 8) | frag[3] as usize;
        assert_eq!(body_len, frag.len() - 4);
        let body = &frag[4..];
        assert_eq!(&body[0..2], &[0x03, 0x03]);
        assert_eq!(&body[2..34], &CLIENT_HELLO_RANDOM[..]);
        let cipher = u16::from_be_bytes([body[37], body[38]]);
        assert_eq!(cipher, CIPHER_AES_128_GCM_SHA256);
    }

    #[test]
    fn server_hello_parse_roundtrip() {
        // Build a synthetic ServerHello body and parse it back.
        let mut msg = [0u8; 128];
        msg[0] = 0x03;
        msg[1] = 0x03;
        for (i, b) in msg[2..34].iter_mut().enumerate() {
            *b = (i % 251) as u8;
        }
        msg[34] = 0; // no session id
        msg[35] = 0x13;
        msg[36] = 0x01;
        msg[37] = 0; // compression null
                     // extensions
        msg[38] = 0;
        msg[39] = 48;
        // supported_versions 0x002b len 2 -> 0x0304
        msg[40] = 0x00;
        msg[41] = 0x2b;
        msg[42] = 0x00;
        msg[43] = 0x02;
        msg[44] = 0x03;
        msg[45] = 0x04;
        // key_share 0x0033 len 38 -> group 0x001d, u16 keylen 32, key bytes
        msg[46] = 0x00;
        msg[47] = 0x33;
        msg[48] = 0x00;
        msg[49] = 38;
        msg[50] = 0x00;
        msg[51] = 0x1d;
        msg[52] = 0x00;
        msg[53] = 32;
        for (i, b) in msg[54..86].iter_mut().enumerate() {
            *b = (i as u8).wrapping_add(7);
        }
        let sh = parse_server_hello(&msg[..88]).expect("server hello");
        assert_eq!(sh.version, TLS13_VERSION);
        assert_eq!(sh.cipher_suite, CIPHER_AES_128_GCM_SHA256);
        assert_eq!(sh.key_share_group, GROUP_X25519);
        assert_eq!(sh.key_share_key[0], 7);
        assert_eq!(sh.key_share_key[31], 38);
    }

    #[test]
    fn parse_record_rejects_short_buffers() {
        assert!(parse_record(&[0u8; 4]).is_none());
        assert!(parse_record(&[0x17, 0x03, 0x03, 0x01, 0x00]).is_none());
    }

    #[test]
    fn record_protection_roundtrip() {
        // Derive a synthetic key schedule and round-trip a handshake message
        // through record protection.
        let shared = [0x42u8; 32];
        let mut trans = Transcript::new();
        assert!(trans.push(HS_CLIENT_HELLO, &[1, 2, 3]));
        assert!(trans.push(HS_SERVER_HELLO, &[4, 5, 6]));
        let (c, s) = derive_handshake_traffic_secrets(&shared, trans.as_bytes());
        let ck = traffic_key_from_secret(&c);
        let sk = traffic_key_from_secret(&s);

        // Server protects its Finished with the server key at seq 0.
        let vd = finished_verify_data(&sk.secret, trans.as_bytes());
        let mut body = [0u8; 64];
        body[0] = 20; // HS_FINISHED
        body[1] = 0;
        body[2] = 0;
        body[3] = 32;
        body[4..36].copy_from_slice(&vd);
        let mut rec = [0u8; 200];
        let n = protect_record(&sk, 0, CT_HANDSHAKE, &body[..36], &mut rec).expect("protect");

        // Client unprotects with the server key at seq 0.
        let mut buf = [0u8; 200];
        let (ct, plain) = unprotect_record(&sk, 0, &rec[..n], &mut buf).expect("unprotect");
        assert_eq!(ct, CT_HANDSHAKE);
        assert_eq!(plain[0], 20);
        assert_eq!(&plain[4..36], &vd[..]);

        // Wrong key fails auth.
        assert!(unprotect_record(&ck, 0, &rec[..n], &mut buf).is_none());
        // Wrong sequence number fails auth.
        assert!(unprotect_record(&sk, 1, &rec[..n], &mut buf).is_none());
    }

    #[test]
    fn handshake_traffic_secrets_distinct() {
        let shared = [0x11u8; 32];
        let mut trans = Transcript::new();
        assert!(trans.push(HS_CLIENT_HELLO, &[0xaa; 8]));
        let (c, s) = derive_handshake_traffic_secrets(&shared, trans.as_bytes());
        assert_ne!(c, s);
        let ck = traffic_key_from_secret(&c);
        let sk = traffic_key_from_secret(&s);
        assert_ne!(ck.key, sk.key);
        assert_ne!(ck.iv, sk.iv);
        // App traffic secrets differ from handshake ones.
        let hs = hkdf_extract(
            &derive_secret(&hkdf_extract(&[0u8; 32], &[0u8; 32]), b"derived", &[]),
            &shared,
        );
        let (ca, sa) = derive_application_traffic_secrets(&hs, trans.as_bytes());
        assert_ne!(ca, sa);
        assert_ne!(ca, c);
        assert_ne!(sa, s);
    }

    #[test]
    fn transcript_hash_changes_with_messages() {
        let mut t1 = Transcript::new();
        assert!(t1.push(HS_CLIENT_HELLO, b"abc"));
        let mut t2 = Transcript::new();
        assert!(t2.push(HS_CLIENT_HELLO, b"abc"));
        assert!(t2.push(HS_SERVER_HELLO, b"def"));
        assert_ne!(t1.hash(), t2.hash());
        assert_eq!(t1.len(), 7);
    }

    #[test]
    fn real_capture_debug() {
        // Temporary debug: reproduce the live QEMU capture (e1000-tls.pcap)
        // to localize the record-auth failure.
        let ch_msg = [
            0x01, 0x00, 0x00, 0x7c, 0x03, 0x03, 0xa6, 0x07, 0x6f, 0x3e, 0x1b, 0x2c, 0x4d, 0x5e,
            0x6f, 0x70, 0x81, 0x92, 0xa3, 0xb4, 0xc5, 0xd6, 0xe7, 0xf8, 0x09, 0x1a, 0x2b, 0x3c,
            0x4d, 0x5e, 0x6f, 0x70, 0x81, 0x92, 0xa3, 0xb4, 0xc5, 0xd6, 0x00, 0x00, 0x02, 0x13,
            0x01, 0x01, 0x00, 0x00, 0x51, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x08, 0x00, 0x00, 0x05,
            0x61, 0x65, 0x67, 0x69, 0x73, 0x00, 0x2b, 0x00, 0x03, 0x02, 0x03, 0x04, 0x00, 0x0d,
            0x00, 0x06, 0x00, 0x04, 0x04, 0x01, 0x08, 0x04, 0x00, 0x0a, 0x00, 0x04, 0x00, 0x02,
            0x00, 0x1d, 0x00, 0x33, 0x00, 0x26, 0x00, 0x24, 0x00, 0x1d, 0x00, 0x20, 0xb1, 0x1b,
            0xca, 0x01, 0x1d, 0xa3, 0x6c, 0x40, 0x3a, 0xa2, 0x08, 0x51, 0x27, 0xcb, 0x46, 0xa2,
            0x46, 0x05, 0x9b, 0xa1, 0x26, 0x6e, 0x9d, 0x63, 0x2f, 0x15, 0x1b, 0x31, 0x6f, 0xdd,
            0x82, 0x05,
        ];
        let sh_msg = [
            0x02, 0x00, 0x00, 0x56, 0x03, 0x03, 0x95, 0x0c, 0x2b, 0xfb, 0x31, 0x22, 0x5c, 0x34,
            0x67, 0x1f, 0xb1, 0x9d, 0xf9, 0xfc, 0x4b, 0xc4, 0xe0, 0x70, 0xbd, 0x28, 0x48, 0xf8,
            0x1c, 0xe3, 0xf8, 0x0b, 0xdd, 0xd3, 0x51, 0x0d, 0xf8, 0x2c, 0x00, 0x13, 0x01, 0x00,
            0x00, 0x2e, 0x00, 0x2b, 0x00, 0x02, 0x03, 0x04, 0x00, 0x33, 0x00, 0x24, 0x00, 0x1d,
            0x00, 0x20, 0x4d, 0xb1, 0x35, 0xd1, 0x5c, 0xfe, 0xb8, 0x10, 0x0a, 0x26, 0x81, 0xcd,
            0x6c, 0x22, 0x5f, 0xde, 0xcf, 0xac, 0x11, 0xf8, 0x10, 0x13, 0xdc, 0xf2, 0x2f, 0x02,
            0xcb, 0x91, 0x6b, 0x59, 0x60, 0x05,
        ];
        let rec2 = [
            0x17, 0x03, 0x03, 0x00, 0x17, 0xb3, 0xe9, 0xb0, 0xaf, 0xc4, 0x9f, 0x1d, 0xc5, 0xb2,
            0x11, 0x1e, 0xb8, 0xb9, 0x4e, 0x89, 0xb0, 0x43, 0xe6, 0x51, 0x84, 0xa7, 0x63, 0xb9,
        ];
        let shared = [
            0x9a, 0x3e, 0x2d, 0xd5, 0xf5, 0x69, 0x4a, 0xa5, 0xae, 0x40, 0x52, 0x5a, 0xc4, 0xc5,
            0x9c, 0xd2, 0x8a, 0xe2, 0xee, 0x85, 0x44, 0xb0, 0x41, 0xe7, 0xa9, 0x9b, 0x46, 0x04,
            0xd8, 0x19, 0xcf, 0x22,
        ];
        let mut trans = Transcript::new();
        assert!(trans.push_message(&ch_msg));
        assert!(trans.push_message(&sh_msg));
        // DEBUG: does the kernel's own base-point public key equal the
        // ClientHello keyshare that went on the wire? The wire capture was
        // made with the old (buggy) ladder that returned 2d512bf7... for
        // this scalar; the corrected ladder must return b11bca01... which is
        // the value OpenSSL/cryptography derive for the same scalar.
        let expect_base = [
            0xb1, 0x1b, 0xca, 0x01, 0x1d, 0xa3, 0x6c, 0x40, 0x3a, 0xa2, 0x08, 0x51, 0x27, 0xcb,
            0x46, 0xa2, 0x46, 0x05, 0x9b, 0xa1, 0x26, 0x6e, 0x9d, 0x63, 0x2f, 0x15, 0x1b, 0x31,
            0x6f, 0xdd, 0x82, 0x05,
        ];
        assert_eq!(
            x25519_base(&EPHEMERAL_SCALAR),
            expect_base,
            "base != expected"
        );
        let ser_ks = [
            0x4d, 0xb1, 0x35, 0xd1, 0x5c, 0xfe, 0xb8, 0x10, 0x0a, 0x26, 0x81, 0xcd, 0x6c, 0x22,
            0x5f, 0xde, 0xcf, 0xac, 0x11, 0xf8, 0x10, 0x13, 0xdc, 0xf2, 0x2f, 0x02, 0xcb, 0x91,
            0x6b, 0x59, 0x60, 0x05,
        ];
        let expect_shared = [
            0x9a, 0x3e, 0x2d, 0xd5, 0xf5, 0x69, 0x4a, 0xa5, 0xae, 0x40, 0x52, 0x5a, 0xc4, 0xc5,
            0x9c, 0xd2, 0x8a, 0xe2, 0xee, 0x85, 0x44, 0xb0, 0x41, 0xe7, 0xa9, 0x9b, 0x46, 0x04,
            0xd8, 0x19, 0xcf, 0x22,
        ];
        assert_eq!(
            x25519(&EPHEMERAL_SCALAR, &ser_ks),
            Some(expect_shared),
            "server-ks shared != expected"
        );
        let u2 = [
            0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0,
        ];
        let expect_u2 = [
            0x50, 0xe1, 0xb2, 0x33, 0x89, 0x2e, 0xd2, 0xbb, 0x23, 0xc5, 0xae, 0xbe, 0x65, 0x70,
            0x83, 0xb7, 0xd8, 0x42, 0x7d, 0xf2, 0xe1, 0x60, 0x2d, 0xd4, 0xa2, 0xe6, 0xe4, 0xce,
            0x43, 0x23, 0xdc, 0x4e,
        ];
        assert_eq!(
            x25519(&EPHEMERAL_SCALAR, &u2),
            Some(expect_u2),
            "u=2 shared != expected"
        );
        let u5 = [
            0x05, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0,
        ];
        let expect_u5 = [
            0x95, 0x9c, 0xbc, 0x97, 0x4e, 0x61, 0x5d, 0x0f, 0x75, 0x93, 0x7e, 0x12, 0xf3, 0xcd,
            0xfc, 0x50, 0x0b, 0x85, 0x9c, 0x7a, 0xdd, 0x6c, 0xa8, 0x63, 0x5e, 0x29, 0x67, 0x37,
            0x8f, 0x6f, 0xe9, 0x2a,
        ];
        assert_eq!(
            x25519(&EPHEMERAL_SCALAR, &u5),
            Some(expect_u5),
            "u=5 shared != expected"
        );
        let u_r2 = [
            0xe5, 0x21, 0x0f, 0x12, 0x78, 0x68, 0x11, 0xd3, 0xf4, 0xb7, 0x95, 0x9d, 0x05, 0x38,
            0xae, 0x2c, 0x31, 0xdb, 0xe7, 0x10, 0x6f, 0xc0, 0x3c, 0x3e, 0xfc, 0x4c, 0xd5, 0x49,
            0xc7, 0x15, 0xa4, 0x93,
        ];
        let expect_r2 = [
            0xed, 0x5e, 0x20, 0xcb, 0x29, 0x3d, 0x21, 0x97, 0x8e, 0x67, 0xa6, 0xad, 0x44, 0x95,
            0x18, 0xa4, 0x83, 0x45, 0xa5, 0xac, 0xc0, 0xcd, 0xe8, 0x43, 0x83, 0x9a, 0x8b, 0x4f,
            0x94, 0x1d, 0xac, 0x0c,
        ];
        assert_eq!(
            x25519(&EPHEMERAL_SCALAR, &u_r2),
            Some(expect_r2),
            "rfc2u shared != expected"
        );
        let th = sha256(trans.as_bytes());
        // Expected CH..SH transcript hash from the host-side Python repro.
        assert_eq!(
            th,
            [
                0x0d, 0xee, 0x03, 0xde, 0x54, 0x6b, 0x1b, 0x61, 0xee, 0xdb, 0xb2, 0xc2, 0xbc, 0xbb,
                0x91, 0xb0, 0xb5, 0xa8, 0x04, 0x69, 0x24, 0xfd, 0xc0, 0x9d, 0x5a, 0xd7, 0x50, 0xc6,
                0x8d, 0x60, 0x04, 0x2d,
            ]
        );
        let mut client = Tls13Client::new(shared, trans);
        // s hs traffic key expected from the host repro.
        assert_eq!(
            client.s_hs.key,
            [
                0xad, 0x80, 0x79, 0x8d, 0x82, 0xf4, 0x94, 0x23, 0x38, 0x29, 0xce, 0xff, 0x50, 0x6f,
                0x64, 0xdc,
            ]
        );
        let mut plain = [0u8; 256];
        let r = client.unprotect_server_hs(&rec2, &mut plain);
        assert!(r.is_some(), "decrypt of REC2 should succeed");
    }

    #[test]
    fn rfc8448_record_protection_vectors() {
        // Decrypt the real TLS 1.3 ciphertext records published in RFC 8448
        // §3 with the published traffic keys, independently validating the
        // record-nonce construction (IV XOR big-endian sequence number), the
        // AAD, and the inner-content-type framing. The application-data
        // record sits at sequence number 1, which would fail under the
        // little-endian nonce variant.
        let s_ap = TrafficKey {
            key: [
                0x9f, 0x02, 0x28, 0x3b, 0x6c, 0x9c, 0x07, 0xef, 0xc2, 0x6b, 0xb9, 0xf2, 0xac, 0x92,
                0xe3, 0x56,
            ],
            iv: [
                0xcf, 0x78, 0x2b, 0x88, 0xdd, 0x83, 0x54, 0x9a, 0xad, 0xf1, 0xe9, 0x84,
            ],
            secret: [0u8; 32],
        };
        // Server -> client application_data record (RFC 8448 §3), encrypted
        // under s_ap at sequence 1. Payload is 0x00..=0x31, inner content
        // type application_data (0x17).
        let rec = [
            0x17, 0x03, 0x03, 0x00, 0x43, 0x2e, 0x93, 0x7e, 0x11, 0xef, 0x4a, 0xc7, 0x40, 0xe5,
            0x38, 0xad, 0x36, 0x00, 0x5f, 0xc4, 0xa4, 0x69, 0x32, 0xfc, 0x32, 0x25, 0xd0, 0x5f,
            0x82, 0xaa, 0x1b, 0x36, 0xe3, 0x0e, 0xfa, 0xf9, 0x7d, 0x90, 0xe6, 0xdf, 0xfc, 0x60,
            0x2d, 0xcb, 0x50, 0x1a, 0x59, 0xa8, 0xfc, 0xc4, 0x9c, 0x4b, 0xf2, 0xe5, 0xf0, 0xa2,
            0x1c, 0x00, 0x47, 0xc2, 0xab, 0xf3, 0x32, 0x54, 0x0d, 0xd0, 0x32, 0xe1, 0x67, 0xc2,
            0x95, 0x5d,
        ];
        let mut buf = [0u8; 256];
        let (ct, plain) = unprotect_record(&s_ap, 1, &rec, &mut buf).expect("s_ap seq1");
        assert_eq!(ct, CT_APPLICATION_DATA);
        let expected: [u8; 50] = core::array::from_fn(|i| i as u8);
        assert_eq!(plain, expected);
        // Re-protecting the same plaintext at seq 1 must reproduce the exact
        // RFC 8448 ciphertext.
        let mut out = [0u8; 256];
        let n = protect_record(&s_ap, 1, CT_APPLICATION_DATA, &expected, &mut out).unwrap();
        assert_eq!(&out[..n], &rec[..]);

        // Server -> client NewSessionTicket record at seq 0 (s_ap). Payload
        // is the NewSessionTicket handshake message, inner type handshake.
        let nst = [
            0x17, 0x03, 0x03, 0x00, 0xde, 0x3a, 0x6b, 0x8f, 0x90, 0x41, 0x4a, 0x97, 0xd6, 0x95,
            0x9c, 0x34, 0x87, 0x68, 0x0d, 0xe5, 0x13, 0x4a, 0x2b, 0x24, 0x0e, 0x6c, 0xff, 0xac,
            0x11, 0x6e, 0x95, 0xd4, 0x1d, 0x6a, 0xf8, 0xf6, 0xb5, 0x80, 0xdc, 0xf3, 0xd1, 0x1d,
            0x63, 0xc7, 0x58, 0xdb, 0x28, 0x9a, 0x01, 0x59, 0x40, 0x25, 0x2f, 0x55, 0x71, 0x3e,
            0x06, 0x1d, 0xc1, 0x3e, 0x07, 0x88, 0x91, 0xa3, 0x8e, 0xfb, 0xcf, 0x57, 0x53, 0xad,
            0x8e, 0xf1, 0x70, 0xad, 0x3c, 0x73, 0x53, 0xd1, 0x6d, 0x9d, 0xa7, 0x73, 0xb9, 0xca,
            0x7f, 0x2b, 0x9f, 0xa1, 0xb6, 0xc0, 0xd4, 0xa3, 0xd0, 0x3f, 0x75, 0xe0, 0x9c, 0x30,
            0xba, 0x1e, 0x62, 0x97, 0x2a, 0xc4, 0x6f, 0x75, 0xf7, 0xb9, 0x81, 0xbe, 0x63, 0x43,
            0x9b, 0x29, 0x99, 0xce, 0x13, 0x06, 0x46, 0x15, 0x13, 0x98, 0x91, 0xd5, 0xe4, 0xc5,
            0xb4, 0x06, 0xf1, 0x6e, 0x3f, 0xc1, 0x81, 0xa7, 0x7c, 0xa4, 0x75, 0x84, 0x00, 0x25,
            0xdb, 0x2f, 0x0a, 0x77, 0xf8, 0x1b, 0x5a, 0xb0, 0x5b, 0x94, 0xc0, 0x13, 0x46, 0x75,
            0x5f, 0x69, 0x23, 0x2c, 0x86, 0x51, 0x9d, 0x86, 0xcb, 0xee, 0xac, 0x87, 0xaa, 0xc3,
            0x47, 0xd1, 0x43, 0xf9, 0x60, 0x5d, 0x64, 0xf6, 0x50, 0xdb, 0x4d, 0x02, 0x3e, 0x70,
            0xe9, 0x52, 0xca, 0x49, 0xfe, 0x51, 0x37, 0x12, 0x1c, 0x74, 0xbc, 0x26, 0x97, 0x68,
            0x7e, 0x24, 0x87, 0x46, 0xd6, 0xdf, 0x35, 0x30, 0x05, 0xf3, 0xbc, 0xe1, 0x86, 0x96,
            0x12, 0x9c, 0x81, 0x53, 0x55, 0x6b, 0x3b, 0x6c, 0x67, 0x79, 0xb3, 0x7b, 0xf1, 0x59,
            0x85, 0x68, 0x4f,
        ];
        let mut buf2 = [0u8; 512];
        let (ct, plain) = unprotect_record(&s_ap, 0, &nst, &mut buf2).expect("s_ap seq0");
        assert_eq!(ct, CT_HANDSHAKE);
        assert_eq!(plain[0], HS_NEW_SESSION_TICKET);

        // Client -> server Finished record (RFC 8448 §3), encrypted under the
        // client handshake write key at seq 0. Inner type handshake.
        let c_hs = TrafficKey {
            key: [
                0xdb, 0xfa, 0xa6, 0x93, 0xd1, 0x76, 0x2c, 0x5b, 0x66, 0x6a, 0xf5, 0xd9, 0x50, 0x25,
                0x8d, 0x01,
            ],
            iv: [
                0x5b, 0xd3, 0xc7, 0x1b, 0x83, 0x6e, 0x0b, 0x76, 0xbb, 0x73, 0x26, 0x5f,
            ],
            secret: [0u8; 32],
        };
        let cfin = [
            0x17, 0x03, 0x03, 0x00, 0x35, 0x75, 0xec, 0x4d, 0xc2, 0x38, 0xcc, 0xe6, 0x0b, 0x29,
            0x80, 0x44, 0xa7, 0x1e, 0x21, 0x9c, 0x56, 0xcc, 0x77, 0xb0, 0x51, 0x7f, 0xe9, 0xb9,
            0x3c, 0x7a, 0x4b, 0xfc, 0x44, 0xd8, 0x7f, 0x38, 0xf8, 0x03, 0x38, 0xac, 0x98, 0xfc,
            0x46, 0xde, 0xb3, 0x84, 0xbd, 0x1c, 0xae, 0xac, 0xab, 0x68, 0x67, 0xd7, 0x26, 0xc4,
            0x05, 0x46,
        ];
        let mut buf3 = [0u8; 256];
        let (ct, plain) = unprotect_record(&c_hs, 0, &cfin, &mut buf3).expect("c_hs seq0");
        assert_eq!(ct, CT_HANDSHAKE);
        assert_eq!(plain[0], HS_FINISHED);
        assert_eq!(
            &plain[4..36],
            &[
                0xa8, 0xec, 0x43, 0x6d, 0x67, 0x76, 0x34, 0xae, 0x52, 0x5a, 0xc1, 0xfc, 0xeb, 0xe1,
                0x1a, 0x03, 0x9e, 0xc1, 0x76, 0x94, 0xfa, 0xc6, 0xe9, 0x85, 0x27, 0xb6, 0x42, 0xf2,
                0xed, 0xd5, 0xce, 0x61,
            ]
        );
    }

    #[test]
    fn client_handshake_state_machine() {
        // Drive the full client-side handshake with synthetic messages and
        // confirm Finished verification, client Finished construction, and
        // application-data protection both ways.
        let shared = [0x42u8; 32];
        let mut trans = Transcript::new();
        // Raw ClientHello + ServerHello handshake messages (with 4-byte
        // headers) as they would be captured off the wire.
        let ch = [0u8; 100]; // placeholder body; hashed content is irrelevant
        let mut ch_msg = [0u8; 104];
        ch_msg[0] = HS_CLIENT_HELLO;
        ch_msg[3] = 100;
        ch_msg[4..104].copy_from_slice(&ch);
        let mut sh_msg = [0u8; 60];
        sh_msg[0] = HS_SERVER_HELLO;
        sh_msg[3] = 56;
        sh_msg[4] = 0x03;
        sh_msg[5] = 0x03;
        assert!(trans.push_message(&ch_msg));
        assert!(trans.push_message(&sh_msg));
        let mut client = Tls13Client::new(shared, trans);

        // Server handshake traffic key for the server side of the record
        // protection (the client unprotects with its own copy).
        let (c_secret, s_secret) =
            derive_handshake_traffic_secrets(&shared, client.transcript.as_bytes());
        let s_key = traffic_key_from_secret(&s_secret);

        // Server builds its Finished over the transcript hash so far (CH+SH),
        // encrypts it as a handshake record at seq 0, and sends it.
        let vd = finished_verify_data(&s_key.secret, client.transcript.as_bytes());
        let mut fin = [0u8; 36];
        fin[0] = HS_FINISHED;
        fin[3] = 32;
        fin[4..36].copy_from_slice(&vd);
        let mut enc = [0u8; 300];
        let n = protect_record(&s_key, 0, CT_HANDSHAKE, &fin, &mut enc).expect("server enc");
        let mut plain = [0u8; 300];
        let (ct, payload) = client
            .unprotect_server_hs(&enc[..n], &mut plain)
            .expect("client unprotect");
        assert_eq!(ct, CT_HANDSHAKE);
        assert!(client.on_server_handshake_payload(payload));
        assert!(client.server_finished_verified);

        // Client builds its Finished + app secrets. The expected verify_data
        // is over the transcript BEFORE the client Finished is appended.
        let c_key = traffic_key_from_secret(&c_secret);
        let expected_cvd = finished_verify_data(&c_key.secret, client.transcript.as_bytes());
        // Snapshot the raw transcript (through the server Finished) before
        // the client Finished is appended.
        let pre_fin_len = client.transcript.len();
        let mut pre_fin = [0u8; 4096];
        pre_fin[..pre_fin_len].copy_from_slice(client.transcript.as_bytes());
        let master = client.master_secret();
        let mut app = [0u8; 400];
        let mut cfin = [0u8; 64];
        let nfin = client
            .build_client_finished(&mut cfin)
            .expect("client finished");
        assert_eq!(nfin, 36);
        assert_eq!(cfin[0], HS_FINISHED);
        assert_eq!(&cfin[4..36], &expected_cvd[..]);
        let post_fin_len = client.transcript.len();
        assert!(post_fin_len > pre_fin_len);
        // c_ap and s_ap both use the transcript through the server Finished
        // (before the client Finished is pushed); only res_master uses the
        // client Finished (RFC 8446 §7.1).
        let c_ap_secret = derive_secret(&master, b"c ap traffic", &pre_fin[..pre_fin_len]);
        let s_ap_secret = derive_secret(&master, b"s ap traffic", &pre_fin[..pre_fin_len]);
        let c_ap_key = traffic_key_from_secret(&c_ap_secret);
        let s_ap_key = traffic_key_from_secret(&s_ap_secret);
        let mut server_plain = [0u8; 400];
        let napp = client
            .protect_app(b"GET / HTTP/1.0", &mut app)
            .expect("client app enc");
        let (ct, server_data) =
            unprotect_record(&c_ap_key, 0, &app[..napp], &mut server_plain).expect("server dec");
        assert_eq!(ct, CT_APPLICATION_DATA);
        assert_eq!(server_data, b"GET / HTTP/1.0");

        // Server -> client: protected with s_ap, decrypted by the client's
        // read key via unprotect_server_app.
        let mut resp = [0u8; 400];
        let nresp = protect_record(
            &s_ap_key,
            0,
            CT_APPLICATION_DATA,
            b"HTTP/1.0 200 OK",
            &mut resp,
        )
        .expect("server app enc");
        let mut client_plain = [0u8; 400];
        let (ct2, client_data) = client
            .unprotect_server_app(&resp[..nresp], &mut client_plain)
            .expect("client app dec");
        assert_eq!(ct2, CT_APPLICATION_DATA);
        assert_eq!(client_data, b"HTTP/1.0 200 OK");

        // Wrong transcript: a Finished computed over the *good* transcript
        // (CH+SH) must fail to verify on a client whose transcript diverged
        // (extra EncryptedExtensions) before the Finished.
        let mut bad_client = Tls13Client::new(shared, {
            let mut t = Transcript::new();
            assert!(t.push_message(&ch_msg));
            assert!(t.push_message(&sh_msg));
            t
        });
        let mut bad_plain = [0u8; 300];
        // Same key schedule (CH+SH identical), so the server Finished record
        // decrypts at seq 0, but the transcript now has a divergent EE pushed
        // first, so the Finished verify_data (over CH+SH) must be rejected.
        let mut ee_payload = [0u8; 8];
        ee_payload[0] = HS_ENCRYPTED_EXTENSIONS;
        ee_payload[3] = 4;
        assert!(bad_client.on_server_handshake_payload(&ee_payload));
        let (_, bad_payload) = bad_client
            .unprotect_server_hs(&enc[..n], &mut bad_plain)
            .expect("bad unprotect");
        assert!(!bad_client.on_server_handshake_payload(bad_payload));
        assert!(!bad_client.server_finished_verified);
    }
}
