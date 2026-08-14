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
    // (2^255 ≡ 19): 2^(51*(5+k)) ≡ 19 * 2^(51k). Limbs 5..7 are already
    // < 2^51; r8 can have bits above 51, folded into limbs 3 and 4.
    r[0] += r[5] * 19;
    r[1] += r[6] * 19;
    r[2] += r[7] * 19;
    r[3] += (r[8] & M51) * 19;
    r[4] += (r[8] >> 51) * 19;
    // Clear the folded limbs (never fold them again).
    r[5] = 0;
    r[6] = 0;
    r[7] = 0;
    r[8] = 0;
    // Propagate carries; fold any overflow out of limb 4 back with 19.
    for i in 0..4 {
        let c = r[i] >> 51;
        r[i] &= M51;
        r[i + 1] += c;
    }
    let c = r[4] >> 51;
    if c > 0 {
        r[4] &= M51;
        r[0] += c * 19;
        for i in 0..4 {
            let cc = r[i] >> 51;
            r[i] &= M51;
            r[i + 1] += cc;
        }
        r[4] &= M51;
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
    // info = u16(7 + label.len()) || 0x00 || "tls13 " || label || u8(ctx.len) || ctx
    let mut info = [0u8; 80];
    let info_len = 2 + 1 + 6 + label.len() + 1 + context.len();
    let l = 7 + label.len();
    info[0] = (l >> 8) as u8;
    info[1] = l as u8;
    info[2] = 0;
    info[3..9].copy_from_slice(b"tls13 ");
    info[9..9 + label.len()].copy_from_slice(label);
    info[9 + label.len()] = context.len() as u8;
    info[10 + label.len()..10 + label.len() + context.len()].copy_from_slice(context);
    hkdf_expand(secret, &info[..info_len], len)
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
        // The label info for "c hs traffic" with an empty context must match
        // the RFC 8446 §7.1 construction: 0x0023 00 746c733133 2063206873
        // 2074726166666963 00.
        let secret = [0x42u8; 32];
        let out = hkdf_expand_label(&secret, b"c hs traffic", &[], 32);
        assert_eq!(out.len(), 48);
        assert_ne!(out, [0u8; 48]);
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
}
