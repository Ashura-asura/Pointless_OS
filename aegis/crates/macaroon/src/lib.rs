use capability_core::{ObjectKind, Rights};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenObjectKind { Task, Endpoint, MemRegion, GrantRoot, Creator }

impl From<ObjectKind> for TokenObjectKind {
    fn from(k: ObjectKind) -> Self {
        match k {
            ObjectKind::Task => Self::Task,
            ObjectKind::Endpoint => Self::Endpoint,
            ObjectKind::MemRegion => Self::MemRegion,
            ObjectKind::GrantRoot => Self::GrantRoot,
            ObjectKind::Creator => Self::Creator,
        }
    }
}

impl From<TokenObjectKind> for ObjectKind {
    fn from(k: TokenObjectKind) -> Self {
        match k {
            TokenObjectKind::Task => Self::Task,
            TokenObjectKind::Endpoint => Self::Endpoint,
            TokenObjectKind::MemRegion => Self::MemRegion,
            TokenObjectKind::GrantRoot => Self::GrantRoot,
            TokenObjectKind::Creator => Self::Creator,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Caveat {
    RightsNarrow(u32),
    ExpiryClamp(u64),
    Custom(Vec<u8>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapabilityToken {
    pub kernel_id: [u8; 32],
    pub object_id: u64,
    pub kind: TokenObjectKind,
    pub rights: u32,
    pub expiry: Option<u64>,
    pub caveats: Vec<Caveat>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenChain {
    pub token: CapabilityToken,
    pub chain: Vec<[u8; 32]>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TokenError {
    SerializationError,
    DeserializationError,
    ChainIntegrityError,
    CaveatViolation(&'static str),
}

const HMAC_BLOCK: usize = 64;

fn hmac_sha256(key: &[u8], msg: &[u8]) -> [u8; 32] {
    let mut kp = [0u8; HMAC_BLOCK];
    if key.len() > HMAC_BLOCK {
        kp[..32].copy_from_slice(&object_store::sha256::sha256(key));
    } else {
        kp[..key.len()].copy_from_slice(key);
    }
    let mut ipad = [0x36u8; HMAC_BLOCK];
    let mut opad = [0x5cu8; HMAC_BLOCK];
    for i in 0..HMAC_BLOCK {
        ipad[i] ^= kp[i];
        opad[i] ^= kp[i];
    }
    let mut inner = Vec::with_capacity(HMAC_BLOCK + msg.len());
    inner.extend_from_slice(&ipad);
    inner.extend_from_slice(msg);
    let ih = object_store::sha256::sha256(&inner);
    let mut outer = Vec::with_capacity(HMAC_BLOCK + 32);
    outer.extend_from_slice(&opad);
    outer.extend_from_slice(&ih);
    object_store::sha256::sha256(&outer)
}

fn serialize_identifier(token: &CapabilityToken) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(&token.kernel_id);
    buf.extend_from_slice(&token.object_id.to_le_bytes());
    buf.push(match token.kind {
        TokenObjectKind::Task => 0,
        TokenObjectKind::Endpoint => 1,
        TokenObjectKind::MemRegion => 2,
        TokenObjectKind::GrantRoot => 3,
        TokenObjectKind::Creator => 4,
    });
    buf.extend_from_slice(&token.rights.to_le_bytes());
    match token.expiry {
        Some(e) => { buf.push(1); buf.extend_from_slice(&e.to_le_bytes()); }
        None => { buf.push(0); }
    }
    buf
}

fn serialize_caveat(c: &Caveat) -> Vec<u8> {
    let mut buf = Vec::new();
    match c {
        Caveat::RightsNarrow(r) => { buf.push(0); buf.extend_from_slice(&r.to_le_bytes()); }
        Caveat::ExpiryClamp(e) => { buf.push(1); buf.extend_from_slice(&e.to_le_bytes()); }
        Caveat::Custom(data) => {
            buf.push(2);
            buf.extend_from_slice(&(data.len() as u32).to_le_bytes());
            buf.extend_from_slice(data);
        }
    }
    buf
}

fn deserialize_caveat(data: &[u8], pos: &mut usize) -> Result<Caveat, TokenError> {
    if *pos >= data.len() { return Err(TokenError::DeserializationError); }
    let tag = data[*pos]; *pos += 1;
    match tag {
        0 => {
            if *pos + 4 > data.len() { return Err(TokenError::DeserializationError); }
            let r = u32::from_le_bytes(data[*pos..*pos+4].try_into().map_err(|_| TokenError::DeserializationError)?);
            *pos += 4;
            Ok(Caveat::RightsNarrow(r))
        }
        1 => {
            if *pos + 8 > data.len() { return Err(TokenError::DeserializationError); }
            let e = u64::from_le_bytes(data[*pos..*pos+8].try_into().map_err(|_| TokenError::DeserializationError)?);
            *pos += 8;
            Ok(Caveat::ExpiryClamp(e))
        }
        2 => {
            if *pos + 4 > data.len() { return Err(TokenError::DeserializationError); }
            let len = u32::from_le_bytes(data[*pos..*pos+4].try_into().map_err(|_| TokenError::DeserializationError)?) as usize;
            *pos += 4;
            if *pos + len > data.len() { return Err(TokenError::DeserializationError); }
            let d = data[*pos..*pos+len].to_vec();
            *pos += len;
            Ok(Caveat::Custom(d))
        }
        _ => Err(TokenError::DeserializationError),
    }
}

fn deserialize_token_full(data: &[u8]) -> Result<(CapabilityToken, usize), TokenError> {
    if data.len() < 49 { return Err(TokenError::DeserializationError); }
    let mut pos = 0;
    let mut kid = [0u8; 32];
    kid.copy_from_slice(&data[pos..pos+32]); pos += 32;
    let oid = u64::from_le_bytes(data[pos..pos+8].try_into().map_err(|_| TokenError::DeserializationError)?); pos += 8;
    let kind = match data[pos] {
        0 => TokenObjectKind::Task, 1 => TokenObjectKind::Endpoint,
        2 => TokenObjectKind::MemRegion, 3 => TokenObjectKind::GrantRoot,
        4 => TokenObjectKind::Creator, _ => return Err(TokenError::DeserializationError),
    }; pos += 1;
    let rights = u32::from_le_bytes(data[pos..pos+4].try_into().map_err(|_| TokenError::DeserializationError)?); pos += 4;
    let expiry = if data[pos] == 1 {
        pos += 1;
        let e = u64::from_le_bytes(data[pos..pos+8].try_into().map_err(|_| TokenError::DeserializationError)?); pos += 8;
        Some(e)
    } else { pos += 1; None };
    if pos + 4 > data.len() { return Err(TokenError::DeserializationError); }
    let n = u32::from_le_bytes(data[pos..pos+4].try_into().map_err(|_| TokenError::DeserializationError)?) as usize; pos += 4;
    let mut caveats = Vec::new();
    for _ in 0..n { caveats.push(deserialize_caveat(data, &mut pos)?); }
    Ok((CapabilityToken { kernel_id: kid, object_id: oid, kind, rights, expiry, caveats }, pos))
}

fn serialize_token_full(token: &CapabilityToken) -> Vec<u8> {
    let mut buf = serialize_identifier(token);
    buf.extend_from_slice(&(token.caveats.len() as u32).to_le_bytes());
    for c in &token.caveats { buf.extend_from_slice(&serialize_caveat(c)); }
    buf
}

fn compute_chain(signing_key: &[u8; 32], token: &CapabilityToken) -> Vec<[u8; 32]> {
    let mut chain = Vec::with_capacity(token.caveats.len() + 1);
    let root = hmac_sha256(signing_key, &serialize_identifier(token));
    chain.push(root);
    let mut prev = root;
    for c in &token.caveats {
        let mut msg = Vec::new();
        msg.extend_from_slice(&serialize_caveat(c));
        msg.extend_from_slice(&prev);
        let entry = hmac_sha256(signing_key, &msg);
        chain.push(entry);
        prev = entry;
    }
    chain
}

pub fn mint(
    signing_key: &[u8; 32],
    kernel_id: [u8; 32],
    object_id: u64,
    kind: ObjectKind,
    rights: Rights,
    expiry: Option<u64>,
) -> TokenChain {
    let token = CapabilityToken { kernel_id, object_id, kind: TokenObjectKind::from(kind), rights: rights.bits(), expiry, caveats: Vec::new() };
    let chain = compute_chain(signing_key, &token);
    TokenChain { token, chain }
}

pub fn bind_caveat(signing_key: &[u8; 32], chain: &TokenChain, caveat: Caveat) -> TokenChain {
    let mut new_token = chain.token.clone();
    if let Caveat::RightsNarrow(mask) = &caveat {
        new_token.rights &= mask;
    }
    if let Caveat::ExpiryClamp(e) = &caveat {
        new_token.expiry = Some(match new_token.expiry { Some(c) => c.min(*e), None => *e });
    }
    new_token.caveats.push(caveat);
    let new_chain = compute_chain(signing_key, &new_token);
    TokenChain { token: new_token, chain: new_chain }
}

fn ct_eq(a: &[u8; 32], b: &[u8; 32]) -> bool {
    let mut diff = 0u8;
    for i in 0..32 {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

pub fn verify(signing_key: &[u8; 32], chain: &TokenChain) -> Result<(), TokenError> {
    let expected = compute_chain(signing_key, &chain.token);
    if chain.chain.len() != expected.len() { return Err(TokenError::ChainIntegrityError); }
    for (a, b) in chain.chain.iter().zip(expected.iter()) {
        if !ct_eq(a, b) { return Err(TokenError::ChainIntegrityError); }
    }
    Ok(())
}

pub fn serialize_chain(chain: &TokenChain) -> Vec<u8> {
    let mut buf = Vec::new();
    let tb = serialize_token_full(&chain.token);
    buf.extend_from_slice(&(tb.len() as u32).to_le_bytes());
    buf.extend_from_slice(&tb);
    buf.extend_from_slice(&(chain.chain.len() as u32).to_le_bytes());
    for e in &chain.chain { buf.extend_from_slice(e); }
    buf
}

pub fn deserialize_chain(data: &[u8]) -> Result<TokenChain, TokenError> {
    if data.len() < 8 { return Err(TokenError::DeserializationError); }
    let mut pos = 0;
    let tl = u32::from_le_bytes(data[pos..pos+4].try_into().map_err(|_| TokenError::DeserializationError)?) as usize; pos += 4;
    if pos + tl > data.len() { return Err(TokenError::DeserializationError); }
    let (token, _) = deserialize_token_full(&data[pos..pos+tl])?; pos += tl;
    if pos + 4 > data.len() { return Err(TokenError::DeserializationError); }
    let cl = u32::from_le_bytes(data[pos..pos+4].try_into().map_err(|_| TokenError::DeserializationError)?) as usize; pos += 4;
    if pos + cl * 32 > data.len() { return Err(TokenError::DeserializationError); }
    let mut entries = Vec::new();
    for _ in 0..cl {
        let mut e = [0u8; 32]; e.copy_from_slice(&data[pos..pos+32]); entries.push(e); pos += 32;
    }
    Ok(TokenChain { token, chain: entries })
}
