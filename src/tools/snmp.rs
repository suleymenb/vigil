//! `vigil snmp HOST`: look at a switch, router or firewall from the outside.
//!
//! A small SNMP client: BER encoding, GET / GETBULK, SNMPv2c and SNMPv3 with
//! USM (RFC 3414: HMAC-MD5-96 / HMAC-SHA-96, RFC 7860: HMAC-SHA-256-192;
//! RFC 3826: AES-128-CFB privacy). The device report polls interfaces twice
//! to get rates, and flags what a network engineer looks for first: ports
//! that are admin-up but down, CRC/FCS errors, errors and discards rising,
//! saturated links, half duplex, recent flaps, high CPU, and shows the LLDP
//! neighbours (which device is on which port).

use std::collections::{BTreeMap, HashMap};
use std::net::{SocketAddr, ToSocketAddrs, UdpSocket};
use std::time::{Duration, Instant};

use super::Tone;

// ───────────────────────────── BER ─────────────────────────────

#[derive(Clone, Debug, PartialEq)]
pub enum Value {
    Int(i64),
    Str(Vec<u8>),
    Null,
    Oid(Vec<u32>),
    Ip([u8; 4]),
    Counter(u64),
    Gauge(u64),
    Ticks(u64),
    Counter64(u64),
    NoSuch,
    EndOfMib,
    Other(u8, Vec<u8>),
}

impl Value {
    pub fn as_u64(&self) -> Option<u64> {
        match self {
            Value::Int(i) if *i >= 0 => Some(*i as u64),
            Value::Counter(v) | Value::Gauge(v) | Value::Ticks(v) | Value::Counter64(v) => Some(*v),
            _ => None,
        }
    }
    pub fn text(&self) -> String {
        match self {
            Value::Str(b) => String::from_utf8_lossy(b).trim_matches(char::from(0)).trim().to_string(),
            Value::Int(i) => i.to_string(),
            Value::Ip(a) => format!("{}.{}.{}.{}", a[0], a[1], a[2], a[3]),
            Value::Oid(o) => oid_str(o),
            v => v.as_u64().map(|n| n.to_string()).unwrap_or_default(),
        }
    }
}

pub fn oid(s: &str) -> Vec<u32> {
    s.trim_start_matches('.').split('.').filter_map(|p| p.parse().ok()).collect()
}

pub fn oid_str(o: &[u32]) -> String {
    o.iter().map(|n| n.to_string()).collect::<Vec<_>>().join(".")
}

fn push_len(out: &mut Vec<u8>, n: usize) {
    if n < 0x80 {
        out.push(n as u8);
    } else {
        let bytes: Vec<u8> = n.to_be_bytes().iter().copied().skip_while(|b| *b == 0).collect();
        out.push(0x80 | bytes.len() as u8);
        out.extend(bytes);
    }
}

fn tlv(tag: u8, body: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    push_len(&mut out, body.len());
    out.extend_from_slice(body);
    out
}

fn int(v: i64) -> Vec<u8> {
    let mut b = v.to_be_bytes().to_vec();
    while b.len() > 1 && ((b[0] == 0 && b[1] & 0x80 == 0) || (b[0] == 0xff && b[1] & 0x80 != 0)) {
        b.remove(0);
    }
    tlv(0x02, &b)
}

fn octets(b: &[u8]) -> Vec<u8> {
    tlv(0x04, b)
}

fn seq(parts: &[Vec<u8>]) -> Vec<u8> {
    tlv(0x30, &parts.concat())
}

fn enc_oid(o: &[u32]) -> Vec<u8> {
    let mut b = Vec::new();
    if o.len() >= 2 {
        b.push((o[0] * 40 + o[1]) as u8);
    }
    for &n in o.iter().skip(2) {
        let mut tmp = vec![(n & 0x7f) as u8];
        let mut v = n >> 7;
        while v > 0 {
            tmp.push(0x80 | (v & 0x7f) as u8);
            v >>= 7;
        }
        tmp.reverse();
        b.extend(tmp);
    }
    tlv(0x06, &b)
}

/// Read one TLV at `pos`: (tag, body range, next position).
fn read_tlv(b: &[u8], pos: usize) -> Result<(u8, std::ops::Range<usize>, usize), String> {
    let tag = *b.get(pos).ok_or("truncated BER")?;
    let l0 = *b.get(pos + 1).ok_or("truncated BER length")? as usize;
    let (len, start) = if l0 < 0x80 {
        (l0, pos + 2)
    } else {
        let n = l0 & 0x7f;
        if n == 0 || n > 4 {
            return Err("unsupported BER length".into());
        }
        let mut len = 0usize;
        for i in 0..n {
            len = (len << 8) | *b.get(pos + 2 + i).ok_or("truncated BER length")? as usize;
        }
        (len, pos + 2 + n)
    };
    if start + len > b.len() {
        return Err("truncated BER value".into());
    }
    Ok((tag, start..start + len, start + len))
}

fn dec_uint(b: &[u8]) -> u64 {
    b.iter().fold(0u64, |a, x| (a << 8) | *x as u64)
}

fn dec_int(b: &[u8]) -> i64 {
    if b.is_empty() {
        return 0;
    }
    let mut v: i64 = if b[0] & 0x80 != 0 { -1 } else { 0 };
    for x in b {
        v = (v << 8) | *x as i64;
    }
    v
}

fn dec_oid(b: &[u8]) -> Vec<u32> {
    let mut o = Vec::new();
    if let Some(&f) = b.first() {
        o.push((f / 40) as u32);
        o.push((f % 40) as u32);
    }
    let mut v: u32 = 0;
    for &x in b.iter().skip(1) {
        v = (v << 7) | (x & 0x7f) as u32;
        if x & 0x80 == 0 {
            o.push(v);
            v = 0;
        }
    }
    o
}

fn dec_value(tag: u8, b: &[u8]) -> Value {
    match tag {
        0x02 => Value::Int(dec_int(b)),
        0x04 => Value::Str(b.to_vec()),
        0x05 => Value::Null,
        0x06 => Value::Oid(dec_oid(b)),
        0x40 if b.len() == 4 => Value::Ip([b[0], b[1], b[2], b[3]]),
        0x41 => Value::Counter(dec_uint(b)),
        0x42 => Value::Gauge(dec_uint(b)),
        0x43 => Value::Ticks(dec_uint(b)),
        0x46 => Value::Counter64(dec_uint(b)),
        0x80 | 0x81 => Value::NoSuch,
        0x82 => Value::EndOfMib,
        t => Value::Other(t, b.to_vec()),
    }
}

/// A PDU: (tag, request id, error status, error index, varbinds).
pub type Varbinds = Vec<(Vec<u32>, Value)>;

fn enc_pdu(tag: u8, req_id: i32, a: i64, b: i64, oids: &[Vec<u32>]) -> Vec<u8> {
    let vbs: Vec<Vec<u8>> = oids.iter().map(|o| seq(&[enc_oid(o), tlv(0x05, &[])])).collect();
    tlv(tag, &[int(req_id as i64), int(a), int(b), seq(&vbs)].concat())
}

fn dec_pdu(b: &[u8]) -> Result<(u8, i32, i64, i64, Varbinds), String> {
    let (tag, body, _) = read_tlv(b, 0)?;
    let mut p = body.start;
    let mut ints = [0i64; 3];
    for v in ints.iter_mut() {
        let (_, r, n) = read_tlv(b, p)?;
        *v = dec_int(&b[r]);
        p = n;
    }
    let (_, list, _) = read_tlv(b, p)?;
    let mut vbs = Vec::new();
    let mut q = list.start;
    while q < list.end {
        let (_, vb, n) = read_tlv(b, q)?;
        let (_, o, after) = read_tlv(b, vb.start)?;
        let (vt, vr, _) = read_tlv(b, after)?;
        vbs.push((dec_oid(&b[o]), dec_value(vt, &b[vr])));
        q = n;
    }
    Ok((tag, ints[0] as i32, ints[1], ints[2], vbs))
}

// ───────────────────────────── USM (SNMPv3) ─────────────────────────────

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum AuthProto {
    Md5,
    Sha1,
    Sha256,
}

impl AuthProto {
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().replace(['-', '_'], "").as_str() {
            "md5" => Some(AuthProto::Md5),
            "sha" | "sha1" => Some(AuthProto::Sha1),
            "sha256" => Some(AuthProto::Sha256),
            _ => None,
        }
    }
    /// Bytes of the HMAC carried in msgAuthenticationParameters.
    fn mac_len(self) -> usize {
        match self {
            AuthProto::Md5 | AuthProto::Sha1 => 12,
            AuthProto::Sha256 => 24,
        }
    }
    fn hash(self, data: &[u8]) -> Vec<u8> {
        use sha2::Digest;
        match self {
            AuthProto::Md5 => md5::Md5::digest(data).to_vec(),
            AuthProto::Sha1 => sha1::Sha1::digest(data).to_vec(),
            AuthProto::Sha256 => sha2::Sha256::digest(data).to_vec(),
        }
    }
    fn hmac(self, key: &[u8], data: &[u8]) -> Vec<u8> {
        use hmac::{Hmac, Mac};
        match self {
            AuthProto::Md5 => {
                let mut m = Hmac::<md5::Md5>::new_from_slice(key).expect("hmac key");
                m.update(data);
                m.finalize().into_bytes().to_vec()
            }
            AuthProto::Sha1 => {
                let mut m = Hmac::<sha1::Sha1>::new_from_slice(key).expect("hmac key");
                m.update(data);
                m.finalize().into_bytes().to_vec()
            }
            AuthProto::Sha256 => {
                let mut m = Hmac::<sha2::Sha256>::new_from_slice(key).expect("hmac key");
                m.update(data);
                m.finalize().into_bytes().to_vec()
            }
        }
    }
}

/// RFC 3414 A.2: password → localized key for one engine.
pub fn localize_key(proto: AuthProto, password: &str, engine_id: &[u8]) -> Vec<u8> {
    let p = password.as_bytes();
    let mut buf = Vec::with_capacity(1_048_576);
    if !p.is_empty() {
        while buf.len() < 1_048_576 {
            let take = (1_048_576 - buf.len()).min(p.len());
            buf.extend_from_slice(&p[..take]);
        }
    }
    let ku = proto.hash(&buf);
    let mut l = ku.clone();
    l.extend_from_slice(engine_id);
    l.extend_from_slice(&ku);
    proto.hash(&l)
}

fn aes_cfb(key: &[u8], iv: &[u8; 16], data: &mut [u8], encrypt: bool) {
    use cfb_mode::cipher::{AsyncStreamCipher, KeyIvInit};
    if encrypt {
        cfb_mode::Encryptor::<aes::Aes128>::new(key[..16].into(), iv.into()).encrypt(data);
    } else {
        cfb_mode::Decryptor::<aes::Aes128>::new(key[..16].into(), iv.into()).decrypt(data);
    }
}

// ───────────────────────────── client ─────────────────────────────

#[derive(Clone, Debug)]
pub enum Auth {
    V2c { community: String },
    V3 { user: String, auth: Option<(AuthProto, String)>, privacy: Option<String> },
}

struct V3State {
    engine_id: Vec<u8>,
    boots: i64,
    time: i64,
    at: Instant,
    auth_key: Vec<u8>,
    priv_key: Vec<u8>,
}

pub struct Client {
    sock: UdpSocket,
    target: SocketAddr,
    auth: Auth,
    timeout: Duration,
    req: i32,
    v3: Option<V3State>,
    salt: u64,
}

impl Client {
    pub fn connect(host: &str, port: u16, auth: Auth, timeout: Duration) -> Result<Self, String> {
        let target = (host, port).to_socket_addrs().map_err(|e| format!("{host}: {e}"))?.next().ok_or_else(|| format!("{host}: no address"))?;
        let bind: SocketAddr = if target.is_ipv6() { "[::]:0".parse().unwrap() } else { "0.0.0.0:0".parse().unwrap() };
        let sock = UdpSocket::bind(bind).map_err(|e| e.to_string())?;
        sock.set_read_timeout(Some(timeout)).map_err(|e| e.to_string())?;
        let seed = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_nanos() as u64).unwrap_or(1);
        let mut c = Client { sock, target, auth, timeout, req: (seed & 0x3fff_ffff) as i32, v3: None, salt: seed ^ 0x5bd1_e995 };
        if matches!(c.auth, Auth::V3 { .. }) {
            c.discover()?;
        }
        Ok(c)
    }

    fn next_id(&mut self) -> i32 {
        self.req = self.req.wrapping_add(1) & 0x7fff_ffff;
        self.req
    }

    fn exchange(&mut self, msg: &[u8], expect: i32) -> Result<Vec<u8>, String> {
        let mut buf = vec![0u8; 65_535];
        for _attempt in 0..2 {
            self.sock.send_to(msg, self.target).map_err(|e| e.to_string())?;
            let deadline = Instant::now() + self.timeout;
            while Instant::now() < deadline {
                match self.sock.recv_from(&mut buf) {
                    Ok((n, from)) if from.ip() == self.target.ip() => {
                        let reply = buf[..n].to_vec();
                        // v3 agents answer problems (wrong password, unknown user…) with an
                        // unauthenticated Report that may not echo our request id.
                        if expect < 0 || self.peek_id(&reply) == Some(expect) || self.is_v3_report(&reply) {
                            return Ok(reply);
                        }
                    }
                    Ok(_) => continue,
                    Err(e) if matches!(e.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut) => break,
                    Err(e) if e.kind() == std::io::ErrorKind::ConnectionReset => return Err("ICMP port unreachable: nothing listens on UDP 161 (SNMP disabled?)".into()),
                    Err(e) => return Err(e.to_string()),
                }
            }
        }
        Err(match &self.auth {
            Auth::V2c { .. } => "no answer: wrong community, SNMP not enabled for this source, or UDP 161 filtered".into(),
            Auth::V3 { .. } => "no answer: SNMPv3 not enabled for this user/source, or UDP 161 filtered".into(),
        })
    }

    /// Best-effort request id of a reply (for v3 the PDU may be encrypted: None).
    fn peek_id(&self, b: &[u8]) -> Option<i32> {
        let (_, body, _) = read_tlv(b, 0).ok()?;
        let (_, v, mut p) = read_tlv(b, body.start).ok()?;
        if dec_int(&b[v]) == 3 {
            return self.v3_reply_id(b);
        }
        let (_, _, n) = read_tlv(b, p).ok()?; // community
        p = n;
        let (_, pdu, _) = read_tlv(b, p).ok()?;
        let (_, rid, _) = read_tlv(b, pdu.start).ok()?;
        Some(dec_int(&b[rid]) as i32)
    }

    fn is_v3_report(&self, b: &[u8]) -> bool {
        self.v3.is_some() && self.decode_v3(b).map(|r| r.0 == 0xa8).unwrap_or(false)
    }

    fn v3_reply_id(&self, b: &[u8]) -> Option<i32> {
        self.decode_v3(b).ok().map(|(_, id, _, _, _)| id)
    }

    fn request(&mut self, tag: u8, a: i64, bb: i64, oids: &[Vec<u32>]) -> Result<Varbinds, String> {
        let id = self.next_id();
        let pdu = enc_pdu(tag, id, a, bb, oids);
        let msg = match self.auth.clone() {
            Auth::V2c { community } => seq(&[int(1), octets(community.as_bytes()), pdu]),
            Auth::V3 { .. } => self.encode_v3(&pdu, id)?,
        };
        let reply = self.exchange(&msg, id)?;
        let (rtag, rid, status, index, vbs) = match self.auth {
            Auth::V2c { .. } => {
                let (_, body, _) = read_tlv(&reply, 0)?;
                let (_, _, p) = read_tlv(&reply, body.start)?;
                let (_, _, p) = read_tlv(&reply, p)?;
                dec_pdu(&reply[p..])?
            }
            Auth::V3 { .. } => self.decode_v3(&reply)?,
        };
        if rtag == 0xa8 {
            let what = vbs.first().map(|(o, _)| oid_str(o)).unwrap_or_default();
            return Err(report_reason(&what));
        }
        if rid != id {
            return Err("reply for another request".into());
        }
        if status != 0 {
            return Err(format!("agent error {} ({}) at varbind {index}", status, error_name(status)));
        }
        Ok(vbs)
    }

    pub fn get(&mut self, oids: &[Vec<u32>]) -> Result<Varbinds, String> {
        self.request(0xa0, 0, 0, oids)
    }

    /// All varbinds under `root` (GETBULK, 25 at a time, at most 10 000).
    pub fn walk(&mut self, root: &[u32]) -> Result<Varbinds, String> {
        let mut out = Vec::new();
        let mut cur = root.to_vec();
        while out.len() < 10_000 {
            let vbs = self.request(0xa5, 0, 25, std::slice::from_ref(&cur))?;
            if vbs.is_empty() {
                break;
            }
            let mut done = false;
            for (o, v) in vbs {
                if !o.starts_with(root) || matches!(v, Value::EndOfMib) || o <= cur {
                    done = true;
                    break;
                }
                cur = o.clone();
                out.push((o, v));
            }
            if done {
                break;
            }
        }
        Ok(out)
    }

    // ── SNMPv3 ──

    fn discover(&mut self) -> Result<(), String> {
        let id = self.next_id();
        let usm = seq(&[octets(&[]), int(0), int(0), octets(&[]), octets(&[]), octets(&[])]);
        let scoped = seq(&[octets(&[]), octets(&[]), enc_pdu(0xa0, id, 0, 0, &[])]);
        let msg = seq(&[int(3), seq(&[int(id as i64), int(65_507), octets(&[0x04]), int(3)]), octets(&usm), scoped]);
        let reply = self.exchange(&msg, -1)?;
        let (engine, boots, time) = parse_usm_header(&reply)?;
        if engine.is_empty() {
            return Err("agent did not reveal its engine ID".into());
        }
        let Auth::V3 { auth, privacy, .. } = &self.auth else { unreachable!() };
        let (auth_key, priv_key) = match auth {
            Some((p, pass)) => (localize_key(*p, pass, &engine), privacy.as_ref().map(|pp| localize_key(*p, pp, &engine)).unwrap_or_default()),
            None => (Vec::new(), Vec::new()),
        };
        self.v3 = Some(V3State { engine_id: engine, boots, time, at: Instant::now(), auth_key, priv_key });
        Ok(())
    }

    fn encode_v3(&mut self, pdu: &[u8], id: i32) -> Result<Vec<u8>, String> {
        let Auth::V3 { user, auth, privacy } = self.auth.clone() else { unreachable!() };
        let st = self.v3.as_ref().ok_or("SNMPv3 engine not discovered")?;
        let time = st.time + st.at.elapsed().as_secs() as i64;
        let flags = 0x04 | if auth.is_some() { 0x01 } else { 0 } | if privacy.is_some() && auth.is_some() { 0x02 } else { 0 };
        let scoped = seq(&[octets(&st.engine_id), octets(&[]), pdu.to_vec()]);
        let (data, salt) = if flags & 0x02 != 0 {
            self.salt = self.salt.wrapping_add(1);
            let salt = self.salt.to_be_bytes();
            let mut iv = [0u8; 16];
            iv[..4].copy_from_slice(&(st.boots as u32).to_be_bytes());
            iv[4..8].copy_from_slice(&(time as u32).to_be_bytes());
            iv[8..].copy_from_slice(&salt);
            let mut enc = scoped.clone();
            aes_cfb(&st.priv_key, &iv, &mut enc, true);
            (octets(&enc), salt.to_vec())
        } else {
            (scoped, Vec::new())
        };
        let mac_len = auth.as_ref().map(|(p, _)| p.mac_len()).unwrap_or(0);
        let usm = |mac: &[u8]| seq(&[octets(&st.engine_id), int(st.boots), int(time), octets(user.as_bytes()), octets(mac), octets(&salt)]);
        let build = |mac: &[u8]| seq(&[int(3), seq(&[int(id as i64), int(65_507), octets(&[flags]), int(3)]), octets(&usm(mac)), data.clone()]);
        let zeros = vec![0u8; mac_len];
        let mut msg = build(&zeros);
        if let Some((p, _)) = auth {
            // Locate the placeholder exactly: inside the USM parameters, right
            // after engine ID, boots, time and user name (+ its 2-byte header).
            let usm_b = usm(&zeros);
            let prefix = [octets(&st.engine_id), int(st.boots), int(time), octets(user.as_bytes())].concat().len();
            let usm_hdr = usm_b.len() - (prefix + 2 + mac_len + octets(&salt).len());
            let at = find(&msg, &usm_b).ok_or("internal: USM parameters not found")? + usm_hdr + prefix + 2;
            let mac = p.hmac(&st.auth_key, &msg);
            msg[at..at + mac_len].copy_from_slice(&mac[..mac_len]);
        }
        Ok(msg)
    }

    fn decode_v3(&self, b: &[u8]) -> Result<(u8, i32, i64, i64, Varbinds), String> {
        let (_, body, _) = read_tlv(b, 0)?;
        let (_, _, p) = read_tlv(b, body.start)?; // version
        let (_, hdr, p2) = read_tlv(b, p)?;
        let (_, _, q) = read_tlv(b, hdr.start)?; // msgID
        let (_, _, q) = read_tlv(b, q)?; // max size
        let (_, fl, _) = read_tlv(b, q)?;
        let flags = b[fl].first().copied().unwrap_or(0);
        let (_, sec, p3) = read_tlv(b, p2)?;
        let usm = &b[sec.clone()];
        let fields = usm_fields(usm)?;
        let st = self.v3.as_ref();
        if flags & 0x01 != 0 {
            if let (Some(st), Auth::V3 { auth: Some((proto, _)), .. }) = (st, &self.auth) {
                let mac = &fields.4;
                let mut copy = b.to_vec();
                let at = sec.start + find(usm, mac).ok_or("bad auth parameters")?;
                for x in &mut copy[at..at + mac.len()] {
                    *x = 0;
                }
                let want = proto.hmac(&st.auth_key, &copy);
                if want[..mac.len()] != mac[..] {
                    return Err("reply failed authentication (wrong auth password?)".into());
                }
            }
        }
        let scoped: Vec<u8> = if flags & 0x02 != 0 {
            let st = st.ok_or("encrypted reply before discovery")?;
            let (_, enc, _) = read_tlv(b, p3)?;
            let mut data = b[enc].to_vec();
            let salt = &fields.5;
            if salt.len() != 8 {
                return Err("bad privacy parameters".into());
            }
            let mut iv = [0u8; 16];
            iv[..4].copy_from_slice(&(fields.1 as u32).to_be_bytes());
            iv[4..8].copy_from_slice(&(fields.2 as u32).to_be_bytes());
            iv[8..].copy_from_slice(salt);
            aes_cfb(&st.priv_key, &iv, &mut data, false);
            data
        } else {
            let (_, _, end) = read_tlv(b, p3)?;
            b[p3..end].to_vec()
        };
        let (_, sb, _) = read_tlv(&scoped, 0).map_err(|_| "could not decrypt the reply (wrong privacy password?)".to_string())?;
        let (_, _, r) = read_tlv(&scoped, sb.start)?; // contextEngineID
        let (_, _, r) = read_tlv(&scoped, r)?; // contextName
        dec_pdu(&scoped[r..])
    }
}

fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() {
        return None;
    }
    hay.windows(needle.len()).position(|w| w == needle)
}

/// UsmSecurityParameters: (engineID, boots, time, user, authParams, privParams).
type UsmFields = (Vec<u8>, i64, i64, Vec<u8>, Vec<u8>, Vec<u8>);

fn usm_fields(usm: &[u8]) -> Result<UsmFields, String> {
    let (_, body, _) = read_tlv(usm, 0)?;
    let mut p = body.start;
    let mut parts: Vec<Vec<u8>> = Vec::new();
    for _ in 0..6 {
        let (_, r, n) = read_tlv(usm, p)?;
        parts.push(usm[r].to_vec());
        p = n;
    }
    Ok((parts[0].clone(), dec_int(&parts[1]), dec_int(&parts[2]), parts[3].clone(), parts[4].clone(), parts[5].clone()))
}

fn parse_usm_header(b: &[u8]) -> Result<(Vec<u8>, i64, i64), String> {
    let (_, body, _) = read_tlv(b, 0)?;
    let (_, v, p) = read_tlv(b, body.start)?;
    if dec_int(&b[v]) != 3 {
        return Err("agent answered, but not with SNMPv3".into());
    }
    let (_, _, p) = read_tlv(b, p)?;
    let (_, sec, _) = read_tlv(b, p)?;
    let f = usm_fields(&b[sec])?;
    Ok((f.0, f.1, f.2))
}

fn report_reason(oid: &str) -> String {
    let why = match oid {
        o if o.starts_with("1.3.6.1.6.3.15.1.1.3") => "unknown user name",
        o if o.starts_with("1.3.6.1.6.3.15.1.1.5") => "wrong authentication password or protocol",
        o if o.starts_with("1.3.6.1.6.3.15.1.1.6") => "wrong privacy password (decryption failed on the agent)",
        o if o.starts_with("1.3.6.1.6.3.15.1.1.1") => "security level not supported for this user (auth/priv mismatch)",
        o if o.starts_with("1.3.6.1.6.3.15.1.1.2") => "message outside the time window (clock / engine boots)",
        o if o.starts_with("1.3.6.1.6.3.15.1.1.4") => "unknown engine ID",
        _ => "agent rejected the request",
    };
    format!("SNMPv3: {why} ({oid})")
}

fn error_name(e: i64) -> &'static str {
    match e {
        1 => "tooBig",
        2 => "noSuchName",
        5 => "genErr",
        6 => "noAccess",
        16 => "authorizationError",
        _ => "error",
    }
}

// ───────────────────────────── device report ─────────────────────────────

const SYS: &str = "1.3.6.1.2.1.1";
const IF_DESCR: &str = "1.3.6.1.2.1.2.2.1.2";
const IF_ADMIN: &str = "1.3.6.1.2.1.2.2.1.7";
const IF_OPER: &str = "1.3.6.1.2.1.2.2.1.8";
const IF_LASTCHANGE: &str = "1.3.6.1.2.1.2.2.1.9";
const IF_IN_DISCARDS: &str = "1.3.6.1.2.1.2.2.1.13";
const IF_IN_ERRORS: &str = "1.3.6.1.2.1.2.2.1.14";
const IF_OUT_DISCARDS: &str = "1.3.6.1.2.1.2.2.1.19";
const IF_OUT_ERRORS: &str = "1.3.6.1.2.1.2.2.1.20";
const IF_NAME: &str = "1.3.6.1.2.1.31.1.1.1.1";
const IF_HC_IN: &str = "1.3.6.1.2.1.31.1.1.1.6";
const IF_HC_OUT: &str = "1.3.6.1.2.1.31.1.1.1.10";
const IF_HIGHSPEED: &str = "1.3.6.1.2.1.31.1.1.1.15";
const IF_ALIAS: &str = "1.3.6.1.2.1.31.1.1.1.18";
const DOT3_FCS: &str = "1.3.6.1.2.1.10.7.2.1.3";
const DOT3_DUPLEX: &str = "1.3.6.1.2.1.10.7.2.1.19";
const LLDP_LOC_PORT_ID: &str = "1.0.8802.1.1.2.1.3.7.1.3";
const LLDP_REM_PORT_ID: &str = "1.0.8802.1.1.2.1.4.1.1.7";
const LLDP_REM_PORT_DESC: &str = "1.0.8802.1.1.2.1.4.1.1.8";
const LLDP_REM_SYS_NAME: &str = "1.0.8802.1.1.2.1.4.1.1.9";
const JNX_CPU: &str = "1.3.6.1.4.1.2636.3.1.13.1.8";
const JNX_MEM: &str = "1.3.6.1.4.1.2636.3.1.13.1.11";
const CISCO_CPU: &str = "1.3.6.1.4.1.9.9.109.1.1.1.1.8";
const HR_CPU: &str = "1.3.6.1.2.1.25.3.3.1.2";

#[derive(Clone, Debug, Default)]
pub struct Iface {
    pub name: String,
    pub alias: String,
    pub admin_up: bool,
    pub oper_up: bool,
    pub speed_mbps: u64,
    pub in_octets: u64,
    pub out_octets: u64,
    pub in_errors: u64,
    pub out_errors: u64,
    pub in_discards: u64,
    pub out_discards: u64,
    pub fcs: Option<u64>,
    pub duplex: Option<u8>,
    pub last_change: u64,
    // rates over the sampling window
    pub in_bps: f64,
    pub out_bps: f64,
    pub err_rate: f64,
    pub discard_rate: f64,
    pub fcs_delta: u64,
}

impl Iface {
    pub fn util_pct(&self) -> Option<f64> {
        (self.speed_mbps > 0).then(|| self.in_bps.max(self.out_bps) / (self.speed_mbps as f64 * 1e6) * 100.0)
    }
}

fn last_index(o: &[u32]) -> u32 {
    *o.last().unwrap_or(&0)
}

fn column(c: &mut Client, base: &str) -> HashMap<u32, Value> {
    c.walk(&oid(base)).unwrap_or_default().into_iter().map(|(o, v)| (last_index(&o), v)).collect()
}

fn poll_counters(c: &mut Client, ifs: &mut BTreeMap<u32, Iface>) {
    for (col, f) in [
        (IF_HC_IN, 0usize),
        (IF_HC_OUT, 1),
        (IF_IN_ERRORS, 2),
        (IF_OUT_ERRORS, 3),
        (IF_IN_DISCARDS, 4),
        (IF_OUT_DISCARDS, 5),
        (DOT3_FCS, 6),
    ] {
        for (i, v) in column(c, col) {
            if let (Some(x), Some(n)) = (ifs.get_mut(&i), v.as_u64()) {
                match f {
                    0 => x.in_octets = n,
                    1 => x.out_octets = n,
                    2 => x.in_errors = n,
                    3 => x.out_errors = n,
                    4 => x.in_discards = n,
                    5 => x.out_discards = n,
                    _ => x.fcs = Some(n),
                }
            }
        }
    }
}

fn ticks_ago(now: u64, then: u64) -> String {
    if then == 0 || then > now {
        return "·".into();
    }
    let s = (now - then) / 100;
    match s {
        0..=59 => format!("{s}s ago"),
        60..=3599 => format!("{}m ago", s / 60),
        3600..=86_399 => format!("{}h ago", s / 3600),
        _ => format!("{}d ago", s / 86_400),
    }
}

fn bps(v: f64) -> String {
    if v >= 1e9 {
        format!("{:.2}G", v / 1e9)
    } else if v >= 1e6 {
        format!("{:.1}M", v / 1e6)
    } else if v >= 1e3 {
        format!("{:.0}k", v / 1e3)
    } else {
        format!("{v:.0}")
    }
}

/// Is this a logical / internal interface we hide unless `--all`?
fn noisy(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    ["lo", "lsi", "dsc", "gre", "ipip", "pime", "pimd", "mtun", "tap", "pp0", "gr-", "ip-", "lt-", "mt-", "sp-", "vt-", "jsrv", "em", "fxp", "bme", "jsv", ".16384", ".16385", ".32767", "null", "nve", "esi", "vtep", "irb", "pfe", "pfh", "cbp", "demux", "lc-", "pc-", "fti", "rbeb", "sxe"]
        .iter()
        .any(|p| n.starts_with(p) || n.contains(p) && p.starts_with('.'))
}

/// Poll a device and print the report. `interval` is the sampling window.
pub fn report(host: &str, port: u16, auth: Auth, interval: Duration, all: bool, emit: &dyn Fn(Tone, String)) -> Result<Vec<String>, String> {
    let ver = if matches!(auth, Auth::V2c { .. }) { "v2c" } else { "v3" };
    let mut c = Client::connect(host, port, auth, Duration::from_secs(2))?;
    let sys = c.get(&[oid(&format!("{SYS}.1.0")), oid(&format!("{SYS}.3.0")), oid(&format!("{SYS}.5.0")), oid(&format!("{SYS}.6.0"))])?;
    let get = |i: usize| sys.get(i).map(|v| v.1.clone()).unwrap_or(Value::Null);
    let uptime = get(1).as_u64().unwrap_or(0);
    let descr = get(0).text().lines().next().unwrap_or("").to_string();
    emit(Tone::Head, format!("{} · {} · SNMP{ver} · up {}", get(2).text(), descr, crate::util::fmt_duration(uptime / 100)));
    if !get(3).text().is_empty() {
        emit(Tone::Dim, format!("  location: {}", get(3).text()));
    }
    let mut findings: Vec<String> = Vec::new();

    // CPU: Juniper, Cisco, then HOST-RESOURCES.
    let cpu = [(JNX_CPU, "Routing Engine"), (CISCO_CPU, "5-min"), (HR_CPU, "average")].iter().find_map(|(base, label)| {
        let v: Vec<u64> = column(&mut c, base).values().filter_map(Value::as_u64).filter(|v| *v <= 100).collect();
        let v: Vec<u64> = if *base == JNX_CPU { v.into_iter().filter(|x| *x > 0).collect() } else { v };
        (!v.is_empty()).then(|| (if *base == HR_CPU { v.iter().sum::<u64>() / v.len() as u64 } else { *v.iter().max().unwrap() }, *label))
    });
    if let Some((pct, label)) = cpu {
        let mem = column(&mut c, JNX_MEM).values().filter_map(Value::as_u64).filter(|v| *v > 0 && *v <= 100).max();
        emit(
            if pct >= 80 { Tone::Bad } else if pct >= 50 { Tone::Warn } else { Tone::Normal },
            format!("  CPU {pct} % ({label}){}", mem.map(|m| format!(" · memory {m} %")).unwrap_or_default()),
        );
        if pct >= 80 {
            findings.push(format!("CPU at {pct} %: control-plane busy (routing churn, a broadcast storm, or SNMP/SSH polling itself)"));
        }
    }

    // Interfaces: names, state, speed, then counters twice for rates.
    let mut ifs: BTreeMap<u32, Iface> = BTreeMap::new();
    let mut names = column(&mut c, IF_NAME);
    if names.is_empty() {
        names = column(&mut c, IF_DESCR);
    }
    for (i, v) in &names {
        ifs.insert(*i, Iface { name: v.text(), ..Default::default() });
    }
    if ifs.is_empty() {
        return Err("the agent returned no interfaces (view restricted for this community/user?)".into());
    }
    for (col, f) in [(IF_ALIAS, 0), (IF_ADMIN, 1), (IF_OPER, 2), (IF_HIGHSPEED, 3), (IF_LASTCHANGE, 4), (DOT3_DUPLEX, 5)] {
        for (i, v) in column(&mut c, col) {
            if let Some(x) = ifs.get_mut(&i) {
                match f {
                    0 => x.alias = v.text(),
                    1 => x.admin_up = v.as_u64() == Some(1),
                    2 => x.oper_up = v.as_u64() == Some(1),
                    3 => x.speed_mbps = v.as_u64().unwrap_or(0),
                    4 => x.last_change = v.as_u64().unwrap_or(0),
                    _ => x.duplex = v.as_u64().map(|d| d as u8),
                }
            }
        }
    }
    poll_counters(&mut c, &mut ifs);
    let before: BTreeMap<u32, Iface> = ifs.clone();
    let t0 = Instant::now();
    emit(Tone::Dim, format!("  sampling counters for {} s…", interval.as_secs()));
    std::thread::sleep(interval);
    poll_counters(&mut c, &mut ifs);
    let dt = t0.elapsed().as_secs_f64().max(0.5);
    let d = |a: u64, b: u64| a.saturating_sub(b) as f64;
    for (i, x) in ifs.iter_mut() {
        let b = &before[i];
        x.in_bps = d(x.in_octets, b.in_octets) * 8.0 / dt;
        x.out_bps = d(x.out_octets, b.out_octets) * 8.0 / dt;
        x.err_rate = (d(x.in_errors, b.in_errors) + d(x.out_errors, b.out_errors)) / dt;
        x.discard_rate = (d(x.in_discards, b.in_discards) + d(x.out_discards, b.out_discards)) / dt;
        x.fcs_delta = x.fcs.unwrap_or(0).saturating_sub(b.fcs.unwrap_or(0));
    }

    // LLDP neighbours: local port number → (remote system, remote port).
    let loc: HashMap<u32, String> = column(&mut c, LLDP_LOC_PORT_ID).into_iter().map(|(k, v)| (k, v.text())).collect();
    let mut lldp: Vec<(String, String, String)> = Vec::new();
    let rem_name = c.walk(&oid(LLDP_REM_SYS_NAME)).unwrap_or_default();
    let rem_port: HashMap<Vec<u32>, String> = c.walk(&oid(LLDP_REM_PORT_DESC)).unwrap_or_default().into_iter().map(|(o, v)| (o[o.len().saturating_sub(3)..].to_vec(), v.text())).collect();
    let rem_pid: HashMap<Vec<u32>, String> = c.walk(&oid(LLDP_REM_PORT_ID)).unwrap_or_default().into_iter().map(|(o, v)| (o[o.len().saturating_sub(3)..].to_vec(), v.text())).collect();
    for (o, v) in rem_name {
        let key = o[o.len().saturating_sub(3)..].to_vec();
        let local_num = key.get(1).copied().unwrap_or(0);
        let local = loc.get(&local_num).cloned().unwrap_or_else(|| format!("port {local_num}"));
        let port = rem_pid.get(&key).filter(|s| !s.is_empty() && s.chars().all(|c| c.is_ascii_graphic())).cloned().or_else(|| rem_port.get(&key).cloned()).unwrap_or_default();
        lldp.push((local, v.text(), port));
    }

    // Table
    // Default: physical, enabled (or busy) interfaces; logical units (ge-0/0/0.0) only with --all.
    let mut rows: Vec<&Iface> = ifs.values().filter(|x| all || ((x.admin_up || x.in_bps + x.out_bps > 0.0) && !noisy(&x.name) && !x.name.contains('.'))).collect();
    rows.sort_by_key(|x| {
        let problem = (x.admin_up && !x.oper_up) || x.err_rate > 0.0 || x.fcs_delta > 0 || x.duplex == Some(2);
        (!problem, x.name.clone())
    });
    let hidden = ifs.len() - rows.len();
    emit(Tone::Head, format!("  {:<18} {:<9} {:>6} {:>8} {:>8} {:>5} {:>7} {:>8} {:>7} {:<9} {}", "INTERFACE", "STATE", "SPEED", "IN b/s", "OUT b/s", "UTIL", "ERR/s", "CRC", "DISC/s", "CHANGED", "DESCRIPTION"));
    for x in rows.iter().take(if all { 1000 } else { 80 }) {
        let state = match (x.admin_up, x.oper_up) {
            (true, true) => "up",
            (true, false) => "DOWN",
            (false, _) => "disabled",
        };
        let util = x.util_pct();
        let tone = if (x.admin_up && !x.oper_up) || x.err_rate > 0.0 || x.fcs_delta > 0 {
            Tone::Bad
        } else if util.is_some_and(|u| u >= 80.0) || x.discard_rate > 0.0 || x.duplex == Some(2) {
            Tone::Warn
        } else if !x.admin_up {
            Tone::Dim
        } else {
            Tone::Normal
        };
        let speed = match x.speed_mbps {
            0 => "·".to_string(),
            s if s >= 1000 => format!("{}G", s / 1000),
            s => format!("{s}M"),
        };
        let dup = if x.duplex == Some(2) { " half" } else { "" };
        emit(
            tone,
            format!(
                "  {:<18} {:<9} {:>6} {:>8} {:>8} {:>5} {:>7} {:>8} {:>7} {:<9} {}",
                crate::util::truncate(&x.name, 18),
                format!("{state}{dup}"),
                speed,
                bps(x.in_bps),
                bps(x.out_bps),
                util.map(|u| format!("{u:.0}%")).unwrap_or_else(|| "·".into()),
                if x.err_rate > 0.0 { format!("{:.1}", x.err_rate) } else { "0".into() },
                x.fcs.map(|f| if x.fcs_delta > 0 { format!("{f}+{}", x.fcs_delta) } else { f.to_string() }).unwrap_or_else(|| "·".into()),
                if x.discard_rate > 0.0 { format!("{:.1}", x.discard_rate) } else { "0".into() },
                ticks_ago(uptime, x.last_change),
                crate::util::truncate(&x.alias, 30)
            ),
        );
    }
    if hidden > 0 {
        emit(Tone::Dim, format!("  … {hidden} disabled / internal interfaces hidden (--all shows them)"));
    }
    if !lldp.is_empty() {
        emit(Tone::Head, "  LLDP neighbours".into());
        for (l, n, p) in &lldp {
            emit(Tone::Normal, format!("    {l:<18} ↔ {n} {p}"));
        }
    }

    // Findings
    for x in ifs.values() {
        if x.admin_up && !x.oper_up && !noisy(&x.name) && !x.name.contains('.') {
            findings.push(format!("{} is enabled but DOWN{}: cable, optic, or the far end is off / err-disabled", x.name, if x.alias.is_empty() { String::new() } else { format!(" ({})", x.alias) }));
        }
        if x.fcs_delta > 0 {
            findings.push(format!("{}: CRC/FCS errors rising (+{} in {:.0} s): damage on the wire: cable, dirty fibre, optic, duplex", x.name, x.fcs_delta, dt));
        }
        if x.err_rate > 0.0 && x.fcs_delta == 0 {
            findings.push(format!("{}: {:.1} errors/s", x.name, x.err_rate));
        }
        if x.discard_rate > 0.0 {
            findings.push(format!("{}: {:.1} discards/s: buffers full (congestion, micro-bursts) or QoS drops", x.name, x.discard_rate));
        }
        if let Some(u) = x.util_pct().filter(|u| *u >= 80.0) {
            findings.push(format!("{}: {u:.0} % utilised: saturated link", x.name));
        }
        if x.duplex == Some(2) {
            findings.push(format!("{}: half duplex: autonegotiation mismatch?", x.name));
        }
        if x.oper_up && x.last_change > 0 && x.last_change <= uptime && (uptime - x.last_change) < 360_000 && !noisy(&x.name) && !x.name.contains('.') && uptime > 360_000 {
            findings.push(format!("{} changed state {}: a recent flap?", x.name, ticks_ago(uptime, x.last_change)));
        }
    }
    if findings.is_empty() {
        emit(Tone::Good, "→ no interface problems found".into());
    } else {
        for f in &findings {
            emit(Tone::Warn, format!("→ {f}"));
        }
    }
    Ok(findings)
}

/// Parse the prompt form: `HOST [COMMUNITY]`.
pub fn parse_prompt(input: &str) -> Option<(String, Option<String>)> {
    let mut w = input.split_whitespace();
    let host = w.next()?.to_string();
    Some((host, w.next().map(String::from)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
    }

    #[test]
    fn rfc3414_key_localization() {
        let engine = hex("000000000000000000000002");
        assert_eq!(localize_key(AuthProto::Md5, "maplesyrup", &engine), hex("526f5eed9fcce26f8964c2930787d82b"));
        assert_eq!(localize_key(AuthProto::Sha1, "maplesyrup", &engine), hex("6695febc9288e36282235fc7151f128497b38f3f"));
    }

    #[test]
    fn ber_roundtrip() {
        for v in [0i64, 1, 127, 128, 255, 256, -1, -129, 65_535, 2_147_483_647] {
            let b = int(v);
            let (t, r, _) = read_tlv(&b, 0).unwrap();
            assert_eq!((t, dec_int(&b[r])), (0x02, v), "{v}");
        }
        let o = oid("1.3.6.1.4.1.2636.3.1.13.1.8.9.1.0.0");
        let b = enc_oid(&o);
        let (_, r, _) = read_tlv(&b, 0).unwrap();
        assert_eq!(dec_oid(&b[r]), o);
        // A v2c GET of sysName.0 with community "public", request id 1.
        let msg = seq(&[int(1), octets(b"public"), enc_pdu(0xa0, 1, 0, 0, &[oid("1.3.6.1.2.1.1.5.0")])]);
        assert_eq!(msg, hex("302602010104067075626c6963a019020101020100020100300e300c06082b060102010105000500"));
        let long = octets(&[7u8; 300]);
        let (_, r, _) = read_tlv(&long, 0).unwrap();
        assert_eq!(r.len(), 300);
    }

    /// A tiny in-process agent for end-to-end tests of the v2c client.
    fn fake_agent(table: Vec<(Vec<u32>, Value)>) -> u16 {
        let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        let port = sock.local_addr().unwrap().port();
        std::thread::spawn(move || {
            let mut buf = vec![0u8; 4096];
            while let Ok((n, from)) = sock.recv_from(&mut buf) {
                let b = &buf[..n];
                let (_, body, _) = read_tlv(b, 0).unwrap();
                let (_, _, p) = read_tlv(b, body.start).unwrap();
                let (_, comm, p) = read_tlv(b, p).unwrap();
                if &b[comm] != b"public" {
                    continue; // wrong community: agents stay silent
                }
                let (tag, id, _, maxrep, vbs) = dec_pdu(&b[p..]).unwrap();
                let mut out: Vec<(Vec<u32>, Value)> = Vec::new();
                for (o, _) in vbs {
                    match tag {
                        0xa0 => out.push(table.iter().find(|(k, _)| *k == o).cloned().unwrap_or((o, Value::NoSuch))),
                        _ => {
                            let mut after: Vec<_> = table.iter().filter(|(k, _)| *k > o).cloned().collect();
                            after.truncate(maxrep.max(1) as usize);
                            if after.is_empty() {
                                after.push((o, Value::EndOfMib));
                            }
                            out.extend(after);
                        }
                    }
                }
                let enc_val = |v: &Value| match v {
                    Value::Int(i) => int(*i),
                    Value::Str(s) => octets(s),
                    Value::Counter64(c) => {
                        let mut t = int(*c as i64);
                        t[0] = 0x46;
                        t
                    }
                    Value::Ticks(c) => {
                        let mut t = int(*c as i64);
                        t[0] = 0x43;
                        t
                    }
                    Value::Gauge(c) => {
                        let mut t = int(*c as i64);
                        t[0] = 0x42;
                        t
                    }
                    Value::NoSuch => tlv(0x80, &[]),
                    Value::EndOfMib => tlv(0x82, &[]),
                    _ => tlv(0x05, &[]),
                };
                let vbs: Vec<Vec<u8>> = out.iter().map(|(o, v)| seq(&[enc_oid(o), enc_val(v)])).collect();
                let pdu = tlv(0xa2, &[int(id as i64), int(0), int(0), seq(&vbs)].concat());
                let _ = sock.send_to(&seq(&[int(1), octets(b"public"), pdu]), from);
            }
        });
        port
    }

    #[test]
    fn v2c_walk_and_report_against_fake_agent() {
        let mut t: Vec<(Vec<u32>, Value)> = vec![
            (oid("1.3.6.1.2.1.1.1.0"), Value::Str(b"Juniper Networks, Inc. ex4300-48t".to_vec())),
            (oid("1.3.6.1.2.1.1.3.0"), Value::Ticks(90_000_000)),
            (oid("1.3.6.1.2.1.1.5.0"), Value::Str(b"sw-core-1".to_vec())),
            (oid("1.3.6.1.2.1.1.6.0"), Value::Str(b"rack 3".to_vec())),
        ];
        for (i, name, oper) in [(501u32, "ge-0/0/0", 1i64), (502, "ge-0/0/1", 2)] {
            t.push((oid(&format!("{IF_NAME}.{i}")), Value::Str(name.as_bytes().to_vec())));
            t.push((oid(&format!("{IF_ADMIN}.{i}")), Value::Int(1)));
            t.push((oid(&format!("{IF_OPER}.{i}")), Value::Int(oper)));
            t.push((oid(&format!("{IF_HIGHSPEED}.{i}")), Value::Gauge(1000)));
            t.push((oid(&format!("{IF_HC_IN}.{i}")), Value::Counter64(1_000_000)));
        }
        t.sort_by(|a, b| a.0.cmp(&b.0));
        let port = fake_agent(t);
        let mut c = Client::connect("127.0.0.1", port, Auth::V2c { community: "public".into() }, Duration::from_secs(1)).unwrap();
        let names = c.walk(&oid(IF_NAME)).unwrap();
        assert_eq!(names.len(), 2);
        assert_eq!(names[1].1.text(), "ge-0/0/1");
        let lines = std::sync::Mutex::new(Vec::new());
        let findings = report("127.0.0.1", port, Auth::V2c { community: "public".into() }, Duration::from_millis(600), false, &|_, l| lines.lock().unwrap().push(l)).unwrap();
        let out = lines.lock().unwrap().join("\n");
        assert!(out.contains("sw-core-1") && out.contains("ge-0/0/1"), "{out}");
        assert!(findings.iter().any(|f| f.contains("ge-0/0/1 is enabled but DOWN")), "{findings:?}");
        // Wrong community: a clear timeout message, not a hang.
        let mut bad = Client::connect("127.0.0.1", port, Auth::V2c { community: "nope".into() }, Duration::from_millis(300)).unwrap();
        assert!(bad.get(&[oid("1.3.6.1.2.1.1.5.0")]).unwrap_err().contains("wrong community"));
    }

    /// Interop with a real net-snmp agent (run by CI, or by hand):
    /// VIGIL_SNMPD_PORT=16161 cargo test snmpd_interop -- --ignored
    /// Users: vsha / vmd5 (authPriv, AES), vauth (authNoPriv), vsha256 if
    /// VIGIL_SNMPD_SHA256=1; passwords authpass123 / privpass123.
    #[test]
    #[ignore]
    fn snmpd_interop() {
        let port: u16 = std::env::var("VIGIL_SNMPD_PORT").expect("VIGIL_SNMPD_PORT").parse().unwrap();
        let mut cases = vec![
            ("v2c", Auth::V2c { community: "public".into() }),
            ("SHA/AES", Auth::V3 { user: "vsha".into(), auth: Some((AuthProto::Sha1, "authpass123".into())), privacy: Some("privpass123".into()) }),
            ("MD5/AES", Auth::V3 { user: "vmd5".into(), auth: Some((AuthProto::Md5, "authpass123".into())), privacy: Some("privpass123".into()) }),
            ("SHA auth only", Auth::V3 { user: "vauth".into(), auth: Some((AuthProto::Sha1, "authpass123".into())), privacy: None }),
        ];
        if std::env::var_os("VIGIL_SNMPD_SHA256").is_some() {
            cases.push(("SHA-256/AES", Auth::V3 { user: "vsha256".into(), auth: Some((AuthProto::Sha256, "authpass123".into())), privacy: Some("privpass123".into()) }));
        }
        for (name, auth) in cases {
            let mut c = Client::connect("127.0.0.1", port, auth, Duration::from_secs(2)).unwrap_or_else(|e| panic!("{name}: {e}"));
            let v = c.get(&[oid("1.3.6.1.2.1.1.5.0")]).unwrap_or_else(|e| panic!("{name}: {e}"));
            assert!(!v[0].1.text().is_empty(), "{name}: empty sysName");
            let ifs = c.walk(&oid(IF_DESCR)).unwrap_or_else(|e| panic!("{name} walk: {e}"));
            assert!(!ifs.is_empty(), "{name}: no interfaces");
            eprintln!("{name}: sysName {} · {} interfaces", v[0].1.text(), ifs.len());
        }
        // Wrong password: a clear USM error.
        let bad = Client::connect("127.0.0.1", port, Auth::V3 { user: "vsha".into(), auth: Some((AuthProto::Sha1, "wrongpass99".into())), privacy: Some("privpass123".into()) }, Duration::from_secs(2))
            .and_then(|mut c| c.get(&[oid("1.3.6.1.2.1.1.5.0")]));
        assert!(bad.is_err(), "wrong password must fail");
        eprintln!("wrong password: {}", bad.unwrap_err());
    }

    #[test]
    fn v3_message_authenticates_and_encrypts() {
        let engine = hex("80000a4c0102030405");
        let mut c = Client {
            sock: UdpSocket::bind("127.0.0.1:0").unwrap(),
            target: "127.0.0.1:161".parse().unwrap(),
            auth: Auth::V3 { user: "vigil".into(), auth: Some((AuthProto::Sha256, "authpass123".into())), privacy: Some("privpass123".into()) },
            timeout: Duration::from_millis(100),
            req: 7,
            v3: None,
            salt: 42,
        };
        c.v3 = Some(V3State {
            engine_id: engine.clone(),
            boots: 3,
            time: 1000,
            at: Instant::now(),
            auth_key: localize_key(AuthProto::Sha256, "authpass123", &engine),
            priv_key: localize_key(AuthProto::Sha256, "privpass123", &engine),
        });
        let pdu = enc_pdu(0xa2, 99, 0, 0, &[oid("1.3.6.1.2.1.1.5.0")]);
        let msg = c.encode_v3(&pdu, 99).unwrap();
        // Our own decoder must verify the HMAC and decrypt the scoped PDU.
        let (tag, id, _, _, vbs) = c.decode_v3(&msg).unwrap();
        assert_eq!((tag, id, vbs[0].0.clone()), (0xa2, 99, oid("1.3.6.1.2.1.1.5.0")));
        // Flip one byte of the encrypted part: authentication must fail.
        let mut bad = msg.clone();
        let n = bad.len() - 3;
        bad[n] ^= 1;
        assert!(c.decode_v3(&bad).unwrap_err().contains("authentication"));
    }
}
