//! Bounded DNS wire decoding. Transport framing and transaction lifetime belong
//! to the caller. Names/compression/record formats are handled by Hickory.
use hickory_proto::{
    op::{Message, MessageType, OpCode},
    serialize::binary::{BinDecodable, BinDecoder},
};

pub struct Packet {
    pub id: u16,
    pub response: bool,
    pub key: String,
    pub name: String,
    pub kind: String,
    pub status: String,
    pub text: String,
}
pub fn decode(bytes: &[u8]) -> Result<Packet, String> {
    if !(12..=65535).contains(&bytes.len()) {
        return Err("Invalid DNS message length".into());
    }
    let count = |at| u16::from_be_bytes([bytes[at], bytes[at + 1]]) as usize;
    if count(4) > 16 || count(6) + count(8) + count(10) > 256 {
        return Err("DNS record limit exceeded".into());
    }
    let mut decoder = BinDecoder::new(bytes);
    let msg = Message::read(&mut decoder).map_err(|e| format!("Invalid DNS message: {e}"))?;
    if decoder.index() != bytes.len() {
        return Err("Trailing bytes after DNS message".into());
    }
    if msg.op_code() != OpCode::Query {
        return Err("Unsupported DNS opcode".into());
    }
    let response = msg.message_type() == MessageType::Response;
    if !response && msg.queries().is_empty() {
        return Err("DNS query has no question".into());
    }
    let mut key = format!("{}", msg.id());
    let mut names = Vec::new();
    let mut kinds = Vec::new();
    for q in msg.queries() {
        key.push_str(&format!(
            "|{}:{}:{}",
            q.name().to_ascii().to_lowercase(),
            q.query_type(),
            q.query_class()
        ));
        names.push(q.name().to_ascii());
        kinds.push(q.query_type().to_string());
    }
    let status = format!("{:?}", msg.response_code()).to_uppercase();
    let mut text = format!(
        "ID: 0x{:04X}\r\n{}\r\nRCODE: {}\r\nFlags: AA={} TC={} RD={} RA={} AD={} CD={}\r\n",
        msg.id(),
        if response { "Response" } else { "Query" },
        status,
        msg.authoritative(),
        msg.truncated(),
        msg.recursion_desired(),
        msg.recursion_available(),
        msg.authentic_data(),
        msg.checking_disabled()
    );
    text.push_str("\r\n[Question]\r\n");
    for q in msg.queries() {
        text.push_str(&format!(
            "{} {} {}\r\n",
            q.name(),
            q.query_class(),
            q.query_type()
        ));
    }
    for (label, records) in [
        ("Answer", msg.answers()),
        ("Authority", msg.name_servers()),
        ("Additional", msg.additionals()),
    ] {
        if records.is_empty() {
            continue;
        }
        text.push_str(&format!("\r\n[{label}]\r\n"));
        for r in records {
            if text.len() >= 60000 {
                text.push_str("DNS text preview limited.\r\n");
                break;
            }
            text.push_str(&format!(
                "{} {} {} {} {}\r\n",
                r.name(),
                r.ttl(),
                r.dns_class(),
                r.record_type(),
                r.data().map(ToString::to_string).unwrap_or_default()
            ));
        }
    }
    if let Some(edns) = msg.extensions() {
        text.push_str(&format!("\r\n[EDNS]\r\n{edns}\r\n"));
    }
    if text.len() > 65536 {
        let mut n = 65536;
        while !text.is_char_boundary(n) {
            n -= 1;
        }
        text.truncate(n);
        text.push_str("\r\nDNS text preview limited.");
    }
    Ok(Packet {
        id: msg.id(),
        response,
        key,
        name: names.join(", "),
        kind: kinds.join(", "),
        status,
        text,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn ipv6_alias_https_records_and_bounded_damage() {
        for (kind,rdata,expected) in [
            (28u16,vec![0x20,1,0x0d,0xb8,0,0,0,0,0,0,0,0,0,0,0,1],"2001:db8::1"),
            (5,vec![0xc0,12],"CNAME"),
            (65,vec![0,1,0],"HTTPS"),
        ] {
            let mut b=vec![0,1,0x81,0x80,0,1,0,1,0,0,0,0,1,b'a',0];
            b.extend_from_slice(&kind.to_be_bytes());b.extend_from_slice(&[0,1,0xc0,12]);
            b.extend_from_slice(&kind.to_be_bytes());b.extend_from_slice(&[0,1,0,0,0,60]);
            b.extend_from_slice(&(rdata.len() as u16).to_be_bytes());b.extend_from_slice(&rdata);
            assert!(decode(&b).unwrap().text.contains(expected));
            for cut in 0..b.len() { assert!(decode(&b[..cut]).is_err()); }
            for i in 0..b.len() { let mut damaged=b.clone();damaged[i]^=0xff;let _=decode(&damaged); }
        }
    }
    #[test]
    fn compression_and_malformed_input() {
        let mut q = vec![
            0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, b'a', 0, 0, 1, 0, 1,
        ];
        assert_eq!(decode(&q).unwrap().name, "a.");
        q[2] = 0x81;
        q[3] = 0x80;
        q[7] = 1;
        q.extend_from_slice(&[0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 1, 2, 3, 4]);
        let p = decode(&q).unwrap();
        assert!(p.response);
        assert!(p.text.contains("1.2.3.4"));
        q.pop();
        assert!(decode(&q).is_err());
        assert!(decode(&[0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0xc0, 12, 0, 1, 0, 1]).is_err());
        for n in 0..19 {
            assert!(decode(&[0u8; 19][..n]).is_err());
        }
    }
}
