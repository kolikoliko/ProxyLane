use base64::{engine::general_purpose::STANDARD, Engine};
use serde::{Deserialize, Serialize};

pub type Headers = Vec<(String, String)>;
pub(crate) type Result<T> = std::result::Result<T, String>;

/// Identity is supplied by ProxyLane, never inferred from the HTTP payload.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Connection {
    pub id: String,
    pub pid: u32,
    pub process_start: u64,
    /// Snapshot taken while the originating process is still connected.
    #[serde(default)]
    pub process_name: String,
    pub socket: u64,
    pub generation: u64,
    pub destination: String,
    #[serde(default)]
    pub server_name: String,
    #[serde(default)]
    pub server_port: u16,
    #[serde(default)]
    pub decrypted: bool,
    #[serde(default)]
    pub upstream_verification_skipped: bool,
    #[serde(default)]
    pub transport: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Direction {
    Client,
    Server,
}
impl Direction {
    pub(crate) fn index(self) -> usize {
        match self {
            Self::Client => 0,
            Self::Server => 1,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Protocol {
    Http1,
    H2,
}

#[derive(Clone, Debug)]
pub struct Limits {
    pub headers: usize,
    pub header_count: usize,
    pub encoded_body: usize,
    pub decoded_body: usize,
    pub pending: usize,
    pub frame: usize,
    pub hpack_table: u32,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            headers: 64 * 1024,
            header_count: 256,
            encoded_body: 1024 * 1024,
            decoded_body: 4 * 1024 * 1024,
            pending: 16,
            frame: 1024 * 1024,
            hpack_table: 64 * 1024,
        }
    }
}

#[derive(Debug, Default, Serialize)]
pub struct Message {
    #[serde(skip)]
    pub(crate) cache_writer: Option<(crate::cache::CacheRef, usize)>,
    pub method: Option<String>,
    pub target: Option<String>,
    pub status: Option<u16>,
    pub headers: Headers,
    pub trailers: Headers,
    pub body_bytes: u64,
    pub complete: bool,
    /// Transfer framing removed, Content-Encoding still applied.
    #[serde(rename = "body_base64", serialize_with = "as_base64")]
    pub body: Vec<u8>,
    pub decoded_base64: Option<String>,
    /// Only present for valid UTF-8; no guessed charset conversion.
    pub text: Option<String>,
    pub decoding: String,
}
fn as_base64<S: serde::Serializer>(
    bytes: &[u8],
    serializer: S,
) -> std::result::Result<S::Ok, S::Error> {
    serializer.serialize_str(&STANDARD.encode(bytes))
}
impl Message {
    pub(crate) fn append(&mut self, bytes: &[u8], limits: &Limits) {
        self.body_bytes += bytes.len() as u64;
        if let Some((cache, side)) = &self.cache_writer {
            cache.append(*side, bytes);
        }
        let keep = bytes
            .len()
            .min(limits.encoded_body.saturating_sub(self.body.len()));
        self.body.extend_from_slice(&bytes[..keep]);
    }
    pub(crate) fn finish(&mut self, limits: &Limits) {
        if !self.complete {
            self.decoding = "skipped: incomplete message".into();
        } else if self.body_bytes != self.body.len() as u64 {
            self.decoding = if self.cache_writer.is_some() {
                "deferred: query payload cache"
            } else {
                "skipped: encoded body limit"
            }
            .into();
        } else {
            let decode_limit = if self.cache_writer.is_some() {
                limits.decoded_body.min(crate::cache::PREVIEW_BYTES)
            } else {
                limits.decoded_body
            };
            match crate::decode::body(&self.headers, &self.body, decode_limit) {
                Ok(bytes) => {
                    self.text = String::from_utf8(bytes.clone()).ok();
                    self.decoded_base64 = Some(STANDARD.encode(bytes));
                    self.decoding = "ok".into();
                }
                Err(error) if self.cache_writer.is_some() && error == "decoded body limit" => {
                    self.decoding = "deferred: preview decode limit; query payload cache".into()
                }
                Err(error) => self.decoding = format!("failed: {error}"),
            }
        }
    }
}

#[derive(Debug, Default, Serialize)]
pub struct Exchange {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cache: Option<crate::cache::CacheRef>,
    /// HTTP/1 sequence number or HTTP/2 stream ID.
    pub id: u64,
    pub request: Option<Message>,
    pub response: Option<Message>,
    pub informational: Vec<Message>,
    pub problem: Option<String>,
}
impl Exchange {
    pub(crate) fn start_cache(&mut self, cache: Option<&crate::cache::PayloadCache>) {
        self.cache = cache.map(|cache| cache.entry());
        self.bind_cache(0);
    }
    pub(crate) fn bind_cache(&mut self, side: usize) {
        let message = if side == 0 {
            &mut self.request
        } else {
            &mut self.response
        };
        if let (Some(message), Some(cache)) = (message, &self.cache) {
            message.cache_writer = Some((cache.clone(), side));
        }
    }
    pub(crate) fn finish_cache(&self) {
        let Some(cache) = &self.cache else {
            return;
        };
        let head = self.request.as_ref().and_then(|r| r.method.as_deref()) == Some("HEAD");
        let make = |message: Option<&Message>, response: bool| {
            let Some(message) = message else {
                return crate::cache::BodyInfo::default();
            };
            let encodings = tokens(&message.headers, "content-encoding");
            let valid =
                encodings.len() <= 4 && encodings.iter().map(String::len).sum::<usize>() <= 1024;
            crate::cache::BodyInfo {
                bytes: message.body_bytes,
                complete: message.complete && valid,
                headers: if valid && !encodings.is_empty() {
                    vec![("content-encoding".into(), encodings.join(","))]
                } else {
                    Vec::new()
                },
                bodyless: response
                    && (head
                        || message
                            .status
                            .is_some_and(|s| s < 200 || s == 204 || s == 304)),
            }
        };
        cache.finish([
            make(self.request.as_ref(), false),
            make(self.response.as_ref(), true),
        ]);
    }
    pub(crate) fn ready(&self) -> bool {
        self.request.as_ref().is_some_and(|m| m.complete)
            && self.response.as_ref().is_some_and(|m| m.complete)
    }
    pub(crate) fn finish(&mut self, limits: &Limits) {
        let head = self.request.as_ref().and_then(|r| r.method.as_deref()) == Some("HEAD");
        if let Some(request) = &mut self.request {
            request.finish(limits);
        }
        for message in self
            .response
            .iter_mut()
            .chain(self.informational.iter_mut())
        {
            if message.complete
                && (head
                    || message
                        .status
                        .is_some_and(|s| s < 200 || s == 204 || s == 304))
            {
                message.decoding = "not applicable: bodyless response".into();
            } else {
                message.finish(limits);
            }
        }
    }
}

pub(crate) fn values<'a>(headers: &'a Headers, name: &'a str) -> impl Iterator<Item = &'a str> {
    headers
        .iter()
        .filter(move |(n, _)| n.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_str())
}
pub(crate) fn tokens(headers: &Headers, name: &str) -> Vec<String> {
    values(headers, name)
        .flat_map(|v| v.split(','))
        .map(|s| s.trim().to_ascii_lowercase())
        .collect()
}
pub(crate) fn content_length(headers: &Headers) -> Result<Option<u64>> {
    let mut result = None;
    for value in values(headers, "content-length").flat_map(|v| v.split(',')) {
        let value = value.trim();
        if value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
            return Err("invalid Content-Length".into());
        }
        let length = value
            .parse::<u64>()
            .map_err(|_| "Content-Length overflow")?;
        if result.is_some_and(|old| old != length) {
            return Err("conflicting Content-Length".into());
        }
        result = Some(length);
    }
    Ok(result)
}
