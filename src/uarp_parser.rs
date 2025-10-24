//! UARP "Super Binary" parser – header variant with stride preamble.
//!
//! Observed header layout (all u32 big-endian):
//!   0x00: version (e.g., 3)
//!   0x04: header_size (e.g., 44)
//!   0x08: unk2
//!   0x0C: unk3
//!   0x10: unk4
//!   0x14: unk5
//!   0x18: unk6
//!   0x1C: meta_offset
//!   0x20: meta_length
//!   0x24: payload_headers_offset
//!   0x28: payload_headers_size (N * stride)
//!   0x2C: payload_header_stride (e.g., 40)
//
//! At payload_headers_offset, many images store a 4-byte preamble equal to stride.
//! If present, the first actual record starts at (offset + 4).
//!
//! Each payload header (stride bytes; usually 40) has the following layout:
//!   0x00: 4CC tag (u32 BE)
//!   0x04: versionMajor (u32 BE)
//!   0x08: versionMinor (u32 BE)
//!   0x0C: versionRelease (u32 BE)
//!   0x10: versionBuild (u32 BE)
//!   0x14: payloadMetaDataOffset (u32 BE, absolute)
//!   0x18: payloadMetaDataLength (u32 BE)
//!   0x1C: payloadDataOffset (u32 BE, absolute)
//!   0x20: payloadDataLength (u32 BE)
//!   0x24: tail/unknown (u32 BE) -- varies; do not rely on it.

use byteorder::{BigEndian, ByteOrder};
use serde::Serialize;
use std::fmt;

#[derive(Clone, Copy)]
pub struct ValidationMode {
    /// Relax validation (do not enforce per-payload region bounds).
    pub header_only: bool,
    /// Attempt TLV parse for metadata blocks; if false, keep metadata opaque.
    pub parse_tlv: bool,
}

impl Default for ValidationMode {
    fn default() -> Self {
        Self {
            header_only: false,
            parse_tlv: false,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct SuperBinaryHeader {
    pub version: u32,
    pub header_size: u32,
    pub unk2: u32,
    pub unk3: u32,
    pub unk4: u32,
    pub unk5: u32,
    pub unk6: u32,
    pub meta_offset: u64,
    pub meta_length: u64,
    pub payload_headers_offset: u64,
    pub payload_headers_size: u64,
    pub payload_header_stride: u32,

    /// Derived fields (not serialized by default in inner structs)
    #[serde(skip)]
    pub headers_start: u64, // after optional preamble
    #[serde(skip)]
    pub payload_count: u32,
}

#[derive(Debug, Clone)]
pub struct Tlv {
    pub typ: u32,
    pub len: u32,
    pub value: Vec<u8>,
}

#[derive(Debug, Clone, Serialize)]
pub struct TlvView<'a> {
    pub r#type: u32,
    pub length: u32,
    pub value_hex: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value_utf8: Option<&'a str>,
}

impl Tlv {
    pub fn to_view(&self) -> TlvView<'_> {
        let value_hex = hex_encode(&self.value);
        let value_utf8 = std::str::from_utf8(&self.value).ok();
        TlvView {
            r#type: self.typ,
            length: self.len,
            value_hex,
            value_utf8,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct PayloadHeader {
    #[serde(serialize_with = "ser_tag")]
    pub payload_tag: [u8; 4],
    pub version_major: u32,
    pub version_minor: u32,
    pub version_release: u32,
    pub version_build: u32,
    pub payload_meta_offset: u64,
    pub payload_meta_length: u64,
    pub payload_data_offset: u64,
    pub payload_data_length: u64,
    pub tail: u32,
}

#[derive(Debug, Clone)]
pub struct Payload {
    pub header: PayloadHeader,
    pub data: Vec<u8>,
    pub metadata_raw: Option<Vec<u8>>,
    pub metadata_tlvs: Option<Vec<Tlv>>,
}

#[derive(Debug, Clone)]
pub struct Uarp {
    pub header: SuperBinaryHeader,
    pub global_metadata_raw: Option<Vec<u8>>,
    pub global_metadata_tlvs: Option<Vec<Tlv>>,
    pub payloads: Vec<Payload>,
}

#[derive(Debug)]
pub enum UarpError {
    Truncated(&'static str),
    SectionOutOfBounds { name: &'static str, off: u64, len: u64, file_len: u64 },
    MisalignedHeaders { size: u64, stride: u32 },
}

impl std::error::Error for UarpError {}

impl fmt::Display for UarpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use UarpError::*;
        match self {
            Truncated(what) => write!(f, "truncated {}", what),
            SectionOutOfBounds { name, off, len, file_len } =>
                write!(f, "section '{}' [{}..{}] exceeds file length 0x{:X}",
                    name, off, off.saturating_add(*len), file_len),
            MisalignedHeaders { size, stride } =>
                write!(f, "payloadHeadersSize (0x{:X}) is not multiple of stride {}", size, stride),
        }
    }
}

pub fn parse_uarp_from_bytes(bytes: &[u8], mode: ValidationMode) -> Result<Uarp, UarpError> {
    if bytes.len() < 44 {
        return Err(UarpError::Truncated("header (need 44 bytes)"));
    }

    // Header mapping (BE)
    let version = be32(bytes, 0x00);
    let header_size = be32(bytes, 0x04);
    let unk2 = be32(bytes, 0x08);
    let unk3 = be32(bytes, 0x0C);
    let unk4 = be32(bytes, 0x10);
    let unk5 = be32(bytes, 0x14);
    let unk6 = be32(bytes, 0x18);
    let meta_offset = be32(bytes, 0x1C) as u64;
    let meta_length = be32(bytes, 0x20) as u64;
    let payload_headers_offset = be32(bytes, 0x24) as u64;
    let payload_headers_size = be32(bytes, 0x28) as u64;
    let payload_header_stride = be32(bytes, 0x2C);

    let file_len = bytes.len() as u64;

    // Bounds for header array (we'll account for optional preamble below).
    // Require size % stride == 0 (N records).
    if payload_headers_size % (payload_header_stride as u64) != 0 {
        return Err(UarpError::MisalignedHeaders {
            size: payload_headers_size,
            stride: payload_header_stride,
        });
    }
    // At least the preamble word must be within file.
    check_region("payloadHeaders (preamble/region)", payload_headers_offset, 4, file_len)?;

    // Detect optional stride preamble (== stride word).
    let mut headers_start = payload_headers_offset;
    if be32(bytes, payload_headers_offset as usize) == payload_header_stride {
        headers_start += 4;
        // Check full table region with preamble consumed
        check_region("payloadHeaders", headers_start, payload_headers_size, file_len)?;
    } else {
        // No preamble; check region from offset
        check_region("payloadHeaders", payload_headers_offset, payload_headers_size, file_len)?;
    }

    let payload_count = (payload_headers_size / (payload_header_stride as u64)) as u32;

    // Optional global metadata region
    if meta_length > 0 {
        check_region("globalMeta", meta_offset, meta_length, file_len)?;
    }

    let header = SuperBinaryHeader {
        version,
        header_size,
        unk2,
        unk3,
        unk4,
        unk5,
        unk6,
        meta_offset,
        meta_length,
        payload_headers_offset,
        payload_headers_size,
        payload_header_stride,
        headers_start,
        payload_count,
    };

    // Parse global metadata (raw; TLV optionally)
    let (global_metadata_raw, global_metadata_tlvs) = if meta_length > 0 {
        let raw = slice(bytes, meta_offset, meta_length)?.to_vec();
        let tlvs = if mode.parse_tlv {
            parse_tlvs_strict(&raw).ok()
        } else {
            None
        };
        (Some(raw), tlvs)
    } else {
        (None, None)
    };

    // Payload headers
    let mut payloads = Vec::with_capacity(header.payload_count as usize);
    for i in 0..(header.payload_count as usize) {
        let off = header.headers_start + (i as u64) * (payload_header_stride as u64);
        let ph = parse_payload_header(slice(bytes, off, payload_header_stride as u64)?)?;

        // Region checks (strict unless header_only)
        if !mode.header_only {
            if ph.payload_data_length > 0 {
                check_region("payloadData", ph.payload_data_offset, ph.payload_data_length, file_len)?;
            }
            if ph.payload_meta_length > 0 {
                check_region("payloadMeta", ph.payload_meta_offset, ph.payload_meta_length, file_len)?;
            }
        }

        // Materialize data/meta (best-effort in header-only mode)
        let data = if ph.payload_data_length > 0
            && in_bounds(bytes, ph.payload_data_offset, ph.payload_data_length)
        {
            slice(bytes, ph.payload_data_offset, ph.payload_data_length)?.to_vec()
        } else {
            Vec::new()
        };

        let (metadata_raw, metadata_tlvs) = if ph.payload_meta_length > 0
            && in_bounds(bytes, ph.payload_meta_offset, ph.payload_meta_length)
        {
            let raw = slice(bytes, ph.payload_meta_offset, ph.payload_meta_length)?.to_vec();
            let tlvs = if mode.parse_tlv {
                parse_tlvs_strict(&raw).ok()
            } else {
                None
            };
            (Some(raw), tlvs)
        } else {
            (None, None)
        };

        payloads.push(Payload {
            header: ph,
            data,
            metadata_raw,
            metadata_tlvs,
        });
    }

    Ok(Uarp {
        header,
        global_metadata_raw,
        global_metadata_tlvs,
        payloads,
    })
}

fn parse_payload_header(b: &[u8]) -> Result<PayloadHeader, UarpError> {
    if b.len() < 40 {
        return Err(UarpError::Truncated("payload header (need 40 bytes)"));
    }
    let mut tag = [0u8; 4];
    tag.copy_from_slice(&b[0..4]);

    Ok(PayloadHeader {
        payload_tag: tag,
        version_major: BigEndian::read_u32(&b[4..8]),
        version_minor: BigEndian::read_u32(&b[8..12]),
        version_release: BigEndian::read_u32(&b[12..16]),
        version_build: BigEndian::read_u32(&b[16..20]),
        payload_meta_offset: BigEndian::read_u32(&b[20..24]) as u64,
        payload_meta_length: BigEndian::read_u32(&b[24..28]) as u64,
        payload_data_offset: BigEndian::read_u32(&b[28..32]) as u64,
        payload_data_length: BigEndian::read_u32(&b[32..36]) as u64,
        tail: BigEndian::read_u32(&b[36..40]),
    })
}

fn parse_tlvs_strict(region: &[u8]) -> Result<Vec<Tlv>, UarpError> {
    let mut pos = 0usize;
    let n = region.len();
    let mut out = Vec::new();

    while pos + 8 <= n {
        let typ = BigEndian::read_u32(&region[pos..pos + 4]);
        let len = BigEndian::read_u32(&region[pos + 4..pos + 8]) as usize;
        pos += 8;
        if pos.checked_add(len).is_none() || pos + len > n {
            return Err(UarpError::Truncated("TLV value exceeds block"));
        }
        let value = region[pos..pos + len].to_vec();
        pos += len;
        out.push(Tlv { typ, len: len as u32, value });
    }

    if pos != n {
        return Err(UarpError::Truncated("trailing bytes after final TLV"));
    }

    Ok(out)
}

fn be32(bytes: &[u8], off: usize) -> u32 {
    BigEndian::read_u32(&bytes[off..off + 4])
}

fn check_region(name: &'static str, off: u64, len: u64, file_len: u64) -> Result<(), UarpError> {
    if off.checked_add(len).is_none() || off + len > file_len {
        return Err(UarpError::SectionOutOfBounds { name, off, len, file_len });
    }
    Ok(())
}

fn in_bounds(bytes: &[u8], off: u64, len: u64) -> bool {
    off.checked_add(len)
        .and_then(|end| Some(end as usize <= bytes.len()))
        .unwrap_or(false)
}

fn slice<'a>(bytes: &'a [u8], off: u64, len: u64) -> Result<&'a [u8], UarpError> {
    let start = off as usize;
    let end = (off + len) as usize;
    bytes.get(start..end).ok_or(UarpError::SectionOutOfBounds {
        name: "slice",
        off,
        len,
        file_len: bytes.len() as u64,
    })
}

fn hex_encode<B: AsRef<[u8]>>(buf: B) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let b = buf.as_ref();
    let mut s = String::with_capacity(b.len() * 2);
    for &x in b {
        s.push(HEX[(x >> 4) as usize] as char);
        s.push(HEX[(x & 0x0F) as usize] as char);
    }
    s
}

fn ser_tag<S>(tag: &[u8; 4], s: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    let printable = tag.iter().all(|b| (0x20..=0x7E).contains(b));
    if printable {
        s.serialize_str(&String::from_utf8_lossy(tag))
    } else {
        s.serialize_str(&hex_encode(tag))
    }
}

#[derive(Serialize)]
pub struct JsonManifest<'a> {
    pub header: &'a SuperBinaryHeader,
    pub global_tlvs: Option<Vec<TlvView<'a>>>,
    pub payloads: Vec<JsonPayload<'a>>,
}

#[derive(Serialize)]
pub struct JsonPayload<'a> {
    pub header: &'a PayloadHeader,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tlvs: Option<Vec<TlvView<'a>>>,
}

pub fn build_manifest<'a>(u: &'a Uarp) -> JsonManifest<'a> {
    JsonManifest {
        header: &u.header,
        global_tlvs: u.global_metadata_tlvs
            .as_ref()
            .map(|v| v.iter().map(|t| t.to_view()).collect()),
        payloads: u.payloads.iter().map(|p| {
            JsonPayload {
                header: &p.header,
                tlvs: p.metadata_tlvs.as_ref().map(|v| v.iter().map(|t| t.to_view()).collect()),
            }
        }).collect(),
    }
}
