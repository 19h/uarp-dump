//! UARP "Super Binary" container parser.
//!
//! This implementation is verified against Apple's UARP reference sources
//! (CoreUARP / libAppleTconUARPUpdater / UARPiCloud decompilation). The on-disk
//! layout below is taken directly from the reference endian-swap routines, which
//! enumerate every field of the structures as they are byte-swapped from
//! big-endian (network order) to host order:
//!
//! * `uarpSuperBinaryHeaderEndianSwap` — 11 × u32 (44 bytes)
//! * `uarpPayloadHeaderEndianSwap` — 10 × u32 (40 bytes); field[1] is a raw 4CC
//!   tag and is NOT byte-swapped.
//! * `uarpProcessTLV` — metadata TLV header is u32 type + u32 length, value
//!   packed immediately after, with no inter-TLV padding.
//!
//! ## SuperBinary header (44 bytes, all u32 big-endian)
//!   0x00: superBinaryFormatVersion
//!   0x04: superBinaryHeaderLength       (== 44)
//!   0x08: superBinaryLength             (total length of the super binary)
//!   0x0C: superBinaryVersion.major
//!   0x10: superBinaryVersion.minor
//!   0x14: superBinaryVersion.release
//!   0x18: superBinaryVersion.build
//!   0x1C: superBinaryMetadataOffset     (absolute, from start of super binary)
//!   0x20: superBinaryMetadataLength
//!   0x24: payloadHeadersOffset          (absolute)
//!   0x28: payloadHeadersLength          (N × 40)
//!
//! ## Payload header (40 bytes; one entry per payload, fixed 40-byte stride)
//!   0x00: payloadHeaderLength           (== 40)
//!   0x04: payloadTag                     (raw 4CC, NOT byte-swapped)
//!   0x08: payloadVersion.major
//!   0x0C: payloadVersion.minor
//!   0x10: payloadVersion.release
//!   0x14: payloadVersion.build
//!   0x18: payloadMetadataOffset          (absolute)
//!   0x1C: payloadMetadataLength
//!   0x20: payloadOffset                  (absolute)
//!   0x24: payloadLength
//!
//! The reference walks the payload header table at a fixed 40-byte stride
//! (`v11 += 40`), deriving the payload count as `payloadHeadersLength / 40`
//! (the reference rejects a `payloadHeadersLength < 0x28`). Each table entry's
//! `payloadHeaderLength` is expected to be exactly 40.
//!
//! ## Metadata TLVs (super-binary-level and per-payload)
//!   0x00: tlvType   (u32 big-endian)
//!   0x04: tlvLength (u32 big-endian)
//!   0x08: value     (tlvLength bytes; next TLV follows immediately, no padding)
//! The reference consumes the metadata region exactly: it loops until the
//! remaining byte count reaches zero, and a TLV whose `length + 8` exceeds the
//! remaining bytes is a hard error.

use byteorder::{BigEndian, ByteOrder};
use serde::Serialize;
use std::fmt;

/// On-disk size of the SuperBinary header (11 × u32).
pub const SUPER_BINARY_HEADER_LENGTH: u32 = 44;
/// On-disk size of a single payload header (10 × u32). Stride of the table.
pub const PAYLOAD_HEADER_LENGTH: u32 = 40;
/// Size of a metadata TLV header (u32 type + u32 length).
pub const TLV_HEADER_LENGTH: usize = 8;

#[derive(Clone, Copy, Default)]
pub struct ValidationMode {
    /// Relax validation: do not enforce per-region bounds or the structural
    /// length invariants (`superBinaryHeaderLength`, `payloadHeaderLength`).
    /// Regions are still materialized best-effort when they fall within file
    /// bounds. Defaults to `false` (strict).
    pub header_only: bool,
    /// Attempt TLV parse for metadata blocks; if false, keep metadata opaque.
    /// Defaults to `false`.
    pub parse_tlv: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct SuperBinaryHeader {
    pub format_version: u32,
    pub header_length: u32,
    pub super_binary_length: u32,
    pub version_major: u32,
    pub version_minor: u32,
    pub version_release: u32,
    pub version_build: u32,
    pub metadata_offset: u64,
    pub metadata_length: u64,
    pub payload_headers_offset: u64,
    pub payload_headers_length: u64,

    /// Derived: `payload_headers_length / PAYLOAD_HEADER_LENGTH`.
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
    #[serde(serialize_with = "ser_tag_u32")]
    pub type_4cc: u32,
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
            type_4cc: self.typ,
            length: self.len,
            value_hex,
            value_utf8,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct PayloadHeader {
    pub payload_header_length: u32,
    #[serde(serialize_with = "ser_tag")]
    pub payload_tag: [u8; 4],
    pub version_major: u32,
    pub version_minor: u32,
    pub version_release: u32,
    pub version_build: u32,
    pub payload_metadata_offset: u64,
    pub payload_metadata_length: u64,
    pub payload_offset: u64,
    pub payload_length: u64,
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
    SectionOutOfBounds {
        name: &'static str,
        off: u64,
        len: u64,
        file_len: u64,
    },
    /// `superBinaryHeaderLength` is not the expected 44 bytes.
    BadHeaderLength {
        got: u32,
    },
    /// `superBinaryLength` exceeds the actual file length (truncated asset).
    SuperBinaryLengthExceedsFile {
        super_binary_length: u64,
        file_len: u64,
    },
    /// `payloadHeadersLength` is not a multiple of the 40-byte payload header.
    MisalignedHeaders {
        size: u64,
    },
    /// A payload header's self-described length is not the expected 40 bytes.
    BadPayloadHeaderLength {
        index: u32,
        got: u32,
    },
    /// A metadata region is not a well-formed sequence of TLVs.
    BadTlv {
        what: &'static str,
    },
}

impl std::error::Error for UarpError {}

impl fmt::Display for UarpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use UarpError::*;
        match self {
            Truncated(what) => write!(f, "truncated {}", what),
            SectionOutOfBounds {
                name,
                off,
                len,
                file_len,
            } => write!(
                f,
                "section '{}' [0x{:X}..0x{:X}] exceeds file length 0x{:X}",
                name,
                off,
                off.saturating_add(*len),
                file_len
            ),
            BadHeaderLength { got } => write!(
                f,
                "superBinaryHeaderLength is {} (expected {})",
                got, SUPER_BINARY_HEADER_LENGTH
            ),
            SuperBinaryLengthExceedsFile {
                super_binary_length,
                file_len,
            } => write!(
                f,
                "superBinaryLength 0x{:X} exceeds file length 0x{:X} (truncated asset)",
                super_binary_length, file_len
            ),
            MisalignedHeaders { size } => write!(
                f,
                "payloadHeadersLength (0x{:X}) is not a multiple of payload header size {}",
                size, PAYLOAD_HEADER_LENGTH
            ),
            BadPayloadHeaderLength { index, got } => write!(
                f,
                "payload header {} has payloadHeaderLength {} (expected {})",
                index, got, PAYLOAD_HEADER_LENGTH
            ),
            BadTlv { what } => write!(f, "malformed TLV metadata: {}", what),
        }
    }
}

pub fn parse_uarp_from_bytes(bytes: &[u8], mode: ValidationMode) -> Result<Uarp, UarpError> {
    if bytes.len() < SUPER_BINARY_HEADER_LENGTH as usize {
        return Err(UarpError::Truncated("super binary header (need 44 bytes)"));
    }

    // SuperBinary header — 11 × u32 big-endian (see uarpSuperBinaryHeaderEndianSwap).
    let format_version = be32(bytes, 0x00);
    let header_length = be32(bytes, 0x04);
    let super_binary_length = be32(bytes, 0x08);
    let version_major = be32(bytes, 0x0C);
    let version_minor = be32(bytes, 0x10);
    let version_release = be32(bytes, 0x14);
    let version_build = be32(bytes, 0x18);
    let metadata_offset = be32(bytes, 0x1C) as u64;
    let metadata_length = be32(bytes, 0x20) as u64;
    let payload_headers_offset = be32(bytes, 0x24) as u64;
    let payload_headers_length = be32(bytes, 0x28) as u64;

    let file_len = bytes.len() as u64;

    // Structural invariants. The reference reads a fixed 44-byte header; a header
    // length other than 44 means we are not looking at a v-current super binary.
    if !mode.header_only && header_length != SUPER_BINARY_HEADER_LENGTH {
        return Err(UarpError::BadHeaderLength { got: header_length });
    }

    // The asset must not claim to be larger than the bytes we actually have.
    if !mode.header_only && super_binary_length as u64 > file_len {
        return Err(UarpError::SuperBinaryLengthExceedsFile {
            super_binary_length: super_binary_length as u64,
            file_len,
        });
    }

    // The payload header table is N fixed-size (40-byte) records. The reference
    // requires payloadHeadersLength to be a whole number of records.
    if payload_headers_length % (PAYLOAD_HEADER_LENGTH as u64) != 0 {
        return Err(UarpError::MisalignedHeaders {
            size: payload_headers_length,
        });
    }
    let payload_count = (payload_headers_length / (PAYLOAD_HEADER_LENGTH as u64)) as u32;

    // Region bounds. In header-only mode we record the header but tolerate
    // out-of-bounds regions (materialization is then best-effort).
    if !mode.header_only {
        if payload_headers_length > 0 {
            check_region(
                "payloadHeaders",
                payload_headers_offset,
                payload_headers_length,
                file_len,
            )?;
        }
        if metadata_length > 0 {
            check_region(
                "superBinaryMetadata",
                metadata_offset,
                metadata_length,
                file_len,
            )?;
        }
    }

    let header = SuperBinaryHeader {
        format_version,
        header_length,
        super_binary_length,
        version_major,
        version_minor,
        version_release,
        version_build,
        metadata_offset,
        metadata_length,
        payload_headers_offset,
        payload_headers_length,
        payload_count,
    };

    // SuperBinary-level metadata (raw; TLV optionally).
    let (global_metadata_raw, global_metadata_tlvs) =
        if metadata_length > 0 && in_bounds(bytes, metadata_offset, metadata_length) {
            let raw = slice(bytes, metadata_offset, metadata_length)?.to_vec();
            let tlvs = if mode.parse_tlv {
                Some(parse_tlvs_strict(&raw)?)
            } else {
                None
            };
            (Some(raw), tlvs)
        } else {
            (None, None)
        };

    // Payload headers — fixed 40-byte stride starting at payloadHeadersOffset.
    let mut payloads = Vec::with_capacity(payload_count as usize);
    for i in 0..payload_count {
        let off = payload_headers_offset + (i as u64) * (PAYLOAD_HEADER_LENGTH as u64);
        let entry = slice(bytes, off, PAYLOAD_HEADER_LENGTH as u64)?;
        let ph = parse_payload_header(entry);

        // Each table entry self-describes a 40-byte length; the reference treats
        // anything else as malformed.
        if !mode.header_only && ph.payload_header_length != PAYLOAD_HEADER_LENGTH {
            return Err(UarpError::BadPayloadHeaderLength {
                index: i,
                got: ph.payload_header_length,
            });
        }

        if !mode.header_only {
            if ph.payload_length > 0 {
                check_region("payload", ph.payload_offset, ph.payload_length, file_len)?;
            }
            if ph.payload_metadata_length > 0 {
                check_region(
                    "payloadMetadata",
                    ph.payload_metadata_offset,
                    ph.payload_metadata_length,
                    file_len,
                )?;
            }
        }

        // Materialize payload data (best-effort in header-only mode).
        let data =
            if ph.payload_length > 0 && in_bounds(bytes, ph.payload_offset, ph.payload_length) {
                slice(bytes, ph.payload_offset, ph.payload_length)?.to_vec()
            } else {
                Vec::new()
            };

        let (metadata_raw, metadata_tlvs) = if ph.payload_metadata_length > 0
            && in_bounds(
                bytes,
                ph.payload_metadata_offset,
                ph.payload_metadata_length,
            ) {
            let raw = slice(
                bytes,
                ph.payload_metadata_offset,
                ph.payload_metadata_length,
            )?
            .to_vec();
            let tlvs = if mode.parse_tlv {
                Some(parse_tlvs_strict(&raw)?)
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

/// Parse a 40-byte payload header. `b` must be at least 40 bytes (the caller
/// slices exactly `PAYLOAD_HEADER_LENGTH`). Field[1] (the 4CC tag) is copied
/// verbatim — it is a raw FourCC and is not byte-swapped in the reference.
fn parse_payload_header(b: &[u8]) -> PayloadHeader {
    debug_assert!(b.len() >= PAYLOAD_HEADER_LENGTH as usize);
    let mut tag = [0u8; 4];
    tag.copy_from_slice(&b[4..8]);

    PayloadHeader {
        payload_header_length: BigEndian::read_u32(&b[0..4]),
        payload_tag: tag,
        version_major: BigEndian::read_u32(&b[8..12]),
        version_minor: BigEndian::read_u32(&b[12..16]),
        version_release: BigEndian::read_u32(&b[16..20]),
        version_build: BigEndian::read_u32(&b[20..24]),
        payload_metadata_offset: BigEndian::read_u32(&b[24..28]) as u64,
        payload_metadata_length: BigEndian::read_u32(&b[28..32]) as u64,
        payload_offset: BigEndian::read_u32(&b[32..36]) as u64,
        payload_length: BigEndian::read_u32(&b[36..40]) as u64,
    }
}

/// Parse a metadata region as a packed sequence of `{u32 type, u32 length,
/// value[length]}` TLVs. Mirrors `uarpProcessTLV` + its driving loop: each TLV
/// header is 8 bytes, `length + 8` must not exceed the remaining region, and the
/// region must be consumed exactly (no trailing bytes, no inter-TLV padding).
fn parse_tlvs_strict(region: &[u8]) -> Result<Vec<Tlv>, UarpError> {
    let mut pos = 0usize;
    let n = region.len();
    let mut out = Vec::new();

    while pos < n {
        if n - pos < TLV_HEADER_LENGTH {
            return Err(UarpError::BadTlv {
                what: "remaining bytes too small for a TLV header",
            });
        }
        let typ = BigEndian::read_u32(&region[pos..pos + 4]);
        let len = BigEndian::read_u32(&region[pos + 4..pos + 8]) as usize;
        pos += TLV_HEADER_LENGTH;
        if len > n - pos {
            return Err(UarpError::BadTlv {
                what: "TLV value exceeds metadata region",
            });
        }
        let value = region[pos..pos + len].to_vec();
        pos += len;
        out.push(Tlv {
            typ,
            len: len as u32,
            value,
        });
    }

    Ok(out)
}

fn be32(bytes: &[u8], off: usize) -> u32 {
    BigEndian::read_u32(&bytes[off..off + 4])
}

fn check_region(name: &'static str, off: u64, len: u64, file_len: u64) -> Result<(), UarpError> {
    if off.checked_add(len).map_or(true, |end| end > file_len) {
        return Err(UarpError::SectionOutOfBounds {
            name,
            off,
            len,
            file_len,
        });
    }
    Ok(())
}

fn in_bounds(bytes: &[u8], off: u64, len: u64) -> bool {
    off.checked_add(len)
        .map_or(false, |end| end <= bytes.len() as u64)
}

fn slice<'a>(bytes: &'a [u8], off: u64, len: u64) -> Result<&'a [u8], UarpError> {
    let end = off.checked_add(len).ok_or(UarpError::SectionOutOfBounds {
        name: "slice",
        off,
        len,
        file_len: bytes.len() as u64,
    })?;
    bytes
        .get(off as usize..end as usize)
        .ok_or(UarpError::SectionOutOfBounds {
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
    s.serialize_str(&tag_to_display(tag))
}

/// Render a u32 TLV type as a 4CC string (big-endian bytes) when printable,
/// otherwise as `0xXXXXXXXX`.
fn ser_tag_u32<S>(typ: &u32, s: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    let bytes = typ.to_be_bytes();
    if bytes.iter().all(|b| (0x20..=0x7E).contains(b)) {
        s.serialize_str(&String::from_utf8_lossy(&bytes))
    } else {
        s.serialize_str(&format!("0x{:08X}", typ))
    }
}

/// Render a 4-byte tag as ASCII when fully printable, otherwise as hex.
pub fn tag_to_display(tag: &[u8; 4]) -> String {
    if tag.iter().all(|b| (0x20..=0x7E).contains(b)) {
        String::from_utf8_lossy(tag).to_string()
    } else {
        hex_encode(tag)
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
        global_tlvs: u
            .global_metadata_tlvs
            .as_ref()
            .map(|v| v.iter().map(|t| t.to_view()).collect()),
        payloads: u
            .payloads
            .iter()
            .map(|p| JsonPayload {
                header: &p.header,
                tlvs: p
                    .metadata_tlvs
                    .as_ref()
                    .map(|v| v.iter().map(|t| t.to_view()).collect()),
            })
            .collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use byteorder::WriteBytesExt;
    use std::io::Write;

    /// Build a minimal but spec-correct super binary in memory:
    /// header (44) + payload-header table (N*40) + metadata + payload data,
    /// laid out contiguously.
    struct Builder {
        format_version: u32,
        version: [u32; 4],
        sb_metadata: Vec<u8>,
        payloads: Vec<([u8; 4], [u32; 4], Vec<u8>, Vec<u8>)>, // tag, version, data, metadata
    }

    impl Builder {
        fn new() -> Self {
            Self {
                format_version: 2,
                version: [1, 2, 3, 4],
                sb_metadata: Vec::new(),
                payloads: Vec::new(),
            }
        }

        fn build(&self) -> Vec<u8> {
            let n = self.payloads.len() as u64;
            let header_len = SUPER_BINARY_HEADER_LENGTH as u64;
            let table_len = n * PAYLOAD_HEADER_LENGTH as u64;

            // Layout: [header][table][sb_metadata][ for each payload: metadata, data ]
            let mut cursor = header_len + table_len;

            let sb_meta_off = if self.sb_metadata.is_empty() {
                0
            } else {
                let o = cursor;
                cursor += self.sb_metadata.len() as u64;
                o
            };

            struct Region {
                meta_off: u64,
                meta_len: u64,
                data_off: u64,
                data_len: u64,
            }
            let mut regions = Vec::new();
            for (_, _, data, meta) in &self.payloads {
                let meta_off = if meta.is_empty() {
                    0
                } else {
                    let o = cursor;
                    cursor += meta.len() as u64;
                    o
                };
                let data_off = if data.is_empty() {
                    0
                } else {
                    let o = cursor;
                    cursor += data.len() as u64;
                    o
                };
                regions.push(Region {
                    meta_off,
                    meta_len: meta.len() as u64,
                    data_off,
                    data_len: data.len() as u64,
                });
            }
            let total = cursor;

            let mut buf: Vec<u8> = Vec::with_capacity(total as usize);
            // Header
            buf.write_u32::<BigEndian>(self.format_version).unwrap();
            buf.write_u32::<BigEndian>(SUPER_BINARY_HEADER_LENGTH)
                .unwrap();
            buf.write_u32::<BigEndian>(total as u32).unwrap();
            for v in self.version {
                buf.write_u32::<BigEndian>(v).unwrap();
            }
            buf.write_u32::<BigEndian>(sb_meta_off as u32).unwrap();
            buf.write_u32::<BigEndian>(self.sb_metadata.len() as u32)
                .unwrap();
            buf.write_u32::<BigEndian>(header_len as u32).unwrap(); // payloadHeadersOffset
            buf.write_u32::<BigEndian>(table_len as u32).unwrap();

            // Table
            for ((tag, ver, _, _), r) in self.payloads.iter().zip(&regions) {
                buf.write_u32::<BigEndian>(PAYLOAD_HEADER_LENGTH).unwrap();
                buf.write_all(tag).unwrap(); // raw 4CC, NOT byte-swapped
                for v in *ver {
                    buf.write_u32::<BigEndian>(v).unwrap();
                }
                buf.write_u32::<BigEndian>(r.meta_off as u32).unwrap();
                buf.write_u32::<BigEndian>(r.meta_len as u32).unwrap();
                buf.write_u32::<BigEndian>(r.data_off as u32).unwrap();
                buf.write_u32::<BigEndian>(r.data_len as u32).unwrap();
            }

            // SB metadata
            buf.extend_from_slice(&self.sb_metadata);
            // Per-payload metadata + data, in the order offsets were assigned.
            for ((_, _, data, meta), r) in self.payloads.iter().zip(&regions) {
                if r.meta_len > 0 {
                    buf.extend_from_slice(meta);
                }
                if r.data_len > 0 {
                    buf.extend_from_slice(data);
                }
            }

            assert_eq!(buf.len() as u64, total);
            buf
        }
    }

    fn tlv(typ: u32, value: &[u8]) -> Vec<u8> {
        let mut v = Vec::new();
        v.write_u32::<BigEndian>(typ).unwrap();
        v.write_u32::<BigEndian>(value.len() as u32).unwrap();
        v.extend_from_slice(value);
        v
    }

    #[test]
    fn parses_header_and_payloads() {
        let mut b = Builder::new();
        b.payloads
            .push((*b"rkos", [7, 0, 0, 1], b"FIRMWARE-A".to_vec(), Vec::new()));
        b.payloads.push((
            *b"dlpm",
            [7, 0, 0, 2],
            b"DATA-B-payload".to_vec(),
            Vec::new(),
        ));
        let bytes = b.build();

        let u = parse_uarp_from_bytes(&bytes, ValidationMode::default()).unwrap();
        assert_eq!(u.header.format_version, 2);
        assert_eq!(u.header.header_length, 44);
        assert_eq!(u.header.payload_count, 2);
        assert_eq!(u.header.version_major, 1);
        assert_eq!(u.header.version_build, 4);

        assert_eq!(u.payloads.len(), 2);
        assert_eq!(&u.payloads[0].header.payload_tag, b"rkos");
        assert_eq!(u.payloads[0].header.version_major, 7);
        assert_eq!(u.payloads[0].header.version_build, 1);
        assert_eq!(u.payloads[0].data, b"FIRMWARE-A");
        assert_eq!(&u.payloads[1].header.payload_tag, b"dlpm");
        assert_eq!(u.payloads[1].data, b"DATA-B-payload");
    }

    #[test]
    fn tag_is_not_byteswapped() {
        // A tag whose bytes form a distinctive ascending sequence must survive
        // verbatim (proves field[1] is copied raw, not endian-swapped).
        let mut b = Builder::new();
        b.payloads
            .push((*b"ABCD", [0, 0, 0, 0], b"x".to_vec(), Vec::new()));
        let bytes = b.build();
        let u = parse_uarp_from_bytes(&bytes, ValidationMode::default()).unwrap();
        assert_eq!(&u.payloads[0].header.payload_tag, b"ABCD");
    }

    #[test]
    fn parses_superbinary_and_payload_tlvs() {
        let mut b = Builder::new();
        b.sb_metadata = {
            let mut m = tlv(u32::from_be_bytes(*b"PLMN"), b"hello");
            m.extend(tlv(u32::from_be_bytes(*b"VRSN"), &[0, 0, 0, 9]));
            m
        };
        let payload_meta = tlv(u32::from_be_bytes(*b"DHSH"), b"digest!!");
        b.payloads
            .push((*b"rkos", [1, 0, 0, 0], b"fw".to_vec(), payload_meta));
        let bytes = b.build();

        let mode = ValidationMode {
            header_only: false,
            parse_tlv: true,
        };
        let u = parse_uarp_from_bytes(&bytes, mode).unwrap();

        let g = u.global_metadata_tlvs.as_ref().unwrap();
        assert_eq!(g.len(), 2);
        assert_eq!(g[0].typ, u32::from_be_bytes(*b"PLMN"));
        assert_eq!(g[0].value, b"hello");
        assert_eq!(g[1].value, vec![0, 0, 0, 9]);

        let p = u.payloads[0].metadata_tlvs.as_ref().unwrap();
        assert_eq!(p.len(), 1);
        assert_eq!(p[0].typ, u32::from_be_bytes(*b"DHSH"));
        assert_eq!(p[0].value, b"digest!!");
    }

    #[test]
    fn rejects_bad_header_length() {
        let mut b = Builder::new();
        b.payloads
            .push((*b"rkos", [0; 4], b"x".to_vec(), Vec::new()));
        let mut bytes = b.build();
        // Corrupt superBinaryHeaderLength (offset 0x04) to 40.
        BigEndian::write_u32(&mut bytes[0x04..0x08], 40);
        let err = parse_uarp_from_bytes(&bytes, ValidationMode::default()).unwrap_err();
        assert!(matches!(err, UarpError::BadHeaderLength { got: 40 }));
    }

    #[test]
    fn rejects_misaligned_header_table() {
        let mut b = Builder::new();
        b.payloads
            .push((*b"rkos", [0; 4], b"x".to_vec(), Vec::new()));
        let mut bytes = b.build();
        // Corrupt payloadHeadersLength (offset 0x28) to a non-multiple of 40.
        BigEndian::write_u32(&mut bytes[0x28..0x2C], 41);
        let err = parse_uarp_from_bytes(&bytes, ValidationMode::default()).unwrap_err();
        assert!(matches!(err, UarpError::MisalignedHeaders { size: 41 }));
    }

    #[test]
    fn rejects_bad_payload_header_length() {
        let mut b = Builder::new();
        b.payloads
            .push((*b"rkos", [0; 4], b"x".to_vec(), Vec::new()));
        let mut bytes = b.build();
        // The first payload header begins at offset 44; its length field is the
        // first u32 there.
        BigEndian::write_u32(&mut bytes[44..48], 36);
        let err = parse_uarp_from_bytes(&bytes, ValidationMode::default()).unwrap_err();
        assert!(matches!(
            err,
            UarpError::BadPayloadHeaderLength { index: 0, got: 36 }
        ));
    }

    #[test]
    fn rejects_super_binary_length_exceeding_file() {
        let mut b = Builder::new();
        b.payloads
            .push((*b"rkos", [0; 4], b"x".to_vec(), Vec::new()));
        let mut bytes = b.build();
        // Inflate superBinaryLength (offset 0x08) past the real file size.
        let inflated = bytes.len() as u32 + 100;
        BigEndian::write_u32(&mut bytes[0x08..0x0C], inflated);
        let err = parse_uarp_from_bytes(&bytes, ValidationMode::default()).unwrap_err();
        assert!(matches!(
            err,
            UarpError::SuperBinaryLengthExceedsFile { .. }
        ));
    }

    #[test]
    fn rejects_out_of_bounds_payload_region() {
        let mut b = Builder::new();
        b.payloads
            .push((*b"rkos", [0; 4], b"payload".to_vec(), Vec::new()));
        let mut bytes = b.build();
        // payloadLength field is the last u32 of payload header 0 (offset 44+36).
        BigEndian::write_u32(&mut bytes[44 + 36..44 + 40], 0xFFFF);
        let err = parse_uarp_from_bytes(&bytes, ValidationMode::default()).unwrap_err();
        assert!(matches!(err, UarpError::SectionOutOfBounds { .. }));
    }

    #[test]
    fn header_only_tolerates_out_of_bounds() {
        let mut b = Builder::new();
        b.payloads
            .push((*b"rkos", [0; 4], b"payload".to_vec(), Vec::new()));
        let mut bytes = b.build();
        BigEndian::write_u32(&mut bytes[44 + 36..44 + 40], 0xFFFF);
        let mode = ValidationMode {
            header_only: true,
            parse_tlv: false,
        };
        let u = parse_uarp_from_bytes(&bytes, mode).unwrap();
        // Out-of-bounds data is not materialized, but the header still parses.
        assert_eq!(u.payloads[0].header.payload_length, 0xFFFF);
        assert!(u.payloads[0].data.is_empty());
    }

    #[test]
    fn rejects_truncated_tlv() {
        let mut b = Builder::new();
        // 8-byte TLV header claims 100 bytes of value but region is only 8 bytes.
        let mut bad = Vec::new();
        bad.write_u32::<BigEndian>(u32::from_be_bytes(*b"PLMN"))
            .unwrap();
        bad.write_u32::<BigEndian>(100).unwrap();
        b.sb_metadata = bad;
        b.payloads
            .push((*b"rkos", [0; 4], b"x".to_vec(), Vec::new()));
        let bytes = b.build();
        let mode = ValidationMode {
            header_only: false,
            parse_tlv: true,
        };
        let err = parse_uarp_from_bytes(&bytes, mode).unwrap_err();
        assert!(matches!(err, UarpError::BadTlv { .. }));
    }

    #[test]
    fn zero_payloads_is_valid() {
        let b = Builder::new();
        let bytes = b.build();
        let u = parse_uarp_from_bytes(&bytes, ValidationMode::default()).unwrap();
        assert_eq!(u.header.payload_count, 0);
        assert!(u.payloads.is_empty());
    }
}
