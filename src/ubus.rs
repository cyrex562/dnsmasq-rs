#![cfg(feature = "ubus")]

//! OpenWrt ubus interface.
//!
//! Replaces the previous invented `"object\nmethod\nkey=value\n"` text
//! protocol with OpenWrt's real `blob_attr`/`blobmsg` binary TLV wire
//! format (`libubox/blob.h`, `libubox/blobmsg.h`), the actual encoding real
//! `ubusd`/`libubus` peers speak — port of `ubus.c`.
//!
//! Confidence notes (read before relying on this for wire-level
//! interoperability — see `tasks.md` for the tracked follow-up):
//! - [`blob`] (the `blob_attr` TLV: 7-bit id + `EXTENDED_BIT` flag + 24-bit
//!   length-including-header in a big-endian `u32`, data padded to 4 bytes)
//!   and [`blobmsg`] (the named/typed layer built on top: `BLOBMSG_TYPE_*`,
//!   `blobmsg_hdr`) are reproduced from `libubox`'s documented layout with
//!   high confidence; `BLOBMSG_TYPE_TABLE`/`INT32`/`ARRAY`/`STRING`'s numeric
//!   values are corroborated by the upstream `ubus.c` source read for this
//!   port. A prior version of this module got two structural details wrong
//!   — no attribute ever set `EXTENDED_BIT` (the flag a real peer's
//!   `blobmsg_data()`/`blobmsg_name()` use to know a `blobmsg_hdr` precedes
//!   the value at all), and a child's `namelen` field stored the
//!   NUL-inclusive byte count instead of `strlen(name)`, which would make a
//!   real peer skip one byte short and misread the first value byte as name
//!   padding. Both are fixed: every [`blobmsg::encode_entry`] child now sets
//!   `EXTENDED_BIT` and encodes `namelen = strlen(name)` followed by
//!   `namelen + 1` name bytes (chars + NUL, matching
//!   `blobmsg_hdrlen(len) == offsetof(struct blobmsg_hdr, name[len + 1])`),
//!   and the top-level container built by [`blobmsg::encode_table`] is
//!   itself a plain (non-extended, headerless) `blob_attr` around its
//!   children, matching `blob_buf_init()`.
//! - This was reasoned from memory of `libubox`'s documented `blob.h`/
//!   `blobmsg.h` layout, not diffed byte-for-byte against a vendored header
//!   or exercised against a live `ubusd` — this sandboxed environment has no
//!   network access and no `libubox`/`libubus` headers or binary available
//!   to check against (attempts to fetch them were blocked; see `tasks.md`).
//!   Treat the `blobmsg` layer as high-confidence but not yet verified, and
//!   the outer `ubus_msghdr`/`UBUS_MSG_*`/`UBUS_ATTR_*` session envelope
//!   (module [`envelope`]) — reconstructed from memory of `libubus`'s
//!   `ubusmsg.h`, including this port's own stream-framing length prefix,
//!   which `blob_attr` itself has no equivalent for — as lower-confidence
//!   still and **not** verified against a vendored header or a live `ubusd`.
//!   Closing that gap needs either real `libubox`/`libubus` headers to check
//!   against or a live-`ubusd` interop smoke test; neither was available
//!   here.

// ─────────────────────────────────────────────────────────────────────────
// blob_attr: the raw TLV primitive (libubox/blob.h)
// ─────────────────────────────────────────────────────────────────────────

pub mod blob {
    //! Raw `blob_attr` TLV encode/parse. Loosely modeled on netlink
    //! attributes (`blob.h`'s own description): a 4-byte big-endian header
    //! packing a 7-bit `id` and a 24-bit `len` (the length of this
    //! attribute *including* its own 4-byte header, excluding padding),
    //! followed by `len - 4` bytes of data, zero-padded up to a 4-byte
    //! boundary before the next attribute.

    pub const HDR_LEN: usize = 4;
    const ID_SHIFT: u32 = 24;
    const ID_MASK: u32 = 0x7f << ID_SHIFT;
    const LEN_MASK: u32 = 0x00ff_ffff;
    /// `BLOB_ATTR_EXTENDED` (`blob.h`): the top bit of the big-endian
    /// `id_len` word. `blobmsg` sets this on every attribute it writes (both
    /// named table entries and unnamed array elements) to signal that the
    /// attribute's data begins with a `blobmsg_hdr` (name length + name)
    /// ahead of the typed value — a plain (non-`blobmsg`) `blob_attr`, like
    /// this module's own top-level container or [`super::envelope`]'s
    /// session attrs, leaves this bit clear and carries no such header.
    pub const EXTENDED_BIT: u32 = 1 << 31;

    #[derive(Debug, thiserror::Error, PartialEq, Eq)]
    pub enum BlobError {
        #[error("truncated blob_attr")]
        Truncated,
        #[error("invalid blob_attr header")]
        InvalidHeader,
        #[error("blob_attr id {0} exceeds 7 bits")]
        IdOutOfRange(u32),
        #[error("blob_attr payload too large")]
        PayloadTooLarge,
    }

    fn pad_len(len: usize) -> usize {
        (len + 3) & !3
    }

    /// Append one plain (non-`blobmsg`) `blob_attr` (header + data + zero
    /// padding) to `out` — the `EXTENDED_BIT` is left clear.
    pub fn put(out: &mut Vec<u8>, id: u8, payload: &[u8]) -> Result<(), BlobError> {
        put_ext(out, id, false, payload)
    }

    /// Append one `blob_attr`, optionally setting `EXTENDED_BIT` — used by
    /// [`super::blobmsg`] to mark attributes whose data begins with a
    /// `blobmsg_hdr`.
    pub fn put_ext(out: &mut Vec<u8>, id: u8, extended: bool, payload: &[u8]) -> Result<(), BlobError> {
        if id > 0x7f {
            return Err(BlobError::IdOutOfRange(id as u32));
        }
        let total_len = HDR_LEN + payload.len();
        if total_len > LEN_MASK as usize {
            return Err(BlobError::PayloadTooLarge);
        }
        let mut id_len: u32 = ((id as u32) << ID_SHIFT) | (total_len as u32 & LEN_MASK);
        if extended {
            id_len |= EXTENDED_BIT;
        }
        out.extend_from_slice(&id_len.to_be_bytes());
        out.extend_from_slice(payload);
        let padded = pad_len(total_len);
        out.resize(out.len() + (padded - total_len), 0);
        Ok(())
    }

    /// One parsed `blob_attr`: its 7-bit `id`, whether `EXTENDED_BIT` was
    /// set, and a slice over its payload (excluding the 4-byte header and
    /// any trailing padding).
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct Attr<'a> {
        pub id: u8,
        pub extended: bool,
        pub data: &'a [u8],
    }

    /// Parse one `blob_attr` from the front of `input`, returning it plus
    /// the number of bytes consumed (header + data + padding).
    pub fn parse_one(input: &[u8]) -> Result<(Attr<'_>, usize), BlobError> {
        if input.len() < HDR_LEN {
            return Err(BlobError::Truncated);
        }
        let id_len = u32::from_be_bytes(input[0..4].try_into().unwrap());
        let id = ((id_len & ID_MASK) >> ID_SHIFT) as u8;
        let extended = id_len & EXTENDED_BIT != 0;
        let len = (id_len & LEN_MASK) as usize;
        if len < HDR_LEN {
            return Err(BlobError::InvalidHeader);
        }
        if input.len() < len {
            return Err(BlobError::Truncated);
        }
        let data = &input[HDR_LEN..len];
        let padded = pad_len(len);
        // The final attribute in a buffer isn't required to carry trailing
        // padding bytes that don't exist in the underlying stream.
        let consumed = padded.min(input.len());
        Ok((Attr { id, extended, data }, consumed))
    }

    /// Parse a flat sequence of back-to-back `blob_attr`s (e.g. a
    /// `blobmsg` table's or array's contents) until `input` is exhausted.
    pub fn parse_all(mut input: &[u8]) -> Result<Vec<Attr<'_>>, BlobError> {
        let mut out = Vec::new();
        while !input.is_empty() {
            let (attr, consumed) = parse_one(input)?;
            out.push(attr);
            input = &input[consumed..];
        }
        Ok(out)
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn put_then_parse_one_roundtrips_id_and_payload() {
            let mut buf = Vec::new();
            put(&mut buf, 5, b"hi").unwrap();
            let (attr, consumed) = parse_one(&buf).unwrap();
            assert_eq!(attr.id, 5);
            assert_eq!(attr.data, b"hi");
            assert_eq!(consumed, buf.len());
        }

        #[test]
        fn payload_is_padded_to_four_bytes() {
            let mut buf = Vec::new();
            put(&mut buf, 1, b"x").unwrap(); // header(4) + 1 byte = 5, padded to 8
            assert_eq!(buf.len(), 8);
            assert_eq!(&buf[5..8], &[0, 0, 0]);
        }

        #[test]
        fn exact_multiple_of_four_needs_no_padding() {
            let mut buf = Vec::new();
            put(&mut buf, 1, b"abcd").unwrap(); // header(4) + 4 = 8, already aligned
            assert_eq!(buf.len(), 8);
        }

        #[test]
        fn id_len_header_is_big_endian_with_id_in_top_byte() {
            let mut buf = Vec::new();
            put(&mut buf, 0x2a, b"").unwrap();
            // total_len = 4, id = 0x2a -> id_len = (0x2a << 24) | 4
            assert_eq!(&buf[0..4], &[0x2a, 0x00, 0x00, 0x04]);
        }

        #[test]
        fn put_ext_sets_the_extended_bit_and_put_leaves_it_clear() {
            let mut buf = Vec::new();
            put_ext(&mut buf, 3, true, b"x").unwrap();
            let (attr, _) = parse_one(&buf).unwrap();
            assert!(attr.extended);
            assert_eq!(attr.id, 3);

            let mut buf2 = Vec::new();
            put(&mut buf2, 3, b"x").unwrap();
            let (attr2, _) = parse_one(&buf2).unwrap();
            assert!(!attr2.extended);
        }

        #[test]
        fn id_over_seven_bits_is_rejected() {
            assert_eq!(put(&mut Vec::new(), 0x80, b""), Err(BlobError::IdOutOfRange(0x80)));
        }

        #[test]
        fn parse_one_truncated_header_errors() {
            assert_eq!(parse_one(&[0u8; 2]), Err(BlobError::Truncated));
        }

        #[test]
        fn parse_one_len_smaller_than_header_errors() {
            // claims a total length of 2, which is less than the 4-byte header
            let mut buf = vec![0u8; 4];
            buf[3] = 2;
            assert_eq!(parse_one(&buf), Err(BlobError::InvalidHeader));
        }

        #[test]
        fn parse_one_short_body_errors() {
            let mut buf = vec![0u8; 4];
            buf[3] = 100; // claims 100 bytes total, only 4 present
            assert_eq!(parse_one(&buf), Err(BlobError::Truncated));
        }

        #[test]
        fn parse_all_walks_multiple_attrs() {
            let mut buf = Vec::new();
            put(&mut buf, 1, b"ab").unwrap();
            put(&mut buf, 2, b"cde").unwrap();
            put(&mut buf, 3, b"").unwrap();
            let attrs = parse_all(&buf).unwrap();
            assert_eq!(attrs.len(), 3);
            assert_eq!(attrs[0], Attr { id: 1, extended: false, data: b"ab" });
            assert_eq!(attrs[1], Attr { id: 2, extended: false, data: b"cde" });
            assert_eq!(attrs[2], Attr { id: 3, extended: false, data: b"" });
        }

        #[test]
        fn parse_all_of_empty_input_is_empty() {
            assert_eq!(parse_all(&[]).unwrap(), Vec::new());
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────
// blobmsg: named/typed values nested inside a blob_attr (libubox/blobmsg.h)
// ─────────────────────────────────────────────────────────────────────────

pub mod blobmsg {
    //! `blobmsg` layers named, typed values on top of raw [`super::blob`]
    //! attributes. A top-level `TABLE`/`ARRAY` container (built by
    //! [`encode_table`]) is a plain, non-extended `blob_attr` whose data is
    //! directly the concatenation of its children — it carries no
    //! `blobmsg_hdr` of its own. Each *child* (built by [`encode_entry`]) is
    //! itself a full `blob_attr` with `EXTENDED_BIT` set, whose data is a
    //! `blobmsg_hdr` (`be16 namelen` = `strlen(name)`, `0` for an unnamed
    //! array element, followed by `namelen + 1` name bytes — the name plus
    //! its NUL terminator, always present even when `namelen == 0`) ahead of
    //! its typed value bytes.

    use super::blob::{self, BlobError};

    pub const TYPE_UNSPEC: u8 = 0;
    pub const TYPE_ARRAY: u8 = 1;
    pub const TYPE_TABLE: u8 = 2;
    pub const TYPE_STRING: u8 = 3;
    pub const TYPE_INT64: u8 = 4;
    pub const TYPE_INT32: u8 = 5;
    pub const TYPE_INT16: u8 = 6;
    pub const TYPE_INT8: u8 = 7;

    #[derive(Debug, thiserror::Error, PartialEq, Eq)]
    pub enum BlobMsgError {
        #[error(transparent)]
        Blob(#[from] BlobError),
        #[error("truncated blobmsg header")]
        TruncatedHeader,
        #[error("name is not valid UTF-8 or not NUL-terminated")]
        InvalidName,
        #[error("value has the wrong length for its declared type")]
        InvalidValueLength,
        #[error("unknown blobmsg type {0}")]
        UnknownType(u8),
    }

    /// A decoded `blobmsg` value tree.
    #[derive(Debug, Clone, PartialEq)]
    pub enum Value {
        Table(Vec<(String, Value)>),
        Array(Vec<Value>),
        Str(String),
        I64(i64),
        I32(i32),
        I16(i16),
        I8(i8),
    }

    impl Value {
        pub fn as_table(&self) -> Option<&[(String, Value)]> {
            match self {
                Value::Table(t) => Some(t),
                _ => None,
            }
        }

        pub fn as_array(&self) -> Option<&[Value]> {
            match self {
                Value::Array(a) => Some(a),
                _ => None,
            }
        }

        pub fn as_str(&self) -> Option<&str> {
            match self {
                Value::Str(s) => Some(s),
                _ => None,
            }
        }

        pub fn as_i64(&self) -> Option<i64> {
            match self {
                Value::I64(v) => Some(*v),
                Value::I32(v) => Some(*v as i64),
                Value::I16(v) => Some(*v as i64),
                Value::I8(v) => Some(*v as i64),
                _ => None,
            }
        }

        pub fn as_u32(&self) -> Option<u32> {
            self.as_i64().map(|v| v as u32)
        }

        /// `table.get(key)`, mirroring `blobmsg_parse` + array-index lookup
        /// (`nil` for non-tables or a missing key).
        pub fn get<'a>(&'a self, key: &str) -> Option<&'a Value> {
            self.as_table()?.iter().find(|(k, _)| k == key).map(|(_, v)| v)
        }
    }

    fn type_id(v: &Value) -> u8 {
        match v {
            Value::Table(_) => TYPE_TABLE,
            Value::Array(_) => TYPE_ARRAY,
            Value::Str(_) => TYPE_STRING,
            Value::I64(_) => TYPE_INT64,
            Value::I32(_) => TYPE_INT32,
            Value::I16(_) => TYPE_INT16,
            Value::I8(_) => TYPE_INT8,
        }
    }

    fn value_bytes(v: &Value) -> Vec<u8> {
        match v {
            Value::Table(entries) => {
                let mut out = Vec::new();
                for (name, val) in entries {
                    out.extend_from_slice(&encode_entry(Some(name), val));
                }
                out
            }
            Value::Array(items) => {
                let mut out = Vec::new();
                for val in items {
                    out.extend_from_slice(&encode_entry(None, val));
                }
                out
            }
            Value::Str(s) => {
                let mut b = s.as_bytes().to_vec();
                b.push(0);
                b
            }
            Value::I64(n) => n.to_be_bytes().to_vec(),
            Value::I32(n) => n.to_be_bytes().to_vec(),
            Value::I16(n) => n.to_be_bytes().to_vec(),
            Value::I8(n) => vec![*n as u8],
        }
    }

    /// Encode one table/array entry (`blobmsg_hdr` + typed value) as a full
    /// `blob_attr` (header + data + padding), with `EXTENDED_BIT` set —
    /// `blobmsg_add_field()`'s wire layout (`blobmsg.c`). `name = None` for
    /// an array element, matching an empty-string name (`namelen = 0`).
    ///
    /// The `blobmsg_hdr` wire encoding is `be16 namelen` (the name's byte
    /// length *excluding* its NUL terminator — `0` for an array element or
    /// an empty name) followed by exactly `namelen + 1` name bytes (the name
    /// itself, always NUL-terminated even when empty) — `blobmsg_hdrlen(len)
    /// == offsetof(struct blobmsg_hdr, name[len + 1])`. A prior version of
    /// this port stored `namelen = name.len() + 1` (the NUL-inclusive count)
    /// but then only wrote `namelen` further bytes, one short of what a real
    /// peer would skip to find the value — this is fixed below.
    pub fn encode_entry(name: Option<&str>, v: &Value) -> Vec<u8> {
        let name = name.unwrap_or("");
        let mut hdr_and_value = Vec::new();
        let namelen = name.len() as u16;
        hdr_and_value.extend_from_slice(&namelen.to_be_bytes());
        hdr_and_value.extend_from_slice(name.as_bytes());
        hdr_and_value.push(0); // NUL terminator, always present
        hdr_and_value.extend_from_slice(&value_bytes(v));

        let mut out = Vec::new();
        blob::put_ext(&mut out, type_id(v), true, &hdr_and_value)
            .expect("blobmsg names/values stay well under the 24-bit length limit");
        out
    }

    /// Encode a top-level `TABLE` `blob_attr` from `entries` — what
    /// `blob_buf_init(&b, BLOBMSG_TYPE_TABLE)` plus a run of
    /// `blobmsg_add_*` calls builds (`b.head`). Unlike [`encode_entry`]'s
    /// children, this top-level container itself carries no `blobmsg_hdr`
    /// and leaves `EXTENDED_BIT` clear — `blob_buf_init` writes a plain
    /// `blob_attr` whose data is directly the concatenation of its
    /// (individually headered) children, with no header of its own.
    pub fn encode_table(entries: &[(&str, Value)]) -> Vec<u8> {
        let mut data = Vec::new();
        for (name, val) in entries {
            data.extend_from_slice(&encode_entry(Some(name), val));
        }
        let mut out = Vec::new();
        blob::put(&mut out, TYPE_TABLE, &data)
            .expect("blobmsg tables stay well under the 24-bit length limit");
        out
    }

    fn decode_value(type_id: u8, data: &[u8]) -> Result<Value, BlobMsgError> {
        match type_id {
            TYPE_TABLE => Ok(Value::Table(decode_named_children(data)?)),
            TYPE_ARRAY => Ok(Value::Array(decode_unnamed_children(data)?)),
            TYPE_STRING => {
                let s = data.strip_suffix(&[0]).unwrap_or(data);
                Ok(Value::Str(std::str::from_utf8(s).map_err(|_| BlobMsgError::InvalidName)?.to_string()))
            }
            TYPE_INT64 => {
                let b: [u8; 8] = data.try_into().map_err(|_| BlobMsgError::InvalidValueLength)?;
                Ok(Value::I64(i64::from_be_bytes(b)))
            }
            TYPE_INT32 => {
                let b: [u8; 4] = data.try_into().map_err(|_| BlobMsgError::InvalidValueLength)?;
                Ok(Value::I32(i32::from_be_bytes(b)))
            }
            TYPE_INT16 => {
                let b: [u8; 2] = data.try_into().map_err(|_| BlobMsgError::InvalidValueLength)?;
                Ok(Value::I16(i16::from_be_bytes(b)))
            }
            TYPE_INT8 => {
                let b: [u8; 1] = data.try_into().map_err(|_| BlobMsgError::InvalidValueLength)?;
                Ok(Value::I8(b[0] as i8))
            }
            other => Err(BlobMsgError::UnknownType(other)),
        }
    }

    /// Split one child's `blobmsg_hdr` (`be16 namelen` + `namelen + 1` name
    /// bytes, always NUL-terminated — see [`encode_entry`]'s doc comment)
    /// off the front of its `blob_attr` data, returning `(name, value_bytes)`.
    fn split_header(data: &[u8]) -> Result<(String, &[u8]), BlobMsgError> {
        if data.len() < 2 {
            return Err(BlobMsgError::TruncatedHeader);
        }
        let namelen = u16::from_be_bytes([data[0], data[1]]) as usize;
        if data.len() < 2 + namelen + 1 {
            return Err(BlobMsgError::TruncatedHeader);
        }
        let name_bytes = &data[2..2 + namelen];
        let name = std::str::from_utf8(name_bytes).map_err(|_| BlobMsgError::InvalidName)?.to_string();
        Ok((name, &data[2 + namelen + 1..]))
    }

    /// Every child of a `blobmsg` table/array must carry `EXTENDED_BIT` —
    /// it is what tells a real peer's `blobmsg_data()`/`blobmsg_name()` that
    /// a `blobmsg_hdr` precedes the value at all. A non-extended child here
    /// would mean [`split_header`] is misreading raw value bytes as a name.
    fn require_extended(attr: &blob::Attr<'_>) -> Result<(), BlobMsgError> {
        if !attr.extended {
            return Err(BlobMsgError::TruncatedHeader);
        }
        Ok(())
    }

    fn decode_named_children(data: &[u8]) -> Result<Vec<(String, Value)>, BlobMsgError> {
        let mut out = Vec::new();
        for attr in blob::parse_all(data)? {
            require_extended(&attr)?;
            let (name, value_bytes) = split_header(attr.data)?;
            out.push((name, decode_value(attr.id, value_bytes)?));
        }
        Ok(out)
    }

    fn decode_unnamed_children(data: &[u8]) -> Result<Vec<Value>, BlobMsgError> {
        let mut out = Vec::new();
        for attr in blob::parse_all(data)? {
            require_extended(&attr)?;
            let (_, value_bytes) = split_header(attr.data)?;
            out.push(decode_value(attr.id, value_bytes)?);
        }
        Ok(out)
    }

    /// Decode one top-level `TABLE`/`ARRAY` `blob_attr` (as produced by
    /// [`encode_table`]) back into a [`Value`]. Unlike a child entry, the
    /// top-level container carries no `blobmsg_hdr` of its own (see
    /// [`encode_table`]'s doc comment) — its data is decoded directly as a
    /// list of (headered) children.
    pub fn decode(bytes: &[u8]) -> Result<Value, BlobMsgError> {
        let (attr, _) = blob::parse_one(bytes)?;
        decode_value(attr.id, attr.data)
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn string_field_roundtrips_through_a_table() {
            let bytes = encode_table(&[("name", Value::Str("dnsmasq".to_string()))]);
            let decoded = decode(&bytes).unwrap();
            assert_eq!(decoded.get("name").and_then(Value::as_str), Some("dnsmasq"));
        }

        #[test]
        fn u32_metric_field_roundtrips() {
            let bytes = encode_table(&[("dns_cache_inserted", Value::I32(42))]);
            let decoded = decode(&bytes).unwrap();
            assert_eq!(decoded.get("dns_cache_inserted").and_then(Value::as_u32), Some(42));
        }

        #[test]
        fn multiple_fields_all_present_and_ordered() {
            let bytes = encode_table(&[
                ("mark", Value::I32(6)),
                ("name", Value::Str("example.com".to_string())),
            ]);
            let Value::Table(fields) = decode(&bytes).unwrap() else { panic!("expected table") };
            assert_eq!(fields[0].0, "mark");
            assert_eq!(fields[1].0, "name");
        }

        #[test]
        fn nested_array_of_strings_roundtrips() {
            let patterns = Value::Array(vec![
                Value::Str("*.example.com".to_string()),
                Value::Str("*".to_string()),
            ]);
            let bytes = encode_table(&[("patterns", patterns)]);
            let decoded = decode(&bytes).unwrap();
            let arr = decoded.get("patterns").unwrap().as_array().unwrap();
            assert_eq!(arr.len(), 2);
            assert_eq!(arr[0].as_str(), Some("*.example.com"));
            assert_eq!(arr[1].as_str(), Some("*"));
        }

        #[test]
        fn empty_table_roundtrips() {
            let bytes = encode_table(&[]);
            assert_eq!(decode(&bytes).unwrap(), Value::Table(vec![]));
        }

        #[test]
        fn missing_key_returns_none() {
            let bytes = encode_table(&[("a", Value::I8(1))]);
            let decoded = decode(&bytes).unwrap();
            assert!(decoded.get("b").is_none());
        }

        #[test]
        fn array_elements_carry_a_zero_length_name_and_its_nul_terminator() {
            let entry = encode_entry(None, &Value::I32(7));
            // 4-byte blob_attr header + 2-byte namelen(=0) + 1-byte NUL +
            // 4-byte i32 = 11, padded to 12.
            assert_eq!(entry.len(), 12);
            assert_eq!(&entry[4..6], &[0, 0]); // namelen = 0
            assert_eq!(entry[6], 0); // the empty name's NUL terminator
            assert_eq!(&entry[7..11], &7i32.to_be_bytes());
        }

        #[test]
        fn named_entry_namelen_excludes_the_nul_terminator() {
            // blobmsg_hdr.namelen is strlen(name), not name.len() + 1 — a
            // prior version of this port stored the +1 count, which would
            // make a real peer read one byte too few for the name field and
            // misinterpret the first value byte as trailing name padding.
            let entry = encode_entry(Some("ip"), &Value::I8(1));
            assert_eq!(&entry[4..6], &2u16.to_be_bytes()); // namelen = strlen("ip") = 2
            assert_eq!(&entry[6..8], b"ip");
            assert_eq!(entry[8], 0); // NUL terminator
            assert_eq!(entry[9], 1); // the I8 value
        }

        #[test]
        fn every_blobmsg_entry_sets_the_extended_bit() {
            let named = encode_entry(Some("x"), &Value::I8(1));
            let (attr, _) = blob::parse_one(&named).unwrap();
            assert!(attr.extended);

            let unnamed = encode_entry(None, &Value::I8(1));
            let (attr2, _) = blob::parse_one(&unnamed).unwrap();
            assert!(attr2.extended);
        }

        #[test]
        fn top_level_table_container_is_not_extended_and_has_no_header() {
            // blob_buf_init(&b, BLOBMSG_TYPE_TABLE) writes a plain blob_attr
            // whose data is directly its children — no blobmsg_hdr wrapping
            // the container itself, unlike each individual child.
            let bytes = encode_table(&[("a", Value::I8(1))]);
            let (attr, _) = blob::parse_one(&bytes).unwrap();
            assert!(!attr.extended);
            assert_eq!(attr.id, TYPE_TABLE);
            // attr.data is exactly the one child's encoded entry, with no
            // extra header bytes ahead of it.
            assert_eq!(attr.data, encode_entry(Some("a"), &Value::I8(1)).as_slice());
        }

        #[test]
        fn truncated_input_does_not_panic() {
            assert!(decode(&[0u8; 3]).is_err());
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────
// ubus session envelope (best-effort reconstruction of ubusmsg.h — see the
// module doc's confidence notes)
// ─────────────────────────────────────────────────────────────────────────

pub mod envelope {
    //! One framed ubus message on the wire: a stream-framing length prefix
    //! (this port's own addition — `blob_attr` itself carries no top-level
    //! length, and a Unix *stream* socket needs one), an 8-byte
    //! `ubus_msghdr` (version, message type, sequence number, peer/client
    //! id), and a body of concatenated top-level [`super::blob`] attributes
    //! keyed by `UBUS_ATTR_*`.

    use super::blob::{self, BlobError};

    pub const UBUS_MSG_HELLO: u8 = 0;
    pub const UBUS_MSG_STATUS: u8 = 1;
    pub const UBUS_MSG_DATA: u8 = 2;
    pub const UBUS_MSG_PING: u8 = 3;
    pub const UBUS_MSG_LOOKUP: u8 = 4;
    pub const UBUS_MSG_INVOKE: u8 = 5;
    pub const UBUS_MSG_ADD_OBJECT: u8 = 6;
    pub const UBUS_MSG_REMOVE_OBJECT: u8 = 7;
    pub const UBUS_MSG_SUBSCRIBE: u8 = 8;
    pub const UBUS_MSG_UNSUBSCRIBE: u8 = 9;
    pub const UBUS_MSG_NOTIFY: u8 = 10;

    pub const ATTR_UNSPEC: u8 = 0;
    pub const ATTR_STATUS: u8 = 1;
    pub const ATTR_OBJPATH: u8 = 2;
    pub const ATTR_OBJID: u8 = 3;
    pub const ATTR_METHOD: u8 = 4;
    #[allow(dead_code)]
    pub const ATTR_OBJTYPE: u8 = 5;
    pub const ATTR_SIGNATURE: u8 = 6;
    pub const ATTR_DATA: u8 = 7;
    #[allow(dead_code)]
    pub const ATTR_TARGET: u8 = 8;
    #[allow(dead_code)]
    pub const ATTR_ACTIVE: u8 = 9;
    #[allow(dead_code)]
    pub const ATTR_NO_REPLY: u8 = 10;
    #[allow(dead_code)]
    pub const ATTR_SUBSCRIBERS: u8 = 11;
    #[allow(dead_code)]
    pub const ATTR_USER: u8 = 12;
    #[allow(dead_code)]
    pub const ATTR_GROUP: u8 = 13;

    const UBUS_VERSION: u8 = 0;
    const HDR_LEN: usize = 8;

    #[derive(Debug, Clone)]
    pub struct Message {
        pub msg_type: u8,
        pub seq: u16,
        pub peer: u32,
        /// `(UBUS_ATTR_*, raw payload)` pairs. `ATTR_DATA`'s payload is
        /// itself a `blobmsg` `TABLE` `blob_attr` (see [`super::blobmsg`]).
        pub attrs: Vec<(u8, Vec<u8>)>,
    }

    impl Message {
        pub fn get(&self, id: u8) -> Option<&[u8]> {
            self.attrs.iter().find(|(a, _)| *a == id).map(|(_, v)| v.as_slice())
        }
    }

    #[derive(Debug, thiserror::Error, PartialEq, Eq)]
    pub enum EnvelopeError {
        #[error("truncated ubus frame")]
        Truncated,
        #[error(transparent)]
        Blob(#[from] BlobError),
    }

    /// Encode one framed message: `[be32 body length][ubus_msghdr][body]`.
    pub fn encode(msg: &Message) -> Vec<u8> {
        let mut body = Vec::new();
        body.push(UBUS_VERSION);
        body.push(msg.msg_type);
        body.extend_from_slice(&msg.seq.to_be_bytes());
        body.extend_from_slice(&msg.peer.to_be_bytes());
        for (id, payload) in &msg.attrs {
            blob::put(&mut body, *id, payload).expect("ubus attr ids/payloads stay within limits");
        }

        let mut out = Vec::with_capacity(4 + body.len());
        out.extend_from_slice(&(body.len() as u32).to_be_bytes());
        out.extend_from_slice(&body);
        out
    }

    /// Decode one framed message from the front of `input`, returning it
    /// plus the number of bytes consumed.
    pub fn decode(input: &[u8]) -> Result<(Message, usize), EnvelopeError> {
        if input.len() < 4 {
            return Err(EnvelopeError::Truncated);
        }
        let body_len = u32::from_be_bytes(input[0..4].try_into().unwrap()) as usize;
        if input.len() < 4 + body_len {
            return Err(EnvelopeError::Truncated);
        }
        let body = &input[4..4 + body_len];
        if body.len() < HDR_LEN {
            return Err(EnvelopeError::Truncated);
        }
        let msg_type = body[1];
        let seq = u16::from_be_bytes([body[2], body[3]]);
        let peer = u32::from_be_bytes([body[4], body[5], body[6], body[7]]);
        let attrs = blob::parse_all(&body[HDR_LEN..])?
            .into_iter()
            .map(|a| (a.id, a.data.to_vec()))
            .collect();
        Ok((Message { msg_type, seq, peer, attrs }, 4 + body_len))
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn message_roundtrips_type_seq_peer_and_attrs() {
            let msg = Message {
                msg_type: UBUS_MSG_INVOKE,
                seq: 7,
                peer: 42,
                attrs: vec![(ATTR_METHOD, b"metrics".to_vec())],
            };
            let bytes = encode(&msg);
            let (decoded, consumed) = decode(&bytes).unwrap();
            assert_eq!(consumed, bytes.len());
            assert_eq!(decoded.msg_type, UBUS_MSG_INVOKE);
            assert_eq!(decoded.seq, 7);
            assert_eq!(decoded.peer, 42);
            assert_eq!(decoded.get(ATTR_METHOD), Some(b"metrics".as_slice()));
        }

        #[test]
        fn truncated_length_prefix_errors() {
            assert!(matches!(decode(&[0u8; 2]), Err(EnvelopeError::Truncated)));
        }

        #[test]
        fn truncated_body_errors() {
            let mut data = vec![0u8; 4];
            data[0..4].copy_from_slice(&100u32.to_be_bytes());
            data.extend_from_slice(&[0u8; 5]);
            assert!(matches!(decode(&data), Err(EnvelopeError::Truncated)));
        }

        #[test]
        fn decode_reports_bytes_consumed_for_streaming() {
            let msg = Message { msg_type: UBUS_MSG_PING, seq: 1, peer: 0, attrs: vec![] };
            let mut bytes = encode(&msg);
            bytes.extend_from_slice(&[0xAA; 4]); // trailing bytes of a next message
            let (_, consumed) = decode(&bytes).unwrap();
            assert_eq!(consumed, bytes.len() - 4);
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────
// Connection lifecycle, RPC dispatch, event broadcast (ubus.c:82-391)
// ─────────────────────────────────────────────────────────────────────────

/// Well-known ubus socket path, matching OpenWrt's `UBUS_UNIX_SOCKET`
/// default that `ubus_connect(NULL)` falls back to.
pub const UBUS_SOCKET_PATH: &str = "/var/run/ubus.sock";

pub const UBUS_STATUS_OK: u32 = 0;
pub const UBUS_STATUS_INVALID_ARGUMENT: u32 = 2;
pub const UBUS_STATUS_METHOD_NOT_FOUND: u32 = 3;

#[cfg(unix)]
mod connection {
    use super::{blobmsg, envelope, UBUS_SOCKET_PATH, UBUS_STATUS_OK};
    use std::io::{Read, Write};
    use std::os::unix::net::UnixStream;
    use std::sync::{Mutex, OnceLock};

    /// Live connection + object registration state — the Rust analogue of
    /// upstream's globals `daemon->ubus` (an opaque `ubus_context *`) and
    /// `ubus_object`/`ubus_object.has_subscribers` (`ubus.c:64-73`).
    /// Deliberately process-global rather than threaded through every call
    /// site, mirroring upstream's own use of file-scope statics for exactly
    /// this state.
    struct Runtime {
        stream: Option<UnixStream>,
        peer: u32,
        object_id: u32,
        has_subscribers: bool,
        next_seq: u16,
        /// Bytes read off the socket but not yet decoded into a complete
        /// message — a Unix *stream* socket has no message boundaries, so a
        /// peer that pipelines frames (e.g. a `SUBSCRIBE` sent immediately
        /// after an `ADD_OBJECT` reply, both delivered in one `read()`) can
        /// leave a partial or extra frame behind a given read call. This
        /// persists across both the handshake and later
        /// `check_ubus_listeners_once` polls so nothing pipelined is ever
        /// silently dropped.
        pending: Vec<u8>,
    }

    impl Default for Runtime {
        fn default() -> Self {
            Runtime {
                stream: None,
                peer: 0,
                object_id: 0,
                has_subscribers: false,
                next_seq: 1,
                pending: Vec::new(),
            }
        }
    }

    static RUNTIME: OnceLock<Mutex<Runtime>> = OnceLock::new();

    fn runtime() -> &'static Mutex<Runtime> {
        RUNTIME.get_or_init(|| Mutex::new(Runtime::default()))
    }

    /// Whether [`ubus_init`] currently holds a live connection — the Rust
    /// analogue of upstream's `daemon->ubus != NULL` check.
    pub fn is_connected() -> bool {
        runtime().lock().unwrap().stream.is_some()
    }

    /// The `RUNTIME` above is process-global (matching upstream's own
    /// `daemon->ubus` / `ubus_object` globals), so tests that touch a real
    /// socket connection must not run concurrently with each other — a
    /// second test's `reset_for_test()` could otherwise clobber a
    /// connection another test is mid-handshake on. Every test below takes
    /// this lock first.
    #[cfg(test)]
    static TEST_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

    #[cfg(test)]
    pub(super) fn test_lock() -> std::sync::MutexGuard<'static, ()> {
        TEST_LOCK.get_or_init(|| Mutex::new(())).lock().unwrap_or_else(|e| e.into_inner())
    }

    #[cfg(test)]
    pub(super) fn reset_for_test() {
        let mut rt = runtime().lock().unwrap();
        *rt = Runtime::default();
    }

    #[cfg(test)]
    pub(super) fn subscriber_state_for_test() -> (bool, bool) {
        let rt = runtime().lock().unwrap();
        (rt.stream.is_some(), rt.has_subscribers)
    }

    #[cfg(test)]
    pub(super) fn set_subscribers_for_test(v: bool) {
        runtime().lock().unwrap().has_subscribers = v;
    }

    fn method_names() -> &'static [&'static str] {
        #[cfg(feature = "conntrack")]
        {
            &["metrics", "set_connmark_allowlist"]
        }
        #[cfg(not(feature = "conntrack"))]
        {
            &["metrics"]
        }
    }

    /// Read one complete message, using (and updating) `buf` as a
    /// persistent accumulator so any bytes read past this message's end —
    /// the start of a pipelined next frame — survive for the next call
    /// instead of being discarded with a fresh, function-local buffer.
    fn read_one_message(stream: &mut UnixStream, buf: &mut Vec<u8>) -> Option<envelope::Message> {
        let mut chunk = [0u8; 512];
        loop {
            match envelope::decode(buf) {
                Ok((msg, consumed)) => {
                    buf.drain(0..consumed);
                    return Some(msg);
                }
                Err(envelope::EnvelopeError::Truncated) => {}
                Err(_) => return None,
            }
            match stream.read(&mut chunk) {
                Ok(0) => return None,
                Ok(n) => buf.extend_from_slice(&chunk[..n]),
                Err(_) => return None,
            }
        }
    }

    /// `ubus_init()` (ubus.c:105-126): connect, register `name` as our
    /// ubus object with [`method_names`]'s method table, store the
    /// resulting connection. Returns `None` on success — including when no
    /// `ubusd` is reachable at all, matching upstream's own
    /// `if (!(ubus = ubus_connect(NULL))) return NULL;` (a missing daemon
    /// is not treated as an error) — or `Some(message)` if the connection
    /// was made but object registration failed.
    pub fn ubus_init(name: &str) -> Option<String> {
        ubus_init_at(name, UBUS_SOCKET_PATH)
    }

    pub(super) fn ubus_init_at(name: &str, sock_path: &str) -> Option<String> {
        let mut stream = UnixStream::connect(sock_path).ok()?;
        // Shared across both handshake reads below — see `read_one_message`'s
        // doc comment on why a fresh buffer per call would lose pipelined
        // bytes (e.g. a `SUBSCRIBE` the peer sends right after its
        // `ADD_OBJECT` reply, with no round trip in between).
        let mut buf = Vec::new();

        let seq = { let mut rt = runtime().lock().unwrap(); let s = rt.next_seq; rt.next_seq = rt.next_seq.wrapping_add(1); s };
        let hello = envelope::Message { msg_type: envelope::UBUS_MSG_HELLO, seq, peer: 0, attrs: vec![] };
        stream.write_all(&envelope::encode(&hello)).ok()?;
        let reply = read_one_message(&mut stream, &mut buf)?;
        let peer = reply.peer;

        let seq2 = { let mut rt = runtime().lock().unwrap(); let s = rt.next_seq; rt.next_seq = rt.next_seq.wrapping_add(1); s };
        let signature: Vec<(&str, blobmsg::Value)> =
            method_names().iter().map(|m| (*m, blobmsg::Value::Table(Vec::new()))).collect();
        let add_object = envelope::Message {
            msg_type: envelope::UBUS_MSG_ADD_OBJECT,
            seq: seq2,
            peer,
            attrs: vec![
                (envelope::ATTR_OBJPATH, name.as_bytes().to_vec()),
                (envelope::ATTR_SIGNATURE, blobmsg::encode_table(&signature)),
            ],
        };
        if stream.write_all(&envelope::encode(&add_object)).is_err() {
            return None;
        }
        let Some(reply2) = read_one_message(&mut stream, &mut buf) else {
            return Some("UBus command failed: no reply to add_object".to_string());
        };
        if let Some(status_bytes) = reply2.get(envelope::ATTR_STATUS) {
            if let Ok(raw) = <[u8; 4]>::try_from(status_bytes) {
                let status = u32::from_be_bytes(raw);
                if status != UBUS_STATUS_OK {
                    return Some(format!("UBus command failed: {status}"));
                }
            }
        }
        let object_id = reply2
            .get(envelope::ATTR_OBJID)
            .and_then(|b| <[u8; 4]>::try_from(b).ok())
            .map(u32::from_be_bytes)
            .unwrap_or(0);

        let _ = stream.set_nonblocking(true);
        let mut rt = runtime().lock().unwrap();
        rt.stream = Some(stream);
        rt.peer = peer;
        rt.object_id = object_id;
        rt.has_subscribers = false;
        // Anything left in `buf` beyond the ADD_OBJECT reply — e.g. a
        // pipelined SUBSCRIBE — carries over for `check_ubus_listeners_once`
        // to pick up, instead of being dropped when `buf` goes out of scope.
        rt.pending = buf;
        None
    }

    /// `check_ubus_listeners()` (ubus.c:148-172), adapted for this port's
    /// tokio runtime: rather than a raw `poll()` readiness bit, this reads
    /// whatever is currently available on the (non-blocking) socket and
    /// returns any complete `INVOKE` requests for the caller to dispatch —
    /// `run_ubus_task` calls this on a short interval instead of waiting on
    /// `poll_listen`/`poll_check`. `SUBSCRIBE`/`UNSUBSCRIBE` update
    /// `has_subscribers` directly; a closed or errored socket is torn down
    /// (`ubus_destroy()`'s effect, ubus.c:82-90 — dropped connection,
    /// forgotten object id) exactly like the hangup/error branch upstream.
    pub fn check_ubus_listeners_once() -> Vec<envelope::Message> {
        let mut rt = runtime().lock().unwrap();
        // Destructure through one single `DerefMut` of the `MutexGuard` so
        // the borrow checker sees `stream_opt`/`pending`/`has_subscribers`/
        // `object_id` as disjoint fields — going through `rt.stream.as_mut()`
        // and then `rt.pending` separately each re-derefs the guard and
        // therefore (from the checker's point of view) re-borrows the whole
        // `Runtime`, which conflicts with the still-live `stream` borrow.
        let Runtime { stream: stream_opt, pending, has_subscribers, object_id, .. } = &mut *rt;
        let Some(stream) = stream_opt.as_mut() else { return Vec::new() };

        let mut chunk = [0u8; 4096];
        let mut closed = false;
        loop {
            match stream.read(&mut chunk) {
                Ok(0) => {
                    closed = true;
                    break;
                }
                Ok(n) => pending.extend_from_slice(&chunk[..n]),
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(_) => {
                    closed = true;
                    break;
                }
            }
        }
        if closed {
            *stream_opt = None;
            *object_id = 0;
            *has_subscribers = false;
            pending.clear();
            return Vec::new();
        }

        let mut invokes = Vec::new();
        loop {
            match envelope::decode(pending) {
                Ok((msg, consumed)) => {
                    pending.drain(0..consumed);
                    match msg.msg_type {
                        envelope::UBUS_MSG_INVOKE => invokes.push(msg),
                        envelope::UBUS_MSG_SUBSCRIBE => *has_subscribers = true,
                        envelope::UBUS_MSG_UNSUBSCRIBE => *has_subscribers = false,
                        _ => {}
                    }
                }
                Err(_) => break,
            }
        }
        invokes
    }

    /// Reply to one `INVOKE` (`ubus_send_reply` + the implicit status
    /// completion): a `DATA` frame carrying the blobmsg reply (when `Ok`),
    /// followed by a `STATUS` frame with the result code.
    pub fn send_invoke_reply(seq: u16, peer: u32, result: Result<Vec<u8>, u32>) {
        let mut rt = runtime().lock().unwrap();
        let object_id = rt.object_id;
        let Some(stream) = rt.stream.as_mut() else { return };
        let status = match result {
            Ok(data) => {
                let msg = envelope::Message {
                    msg_type: envelope::UBUS_MSG_DATA,
                    seq,
                    peer,
                    attrs: vec![
                        (envelope::ATTR_OBJID, object_id.to_be_bytes().to_vec()),
                        (envelope::ATTR_DATA, data),
                    ],
                };
                let _ = stream.write_all(&envelope::encode(&msg));
                UBUS_STATUS_OK
            }
            Err(code) => code,
        };
        let status_msg = envelope::Message {
            msg_type: envelope::UBUS_MSG_STATUS,
            seq,
            peer,
            attrs: vec![(envelope::ATTR_STATUS, status.to_be_bytes().to_vec())],
        };
        let _ = stream.write_all(&envelope::encode(&status_msg));
    }

    /// `ubus_notify(ubus, &ubus_object, type, b.head, ...)`, gated exactly
    /// like upstream on both a live connection and `ubus_object.has_subscribers`
    /// (ubus.c:340-341,361,375) — a query with no subscriber listening for
    /// events never touches the socket.
    pub fn send_notify(event_type: &str, fields: &[(&str, blobmsg::Value)]) {
        let mut rt = runtime().lock().unwrap();
        if !rt.has_subscribers {
            return;
        }
        let seq = rt.next_seq;
        rt.next_seq = rt.next_seq.wrapping_add(1);
        let peer = rt.peer;
        let object_id = rt.object_id;
        let Some(stream) = rt.stream.as_mut() else { return };

        let data = blobmsg::encode_table(fields);
        let msg = envelope::Message {
            msg_type: envelope::UBUS_MSG_NOTIFY,
            seq,
            peer,
            attrs: vec![
                (envelope::ATTR_OBJID, object_id.to_be_bytes().to_vec()),
                (envelope::ATTR_METHOD, event_type.as_bytes().to_vec()),
                (envelope::ATTR_DATA, data),
            ],
        };
        let _ = stream.write_all(&envelope::encode(&msg));
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::os::unix::net::UnixListener;

        fn temp_socket_path(tag: &str) -> std::path::PathBuf {
            let dir = std::env::temp_dir()
                .join(format!("dnsmasq-rs-ubus-test-{tag}-{}", std::process::id()));
            std::fs::create_dir_all(&dir).unwrap();
            let _ = std::fs::remove_file(dir.join("ubus.sock"));
            dir.join("ubus.sock")
        }

        /// `ubus_init` against a mock `ubusd`: accepts the connection,
        /// answers `HELLO` with an assigned peer id, then answers
        /// `ADD_OBJECT` with an object id — exercising this port's own
        /// handshake/framing logic end-to-end (not a claim of byte-for-byte
        /// compatibility with a real `ubusd`; see the module doc).
        #[test]
        fn ubus_init_stores_peer_and_object_id_from_a_mock_ubusd() {
            let _guard = test_lock();
            reset_for_test();
            let sock_path = temp_socket_path("init");
            let listener = UnixListener::bind(&sock_path).unwrap();

            let server = std::thread::spawn(move || {
                let (mut conn, _) = listener.accept().unwrap();
                let mut buf = Vec::new();
                let hello = read_one_message(&mut conn, &mut buf).unwrap();
                assert_eq!(hello.msg_type, envelope::UBUS_MSG_HELLO);
                let hello_reply = envelope::Message {
                    msg_type: envelope::UBUS_MSG_STATUS,
                    seq: hello.seq,
                    peer: 99,
                    attrs: vec![],
                };
                conn.write_all(&envelope::encode(&hello_reply)).unwrap();

                let add_obj = read_one_message(&mut conn, &mut buf).unwrap();
                assert_eq!(add_obj.msg_type, envelope::UBUS_MSG_ADD_OBJECT);
                assert_eq!(add_obj.get(envelope::ATTR_OBJPATH), Some(b"dnsmasq".as_slice()));
                let add_reply = envelope::Message {
                    msg_type: envelope::UBUS_MSG_STATUS,
                    seq: add_obj.seq,
                    peer: 99,
                    attrs: vec![
                        (envelope::ATTR_STATUS, 0u32.to_be_bytes().to_vec()),
                        (envelope::ATTR_OBJID, 555u32.to_be_bytes().to_vec()),
                    ],
                };
                conn.write_all(&envelope::encode(&add_reply)).unwrap();
            });

            let err = ubus_init_at("dnsmasq", sock_path.to_str().unwrap());
            server.join().unwrap();
            assert_eq!(err, None);

            let rt = runtime().lock().unwrap();
            assert!(rt.stream.is_some());
            assert_eq!(rt.peer, 99);
            assert_eq!(rt.object_id, 555);
            drop(rt);
            let _ = std::fs::remove_dir_all(sock_path.parent().unwrap());
        }

        #[test]
        fn ubus_init_with_no_listener_returns_none_without_panicking() {
            let _guard = test_lock();
            reset_for_test();
            let sock_path = temp_socket_path("no-listener");
            // Nothing is bound at `sock_path` — connect fails.
            assert_eq!(ubus_init_at("dnsmasq", sock_path.to_str().unwrap()), None);
            let rt = runtime().lock().unwrap();
            assert!(rt.stream.is_none());
        }

        #[test]
        fn notify_is_a_no_op_without_subscribers() {
            let _guard = test_lock();
            reset_for_test();
            let sock_path = temp_socket_path("notify-gate");
            let listener = UnixListener::bind(&sock_path).unwrap();
            let server = std::thread::spawn(move || listener.accept());

            assert_eq!(ubus_init_at_stub_connect_only(&sock_path), true);
            server.join().unwrap().unwrap();

            // Connected, but no subscribers: `send_notify` must not write
            // anything a peer could read as a spurious event.
            set_subscribers_for_test(false);
            send_notify("dhcp.ack", &[("mac", blobmsg::Value::Str("aa:bb".into()))]);

            let (connected, has_subscribers) = subscriber_state_for_test();
            assert!(connected);
            assert!(!has_subscribers);
            let _ = std::fs::remove_dir_all(sock_path.parent().unwrap());
        }

        /// Minimal connect-only helper for the notify-gating test above,
        /// which only needs a live `stream`, not a full handshake.
        fn ubus_init_at_stub_connect_only(sock_path: &std::path::Path) -> bool {
            let Ok(stream) = UnixStream::connect(sock_path) else { return false };
            let _ = stream.set_nonblocking(true);
            let mut rt = runtime().lock().unwrap();
            rt.stream = Some(stream);
            true
        }
    }
}

#[cfg(unix)]
pub use connection::ubus_init;

/// A handle to shared daemon state, held by [`run_ubus_task`] for the
/// duration of the connection so RPC handlers (`set_connmark_allowlist`)
/// can mutate live config the same way the config-reload path does.
#[cfg(unix)]
pub struct UbusContext {
    pub daemon: crate::dnsmasq::DaemonHandle,
}

#[cfg(unix)]
async fn dispatch_invoke(
    #[cfg_attr(not(feature = "conntrack"), allow(unused_variables))] daemon: &crate::dnsmasq::DaemonHandle,
    method: &str,
    data: Option<&[u8]>,
) -> Result<Vec<u8>, u32> {
    match method {
        "metrics" => Ok(handle_metrics()),
        #[cfg(feature = "conntrack")]
        "set_connmark_allowlist" => handle_set_connmark_allowlist(daemon, data).await,
        _ => Err(UBUS_STATUS_METHOD_NOT_FOUND),
    }
}

/// `ubus_handle_metrics()` (ubus.c:184-201): every daemon metric as a
/// `blobmsg` table of `u32` counters.
fn handle_metrics() -> Vec<u8> {
    use crate::metrics::{get_metric, metric_name, Metric};

    const ALL: &[Metric] = &[
        Metric::DnsCacheInserted,
        Metric::DnsCacheLiveFreed,
        Metric::DnsQueriesForwarded,
        Metric::DnsAuthAnswered,
        Metric::DnsLocalAnswered,
        Metric::DnsStaleAnswered,
        Metric::DnsUnansweredQuery,
        Metric::CryptoHwm,
        Metric::SigFailHwm,
        Metric::WorkHwm,
        Metric::Bootp,
        Metric::Pxe,
        Metric::Dhcpack,
        Metric::Dhcpdecline,
        Metric::Dhcpdiscover,
        Metric::Dhcpinform,
        Metric::Dhcpnak,
        Metric::Dhcpoffer,
        Metric::Dhcprelease,
        Metric::Dhcprequest,
        Metric::Noanswer,
        Metric::LeasesAllocated4,
        Metric::LeasesPruned4,
        Metric::LeasesAllocated6,
        Metric::LeasesPruned6,
        Metric::TcpConnections,
        Metric::Dhcpleasequery,
        Metric::Dhcpleaseunassigned,
        Metric::Dhcpleaseactive,
        Metric::Dhcpleaseunknown,
    ];
    let fields: Vec<(&str, blobmsg::Value)> =
        ALL.iter().map(|&m| (metric_name(m), blobmsg::Value::I32(get_metric(m) as i32))).collect();
    blobmsg::encode_table(&fields)
}

/// `ubus_handle_set_connmark_allowlist()` (ubus.c:204-321, `HAVE_CONNTRACK`):
/// parse `{mark, mask?, patterns?}` and replace any existing
/// `daemon.allowlists` entry for that `(mark, mask)` pair — same
/// remove-then-prepend semantics as the upstream linked-list walk.
#[cfg(all(unix, feature = "conntrack"))]
async fn handle_set_connmark_allowlist(
    daemon: &crate::dnsmasq::DaemonHandle,
    data: Option<&[u8]>,
) -> Result<Vec<u8>, u32> {
    let data = data.ok_or(UBUS_STATUS_INVALID_ARGUMENT)?;
    let parsed = blobmsg::decode(data).map_err(|_| UBUS_STATUS_INVALID_ARGUMENT)?;

    let mark = parsed.get("mark").and_then(blobmsg::Value::as_u32).ok_or(UBUS_STATUS_INVALID_ARGUMENT)?;
    if mark == 0 {
        return Err(UBUS_STATUS_INVALID_ARGUMENT);
    }

    let mask = match parsed.get("mask").and_then(blobmsg::Value::as_u32) {
        Some(0) => return Err(UBUS_STATUS_INVALID_ARGUMENT),
        Some(m) => {
            if mark & !m != 0 {
                return Err(UBUS_STATUS_INVALID_ARGUMENT);
            }
            m
        }
        None => u32::MAX,
    };

    let mut patterns = Vec::new();
    if let Some(list) = parsed.get("patterns").and_then(blobmsg::Value::as_array) {
        for item in list {
            let pattern = item.as_str().ok_or(UBUS_STATUS_INVALID_ARGUMENT)?;
            if pattern != "*" && !crate::pattern::is_valid_dns_name_pattern(pattern) {
                return Err(UBUS_STATUS_INVALID_ARGUMENT);
            }
            patterns.push(pattern.to_string());
        }
    }

    let mut d = daemon.write().await;
    d.allowlists.retain(|a| !(a.mark == mark && a.mask == mask));
    if !patterns.is_empty() {
        d.allowlists.insert(0, crate::types::network::Allowlist { mark, mask, patterns });
    }
    Ok(blobmsg::encode_table(&[]))
}

/// `set_ubus_listeners()`/`check_ubus_listeners()` (ubus.c:128-172) plus
/// the reconnect loop implicit in `ubus_disconnect_cb`/`ubus_reconnect`
/// (ubus.c:92-103), collapsed into one task: this codebase has no raw
/// `poll()` loop to hook a listener into, so this polls the connection on
/// a short interval instead, reconnecting via [`ubus_init`] whenever it
/// finds itself disconnected.
#[cfg(unix)]
pub async fn run_ubus_task(ctx: UbusContext) {
    loop {
        if !connection::is_connected() {
            let name = {
                let d = ctx.daemon.read().await;
                d.ubus_name.clone().unwrap_or_else(|| "dnsmasq".to_string())
            };
            let _ = ubus_init(&name);
            if !connection::is_connected() {
                tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                continue;
            }
        }

        for msg in connection::check_ubus_listeners_once() {
            let method = msg
                .get(envelope::ATTR_METHOD)
                .and_then(|b| std::str::from_utf8(b).ok())
                .unwrap_or_default()
                .to_string();
            let data = msg.get(envelope::ATTR_DATA).map(|b| b.to_vec());
            let result = dispatch_invoke(&ctx.daemon, &method, data.as_deref()).await;
            connection::send_invoke_reply(msg.seq, msg.peer, result);
        }

        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    }
}

/// `ubus_event_bcast()` (ubus.c:336-354): the generic DHCP lease-event
/// emitter, wired into DHCPACK/DHCPRELEASE handling in [`crate::dhcp`].
#[cfg(unix)]
pub fn ubus_event_bcast(event_type: &str, mac: Option<&str>, ip: Option<&str>, name: Option<&str>, interface: Option<&str>) {
    let mut fields: Vec<(&str, blobmsg::Value)> = Vec::new();
    if let Some(v) = mac {
        fields.push(("mac", blobmsg::Value::Str(v.to_string())));
    }
    if let Some(v) = ip {
        fields.push(("ip", blobmsg::Value::Str(v.to_string())));
    }
    if let Some(v) = name {
        fields.push(("name", blobmsg::Value::Str(v.to_string())));
    }
    if let Some(v) = interface {
        fields.push(("interface", blobmsg::Value::Str(v.to_string())));
    }
    connection::send_notify(event_type, &fields);
}

#[cfg(not(unix))]
pub fn ubus_event_bcast(_event_type: &str, _mac: Option<&str>, _ip: Option<&str>, _name: Option<&str>, _interface: Option<&str>) {}

/// Broadcast one resolved name → target mapping (a CNAME target, or a
/// stringified A/AAAA address) as a `connmark_allowlist_resolved` ubus
/// event (`ubus_event_bcast_connmark_allowlist_resolved()`, ubus.c:371-386).
/// Called from [`crate::forward`]. Gated on a live connection *and*
/// `has_subscribers`, exactly like upstream — previously this fired
/// unconditionally at whatever happened to be listening on the well-known
/// socket path.
#[cfg(unix)]
pub fn ubus_event_bcast_connmark_allowlist_resolved(mark: u32, name: &str, target: &str, ttl: u32) {
    connection::send_notify(
        "connmark-allowlist.resolved",
        &[
            ("mark", blobmsg::Value::I32(mark as i32)),
            ("name", blobmsg::Value::Str(name.to_string())),
            ("value", blobmsg::Value::Str(target.to_string())),
            ("ttl", blobmsg::Value::I32(ttl as i32)),
        ],
    );
}

#[cfg(not(unix))]
pub fn ubus_event_bcast_connmark_allowlist_resolved(_mark: u32, _name: &str, _target: &str, _ttl: u32) {}

/// `ubus_event_bcast_connmark_allowlist_refused()` (ubus.c:357-369). Same
/// gating as [`ubus_event_bcast_connmark_allowlist_resolved`].
#[cfg(unix)]
pub fn ubus_event_bcast_connmark_allowlist_refused(mark: u32, name: &str) {
    connection::send_notify(
        "connmark-allowlist.refused",
        &[("mark", blobmsg::Value::I32(mark as i32)), ("name", blobmsg::Value::Str(name.to_string()))],
    );
}

#[cfg(not(unix))]
pub fn ubus_event_bcast_connmark_allowlist_refused(_mark: u32, _name: &str) {}

#[cfg(all(unix, test))]
mod integration_tests {
    use super::*;
    use std::io::{Read, Write};
    use std::os::unix::net::{UnixListener, UnixStream};

    fn temp_socket_path(tag: &str) -> std::path::PathBuf {
        let dir =
            std::env::temp_dir().join(format!("dnsmasq-rs-ubus-itest-{tag}-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let _ = std::fs::remove_file(dir.join("ubus.sock"));
        dir.join("ubus.sock")
    }

    /// End-to-end: `ubus_init` connects and registers the object, a
    /// subscriber toggles `has_subscribers` on via a `SUBSCRIBE` frame, and
    /// a broadcast then actually reaches the peer as a real `blobmsg`
    /// `NOTIFY` — the whole point of replacing the invented text protocol.
    #[test]
    fn event_reaches_a_subscribed_peer_as_a_real_blobmsg_notify() {
        let _guard = connection::test_lock();
        connection::reset_for_test();
        let sock_path = temp_socket_path("e2e");
        let listener = UnixListener::bind(&sock_path).unwrap();

        let server = std::thread::spawn(move || {
            let (mut conn, _) = listener.accept().unwrap();
            let mut buf = Vec::new();
            let hello = read_msg(&mut conn, &mut buf);
            write_msg(&mut conn, envelope::UBUS_MSG_STATUS, hello.seq, 7, &[]);
            let add_obj = read_msg(&mut conn, &mut buf);
            write_msg(
                &mut conn,
                envelope::UBUS_MSG_STATUS,
                add_obj.seq,
                7,
                &[
                    (envelope::ATTR_STATUS, 0u32.to_be_bytes().to_vec()),
                    (envelope::ATTR_OBJID, 42u32.to_be_bytes().to_vec()),
                ],
            );

            // Subscribe, then read the broadcast NOTIFY the test triggers.
            write_msg(&mut conn, envelope::UBUS_MSG_SUBSCRIBE, 0, 7, &[]);
            // Give the poller a moment to observe the SUBSCRIBE frame.
            std::thread::sleep(std::time::Duration::from_millis(50));

            read_msg(&mut conn, &mut buf)
        });

        assert_eq!(connection::ubus_init_at("dnsmasq", sock_path.to_str().unwrap()), None);
        // Drive the "poll loop" manually (this test doesn't spin up the
        // full tokio task) so the SUBSCRIBE frame is actually observed.
        for _ in 0..20 {
            if connection::check_ubus_listeners_once().is_empty()
                && connection::subscriber_state_for_test().1
            {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }

        ubus_event_bcast("dhcp.ack", Some("aa:bb:cc:dd:ee:ff"), Some("192.168.1.50"), Some("host1"), Some("eth0"));

        let notify = server.join().unwrap();
        assert_eq!(notify.msg_type, envelope::UBUS_MSG_NOTIFY);
        assert_eq!(notify.get(envelope::ATTR_METHOD), Some(b"dhcp.ack".as_slice()));
        let data = notify.get(envelope::ATTR_DATA).unwrap();
        let decoded = blobmsg::decode(data).unwrap();
        assert_eq!(decoded.get("mac").and_then(blobmsg::Value::as_str), Some("aa:bb:cc:dd:ee:ff"));
        assert_eq!(decoded.get("ip").and_then(blobmsg::Value::as_str), Some("192.168.1.50"));
        assert_eq!(decoded.get("name").and_then(blobmsg::Value::as_str), Some("host1"));
        assert_eq!(decoded.get("interface").and_then(blobmsg::Value::as_str), Some("eth0"));

        let _ = std::fs::remove_dir_all(sock_path.parent().unwrap());
    }

    /// No subscriber ever showed up: the same broadcast must not reach the
    /// peer at all (`ubus_object.has_subscribers` gate, ubus.c:340).
    #[test]
    fn event_does_not_reach_an_unsubscribed_peer() {
        let _guard = connection::test_lock();
        connection::reset_for_test();
        let sock_path = temp_socket_path("no-sub");
        let listener = UnixListener::bind(&sock_path).unwrap();

        let server = std::thread::spawn(move || {
            let (mut conn, _) = listener.accept().unwrap();
            let mut buf = Vec::new();
            let hello = read_msg(&mut conn, &mut buf);
            write_msg(&mut conn, envelope::UBUS_MSG_STATUS, hello.seq, 7, &[]);
            let add_obj = read_msg(&mut conn, &mut buf);
            write_msg(
                &mut conn,
                envelope::UBUS_MSG_STATUS,
                add_obj.seq,
                7,
                &[
                    (envelope::ATTR_STATUS, 0u32.to_be_bytes().to_vec()),
                    (envelope::ATTR_OBJID, 42u32.to_be_bytes().to_vec()),
                ],
            );
            conn.set_read_timeout(Some(std::time::Duration::from_millis(200))).unwrap();
            let mut buf = [0u8; 16];
            matches!(conn.read(&mut buf), Ok(0) | Err(_))
        });

        assert_eq!(connection::ubus_init_at("dnsmasq", sock_path.to_str().unwrap()), None);
        ubus_event_bcast("dhcp.ack", Some("aa:bb"), None, None, None);
        assert!(server.join().unwrap());

        let _ = std::fs::remove_dir_all(sock_path.parent().unwrap());
    }

    /// Reads one message, draining exactly its bytes from `buf` and leaving
    /// anything pipelined behind it (e.g. a `DATA` reply immediately
    /// followed by its `STATUS` completion, delivered in one `read()`) for
    /// the next call — the same persistent-accumulator requirement as
    /// `connection::read_one_message`.
    fn read_msg(conn: &mut UnixStream, buf: &mut Vec<u8>) -> envelope::Message {
        let mut chunk = [0u8; 512];
        loop {
            if let Ok((msg, consumed)) = envelope::decode(buf) {
                buf.drain(0..consumed);
                return msg;
            }
            let n = conn.read(&mut chunk).unwrap();
            assert!(n > 0, "peer closed before a full message arrived");
            buf.extend_from_slice(&chunk[..n]);
        }
    }

    fn write_msg(conn: &mut UnixStream, msg_type: u8, seq: u16, peer: u32, attrs: &[(u8, Vec<u8>)]) {
        let msg = envelope::Message { msg_type, seq, peer, attrs: attrs.to_vec() };
        conn.write_all(&envelope::encode(&msg)).unwrap();
    }

    /// `run_ubus_task` end-to-end: a mock `ubusd` completes the handshake,
    /// sends an `INVOKE` for `"metrics"`, and gets back a `DATA` reply whose
    /// blobmsg table has a real metric field, followed by an OK `STATUS` —
    /// exercising `dispatch_invoke`/`handle_metrics` through the actual
    /// task loop, not just called directly.
    #[tokio::test]
    async fn run_ubus_task_answers_a_metrics_invoke_from_a_mock_ubusd() {
        let _guard = connection::test_lock();
        connection::reset_for_test();
        let sock_path = temp_socket_path("invoke-metrics");
        let listener = UnixListener::bind(&sock_path).unwrap();

        let server = std::thread::spawn(move || {
            let (mut conn, _) = listener.accept().unwrap();
            conn.set_read_timeout(Some(std::time::Duration::from_secs(3))).unwrap();
            let mut buf = Vec::new();
            let hello = read_msg(&mut conn, &mut buf);
            write_msg(&mut conn, envelope::UBUS_MSG_STATUS, hello.seq, 7, &[]);
            let add_obj = read_msg(&mut conn, &mut buf);
            write_msg(
                &mut conn,
                envelope::UBUS_MSG_STATUS,
                add_obj.seq,
                7,
                &[
                    (envelope::ATTR_STATUS, 0u32.to_be_bytes().to_vec()),
                    (envelope::ATTR_OBJID, 42u32.to_be_bytes().to_vec()),
                ],
            );

            write_msg(
                &mut conn,
                envelope::UBUS_MSG_INVOKE,
                123,
                7,
                &[(envelope::ATTR_METHOD, b"metrics".to_vec())],
            );

            let data_reply = read_msg(&mut conn, &mut buf);
            let status_reply = read_msg(&mut conn, &mut buf);
            (data_reply, status_reply)
        });

        let daemon = crate::dnsmasq::init_daemon();
        {
            let mut d = daemon.write().await;
            d.ubus_name = Some("dnsmasq".to_string());
        }
        // Point this run at the mock socket rather than the real
        // `/var/run/ubus.sock` well-known path.
        assert_eq!(connection::ubus_init_at("dnsmasq", sock_path.to_str().unwrap()), None);

        let ctx = UbusContext { daemon };
        let task = tokio::spawn(run_ubus_task(ctx));
        // The task's own reconnect branch is now moot (already connected);
        // give it a few poll ticks to observe and answer the INVOKE.
        tokio::time::sleep(std::time::Duration::from_millis(400)).await;
        task.abort();

        let (data_reply, status_reply) = server.join().unwrap();
        assert_eq!(data_reply.msg_type, envelope::UBUS_MSG_DATA);
        assert_eq!(data_reply.seq, 123);
        let table = blobmsg::decode(data_reply.get(envelope::ATTR_DATA).unwrap()).unwrap();
        assert!(table.get("dns_cache_inserted").is_some());

        assert_eq!(status_reply.msg_type, envelope::UBUS_MSG_STATUS);
        let status = u32::from_be_bytes(status_reply.get(envelope::ATTR_STATUS).unwrap().try_into().unwrap());
        assert_eq!(status, UBUS_STATUS_OK);

        let _ = std::fs::remove_dir_all(sock_path.parent().unwrap());
    }
}

#[cfg(all(unix, test))]
mod dispatch_tests {
    use super::*;

    #[tokio::test]
    async fn metrics_reply_contains_every_metric_name() {
        let daemon = crate::dnsmasq::init_daemon();
        let reply = dispatch_invoke(&daemon, "metrics", None).await.unwrap();
        let table = blobmsg::decode(&reply).unwrap();
        assert!(table.get("dns_queries_forwarded").is_some());
        assert!(table.get("dhcp_ack").is_some());
    }

    #[tokio::test]
    async fn unknown_method_is_method_not_found() {
        let daemon = crate::dnsmasq::init_daemon();
        let err = dispatch_invoke(&daemon, "no_such_method", None).await.unwrap_err();
        assert_eq!(err, UBUS_STATUS_METHOD_NOT_FOUND);
    }

    #[cfg(feature = "conntrack")]
    #[tokio::test]
    async fn set_connmark_allowlist_adds_an_entry_to_the_daemon() {
        let daemon = crate::dnsmasq::init_daemon();
        let request = blobmsg::encode_table(&[
            ("mark", blobmsg::Value::I32(6)),
            (
                "patterns",
                blobmsg::Value::Array(vec![blobmsg::Value::Str("*.example.com".to_string())]),
            ),
        ]);

        let reply = dispatch_invoke(&daemon, "set_connmark_allowlist", Some(&request)).await;
        assert!(reply.is_ok());

        let d = daemon.read().await;
        assert_eq!(d.allowlists.len(), 1);
        assert_eq!(d.allowlists[0].mark, 6);
        assert_eq!(d.allowlists[0].patterns, vec!["*.example.com".to_string()]);
    }

    #[cfg(feature = "conntrack")]
    #[tokio::test]
    async fn set_connmark_allowlist_replaces_an_existing_entry_for_the_same_mark_and_mask() {
        let daemon = crate::dnsmasq::init_daemon();
        {
            let mut d = daemon.write().await;
            d.allowlists.push(crate::types::network::Allowlist {
                mark: 6,
                mask: u32::MAX,
                patterns: vec!["old.example.com".to_string()],
            });
        }
        let request = blobmsg::encode_table(&[
            ("mark", blobmsg::Value::I32(6)),
            ("patterns", blobmsg::Value::Array(vec![blobmsg::Value::Str("new.example.com".to_string())])),
        ]);

        dispatch_invoke(&daemon, "set_connmark_allowlist", Some(&request)).await.unwrap();

        let d = daemon.read().await;
        assert_eq!(d.allowlists.len(), 1);
        assert_eq!(d.allowlists[0].patterns, vec!["new.example.com".to_string()]);
    }

    #[cfg(feature = "conntrack")]
    #[tokio::test]
    async fn set_connmark_allowlist_rejects_a_zero_mark() {
        let daemon = crate::dnsmasq::init_daemon();
        let request = blobmsg::encode_table(&[("mark", blobmsg::Value::I32(0))]);
        let err = dispatch_invoke(&daemon, "set_connmark_allowlist", Some(&request)).await.unwrap_err();
        assert_eq!(err, UBUS_STATUS_INVALID_ARGUMENT);
    }

    #[cfg(feature = "conntrack")]
    #[tokio::test]
    async fn set_connmark_allowlist_rejects_an_invalid_pattern() {
        let daemon = crate::dnsmasq::init_daemon();
        let request = blobmsg::encode_table(&[
            ("mark", blobmsg::Value::I32(6)),
            ("patterns", blobmsg::Value::Array(vec![blobmsg::Value::Str("".to_string())])),
        ]);
        let err = dispatch_invoke(&daemon, "set_connmark_allowlist", Some(&request)).await.unwrap_err();
        assert_eq!(err, UBUS_STATUS_INVALID_ARGUMENT);
    }

    #[cfg(feature = "conntrack")]
    #[tokio::test]
    async fn set_connmark_allowlist_wildcard_pattern_is_accepted() {
        let daemon = crate::dnsmasq::init_daemon();
        let request = blobmsg::encode_table(&[
            ("mark", blobmsg::Value::I32(6)),
            ("patterns", blobmsg::Value::Array(vec![blobmsg::Value::Str("*".to_string())])),
        ]);
        assert!(dispatch_invoke(&daemon, "set_connmark_allowlist", Some(&request)).await.is_ok());
    }
}
