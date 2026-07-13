//! Strict, byte-only parser for the repository-import SHA-1 index profile.
//!
//! The parser intentionally understands less than Git. It accepts only normal
//! stage-zero `100644` entries and a small, frozen set of optional extensions.
//! Split and sparse indexes remain outside the import profile. `IEOT` is
//! validated independently against the parsed entry region; when `EOIE` is
//! present, it must independently bind the true entry end and extension headers.

use std::collections::BTreeSet;
use std::fmt;

use sha1::{Digest, Sha1};

const INDEX_SIGNATURE: &[u8; 4] = b"DIRC";
const HEADER_BYTES: usize = 12;
const SHA1_BYTES: usize = 20;
const FIXED_ENTRY_BYTES: usize = 62;
const REGULAR_FILE_MODE: u32 = 0o100_644;
const NAME_LENGTH_MASK: u16 = 0x0fff;
const ENTRY_FLAG_MASK: u16 = 0xf000;
const MAX_INDEX_BYTES: usize = 64 * 1024 * 1024;
const MAX_INDEX_ENTRIES: usize = 100_000;
const MAX_PATH_BYTES: usize = 1024;
const MAX_RETAINED_PATH_BYTES: usize = 256 * 1024 * 1024;
const MAX_PATH_COMPONENTS: usize = 128;
const EOIE_DATA_BYTES: usize = 4 + SHA1_BYTES;

const TREE_EXTENSION: [u8; 4] = *b"TREE";
const REUC_EXTENSION: [u8; 4] = *b"REUC";
const UNTR_EXTENSION: [u8; 4] = *b"UNTR";
const FSMN_EXTENSION: [u8; 4] = *b"FSMN";
const EOIE_EXTENSION: [u8; 4] = *b"EOIE";
const IEOT_EXTENSION: [u8; 4] = *b"IEOT";

/// One normal entry proven directly from the raw SHA-1 index bytes.
#[derive(Clone, Eq, PartialEq)]
pub(super) struct RawIndexEntry {
    pub(super) path: Vec<u8>,
    pub(super) oid: [u8; SHA1_BYTES],
}

impl fmt::Debug for RawIndexEntry {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RawIndexEntry")
            .field("path", &"[REDACTED]")
            .field("oid", &"[REDACTED]")
            .finish()
    }
}

/// The minimal semantic result consumed by repository-import verification.
#[derive(Clone, Eq, PartialEq)]
pub(super) struct RawIndex {
    pub(super) version: u32,
    pub(super) entries: Vec<RawIndexEntry>,
}

impl fmt::Debug for RawIndex {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RawIndex")
            .field("version", &self.version)
            .field("entry_count", &self.entries.len())
            .finish()
    }
}

/// Scrubbed internal failure classes. No untrusted path bytes are retained.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum RawIndexError {
    Malformed,
    Unsupported,
    ResourceLimit,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ParsedEntry {
    semantic: RawIndexEntry,
    start: usize,
    end: usize,
}

struct Extension<'a> {
    signature: [u8; 4],
    header: &'a [u8],
    data: &'a [u8],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FirstV4Entry {
    IndexStart,
    IndependentBlock,
}

/// Parse and validate a complete traditional SHA-1 Git index.
///
/// An all-zero trailer is the explicit `index.skipHash` representation. Every
/// non-zero trailer must equal SHA-1 over all preceding bytes.
pub(super) fn parse_sha1_index(bytes: &[u8]) -> Result<RawIndex, RawIndexError> {
    if bytes.len() > MAX_INDEX_BYTES {
        return Err(RawIndexError::ResourceLimit);
    }
    let content_end = bytes
        .len()
        .checked_sub(SHA1_BYTES)
        .filter(|end| *end >= HEADER_BYTES)
        .ok_or(RawIndexError::Malformed)?;
    verify_checksum(bytes, content_end)?;

    if bytes.get(..4) != Some(INDEX_SIGNATURE.as_slice()) {
        return Err(RawIndexError::Malformed);
    }
    let version = read_u32(bytes, 4, content_end)?;
    if !matches!(version, 2..=4) {
        return Err(RawIndexError::Unsupported);
    }
    let entry_count = usize::try_from(read_u32(bytes, 8, content_end)?)
        .map_err(|_| RawIndexError::ResourceLimit)?;
    if entry_count > MAX_INDEX_ENTRIES {
        return Err(RawIndexError::ResourceLimit);
    }

    let mut parsed_entries = Vec::new();
    parsed_entries
        .try_reserve(entry_count)
        .map_err(|_| RawIndexError::ResourceLimit)?;
    let mut offset = HEADER_BYTES;
    let mut previous_path: Option<&[u8]> = None;
    let mut retained_path_bytes = 0_usize;
    for _ in 0..entry_count {
        let parsed = parse_entry(
            bytes,
            version,
            offset,
            content_end,
            previous_path,
            FirstV4Entry::IndexStart,
        )?;
        if let Some(previous) = previous_path
            && previous >= parsed.semantic.path.as_slice()
        {
            return Err(RawIndexError::Malformed);
        }
        retained_path_bytes = retained_path_bytes
            .checked_add(parsed.semantic.path.len())
            .filter(|total| *total <= MAX_RETAINED_PATH_BYTES)
            .ok_or(RawIndexError::ResourceLimit)?;
        offset = parsed.end;
        parsed_entries.push(parsed);
        previous_path = parsed_entries
            .last()
            .map(|entry| entry.semantic.path.as_slice());
    }
    let entries_end = offset;
    let extensions = parse_extensions(bytes, entries_end, content_end)?;
    validate_eoie(&extensions, entries_end)?;
    validate_ieot(bytes, version, &parsed_entries, entries_end, &extensions)?;

    Ok(RawIndex {
        version,
        entries: parsed_entries
            .into_iter()
            .map(|entry| entry.semantic)
            .collect(),
    })
}

fn verify_checksum(bytes: &[u8], content_end: usize) -> Result<(), RawIndexError> {
    let trailer = bytes
        .get(content_end..)
        .filter(|trailer| trailer.len() == SHA1_BYTES)
        .ok_or(RawIndexError::Malformed)?;
    if trailer.iter().all(|byte| *byte == 0) {
        return Ok(());
    }
    let digest = Sha1::digest(bytes.get(..content_end).ok_or(RawIndexError::Malformed)?);
    if digest.as_slice() == trailer {
        Ok(())
    } else {
        Err(RawIndexError::Malformed)
    }
}

fn parse_entry(
    bytes: &[u8],
    version: u32,
    start: usize,
    limit: usize,
    previous_path: Option<&[u8]>,
    first_v4_entry: FirstV4Entry,
) -> Result<ParsedEntry, RawIndexError> {
    let fixed_end = start
        .checked_add(FIXED_ENTRY_BYTES)
        .filter(|end| *end <= limit)
        .ok_or(RawIndexError::Malformed)?;
    if read_u32(bytes, start + 24, limit)? != REGULAR_FILE_MODE {
        return Err(RawIndexError::Unsupported);
    }
    let oid_slice = bytes
        .get(start + 40..start + 60)
        .ok_or(RawIndexError::Malformed)?;
    let oid = <[u8; SHA1_BYTES]>::try_from(oid_slice).map_err(|_| RawIndexError::Malformed)?;
    if oid.iter().all(|byte| *byte == 0) {
        return Err(RawIndexError::Unsupported);
    }
    let flags = read_u16(bytes, start + 60, limit)?;
    if flags & ENTRY_FLAG_MASK != 0 {
        return Err(RawIndexError::Unsupported);
    }
    let encoded_name_length = flags & NAME_LENGTH_MASK;

    let (path, end) = if version == 4 {
        parse_v4_path(bytes, fixed_end, limit, previous_path, first_v4_entry)?
    } else {
        parse_v2_v3_path(bytes, start, fixed_end, limit)?
    };
    validate_name_length(encoded_name_length, path.len())?;
    validate_path(&path)?;

    Ok(ParsedEntry {
        semantic: RawIndexEntry { path, oid },
        start,
        end,
    })
}

fn parse_v2_v3_path(
    bytes: &[u8],
    entry_start: usize,
    name_start: usize,
    limit: usize,
) -> Result<(Vec<u8>, usize), RawIndexError> {
    let name_end = bounded_nul(bytes, name_start, limit)?;
    let path = bytes
        .get(name_start..name_end)
        .ok_or(RawIndexError::Malformed)?
        .to_vec();
    let base_length = FIXED_ENTRY_BYTES
        .checked_add(path.len())
        .ok_or(RawIndexError::ResourceLimit)?;
    let padding = 8_usize
        .checked_sub(base_length % 8)
        .ok_or(RawIndexError::Malformed)?;
    let end = entry_start
        .checked_add(base_length)
        .and_then(|value| value.checked_add(padding))
        .filter(|end| *end <= limit)
        .ok_or(RawIndexError::Malformed)?;
    let padding_start = entry_start
        .checked_add(base_length)
        .ok_or(RawIndexError::Malformed)?;
    if bytes
        .get(padding_start..end)
        .ok_or(RawIndexError::Malformed)?
        .iter()
        .any(|byte| *byte != 0)
    {
        return Err(RawIndexError::Malformed);
    }
    Ok((path, end))
}

fn parse_v4_path(
    bytes: &[u8],
    encoded_start: usize,
    limit: usize,
    previous_path: Option<&[u8]>,
    first_v4_entry: FirstV4Entry,
) -> Result<(Vec<u8>, usize), RawIndexError> {
    let (strip, suffix_start) = decode_canonical_varint(bytes, encoded_start, limit)?;
    let suffix_end = bounded_nul(bytes, suffix_start, limit)?;
    let suffix = bytes
        .get(suffix_start..suffix_end)
        .ok_or(RawIndexError::Malformed)?;
    let prefix = match previous_path {
        Some(previous) => {
            let retained = previous
                .len()
                .checked_sub(strip)
                .ok_or(RawIndexError::Malformed)?;
            previous.get(..retained).ok_or(RawIndexError::Malformed)?
        }
        None if first_v4_entry == FirstV4Entry::IndexStart => {
            if strip != 0 {
                return Err(RawIndexError::Malformed);
            }
            &[]
        }
        // Git's IEOT decoder deliberately ignores the strip count for the
        // first entry in each independently decodable block.
        None => &[],
    };
    let path_len = prefix
        .len()
        .checked_add(suffix.len())
        .filter(|length| *length <= MAX_PATH_BYTES)
        .ok_or(RawIndexError::ResourceLimit)?;
    let mut path = Vec::new();
    path.try_reserve(path_len)
        .map_err(|_| RawIndexError::ResourceLimit)?;
    path.extend_from_slice(prefix);
    path.extend_from_slice(suffix);
    let end = suffix_end
        .checked_add(1)
        .filter(|end| *end <= limit)
        .ok_or(RawIndexError::Malformed)?;
    Ok((path, end))
}

fn bounded_nul(bytes: &[u8], start: usize, limit: usize) -> Result<usize, RawIndexError> {
    if start >= limit {
        return Err(RawIndexError::Malformed);
    }
    let maximum_end = start
        .checked_add(MAX_PATH_BYTES + 1)
        .map_or(limit, |end| end.min(limit));
    let candidate = bytes
        .get(start..maximum_end)
        .ok_or(RawIndexError::Malformed)?;
    candidate
        .iter()
        .position(|byte| *byte == 0)
        .map(|relative| start + relative)
        .ok_or({
            if maximum_end < limit {
                RawIndexError::ResourceLimit
            } else {
                RawIndexError::Malformed
            }
        })
}

fn validate_name_length(encoded: u16, actual: usize) -> Result<(), RawIndexError> {
    let expected = if actual >= usize::from(NAME_LENGTH_MASK) {
        NAME_LENGTH_MASK
    } else {
        u16::try_from(actual).map_err(|_| RawIndexError::ResourceLimit)?
    };
    if encoded == expected {
        Ok(())
    } else {
        Err(RawIndexError::Malformed)
    }
}

fn validate_path(path: &[u8]) -> Result<(), RawIndexError> {
    if path.is_empty()
        || path.len() > MAX_PATH_BYTES
        || std::str::from_utf8(path).is_err()
        || path.first() == Some(&b'/')
        || path.last() == Some(&b'/')
        || path.contains(&b'\\')
    {
        return Err(RawIndexError::Unsupported);
    }
    let mut components = 0_usize;
    for component in path.split(|byte| *byte == b'/') {
        components = components
            .checked_add(1)
            .filter(|count| *count <= MAX_PATH_COMPONENTS)
            .ok_or(RawIndexError::ResourceLimit)?;
        if component.is_empty()
            || matches!(component, b"." | b"..")
            || component.eq_ignore_ascii_case(b".git")
        {
            return Err(RawIndexError::Unsupported);
        }
    }
    Ok(())
}

fn parse_extensions(
    bytes: &[u8],
    mut offset: usize,
    content_end: usize,
) -> Result<Vec<Extension<'_>>, RawIndexError> {
    let mut extensions = Vec::new();
    let mut seen = BTreeSet::new();
    while offset < content_end {
        let header_end = offset
            .checked_add(8)
            .filter(|end| *end <= content_end)
            .ok_or(RawIndexError::Malformed)?;
        let signature = <[u8; 4]>::try_from(
            bytes
                .get(offset..offset + 4)
                .ok_or(RawIndexError::Malformed)?,
        )
        .map_err(|_| RawIndexError::Malformed)?;
        if !is_allowed_extension(signature) {
            return Err(RawIndexError::Unsupported);
        }
        if !seen.insert(signature) {
            return Err(RawIndexError::Unsupported);
        }
        let size = usize::try_from(read_u32(bytes, offset + 4, content_end)?)
            .map_err(|_| RawIndexError::ResourceLimit)?;
        let end = header_end
            .checked_add(size)
            .filter(|end| *end <= content_end)
            .ok_or(RawIndexError::Malformed)?;
        if signature == EOIE_EXTENSION && end != content_end {
            return Err(RawIndexError::Malformed);
        }
        extensions.push(Extension {
            signature,
            header: bytes
                .get(offset..header_end)
                .ok_or(RawIndexError::Malformed)?,
            data: bytes.get(header_end..end).ok_or(RawIndexError::Malformed)?,
        });
        offset = end;
    }
    Ok(extensions)
}

fn is_allowed_extension(signature: [u8; 4]) -> bool {
    matches!(
        signature,
        TREE_EXTENSION
            | REUC_EXTENSION
            | UNTR_EXTENSION
            | FSMN_EXTENSION
            | EOIE_EXTENSION
            | IEOT_EXTENSION
    )
}

fn validate_eoie(extensions: &[Extension<'_>], entries_end: usize) -> Result<(), RawIndexError> {
    let Some(eoie_index) = extensions
        .iter()
        .position(|extension| extension.signature == EOIE_EXTENSION)
    else {
        return Ok(());
    };
    if eoie_index + 1 != extensions.len() {
        return Err(RawIndexError::Malformed);
    }
    let eoie = &extensions[eoie_index];
    if eoie.data.len() != EOIE_DATA_BYTES {
        return Err(RawIndexError::Malformed);
    }
    let recorded_offset = usize::try_from(read_u32(eoie.data, 0, eoie.data.len())?)
        .map_err(|_| RawIndexError::ResourceLimit)?;
    if recorded_offset != entries_end {
        return Err(RawIndexError::Malformed);
    }
    let mut hasher = Sha1::new();
    for extension in &extensions[..eoie_index] {
        hasher.update(extension.header);
    }
    let digest = hasher.finalize();
    if eoie.data.get(4..) == Some(digest.as_slice()) {
        Ok(())
    } else {
        Err(RawIndexError::Malformed)
    }
}

fn validate_ieot(
    bytes: &[u8],
    version: u32,
    entries: &[ParsedEntry],
    entries_end: usize,
    extensions: &[Extension<'_>],
) -> Result<(), RawIndexError> {
    let Some(ieot) = extensions
        .iter()
        .find(|extension| extension.signature == IEOT_EXTENSION)
    else {
        return Ok(());
    };
    if ieot.data.len() < 12 || (ieot.data.len() - 4) % 8 != 0 {
        return Err(RawIndexError::Malformed);
    }
    if read_u32(ieot.data, 0, ieot.data.len())? != 1 {
        return Err(RawIndexError::Unsupported);
    }
    let block_count = (ieot.data.len() - 4) / 8;
    if block_count > entries.len() || block_count > MAX_INDEX_ENTRIES {
        return Err(RawIndexError::ResourceLimit);
    }

    let mut entry_index = 0_usize;
    for block_index in 0..block_count {
        let record_offset = 4 + block_index * 8;
        let block_offset = usize::try_from(read_u32(ieot.data, record_offset, ieot.data.len())?)
            .map_err(|_| RawIndexError::ResourceLimit)?;
        let block_entries =
            usize::try_from(read_u32(ieot.data, record_offset + 4, ieot.data.len())?)
                .map_err(|_| RawIndexError::ResourceLimit)?;
        if block_entries == 0 {
            return Err(RawIndexError::Malformed);
        }
        let expected_start = entries
            .get(entry_index)
            .map(|entry| entry.start)
            .ok_or(RawIndexError::Malformed)?;
        if block_offset != expected_start || (block_index == 0 && block_offset != HEADER_BYTES) {
            return Err(RawIndexError::Malformed);
        }
        let next_entry_index = entry_index
            .checked_add(block_entries)
            .filter(|index| *index <= entries.len())
            .ok_or(RawIndexError::Malformed)?;
        let expected_end = entries
            .get(next_entry_index)
            .map_or(entries_end, |entry| entry.start);
        independently_validate_block(
            bytes,
            version,
            &entries[entry_index..next_entry_index],
            block_offset,
            expected_end,
        )?;
        entry_index = next_entry_index;
    }
    if entry_index == entries.len() {
        Ok(())
    } else {
        Err(RawIndexError::Malformed)
    }
}

fn independently_validate_block(
    bytes: &[u8],
    version: u32,
    expected: &[ParsedEntry],
    mut offset: usize,
    limit: usize,
) -> Result<(), RawIndexError> {
    let mut previous_path: Option<Vec<u8>> = None;
    for (index, expected_entry) in expected.iter().enumerate() {
        let parsed = parse_entry(
            bytes,
            version,
            offset,
            limit,
            previous_path.as_deref(),
            if index == 0 {
                FirstV4Entry::IndependentBlock
            } else {
                FirstV4Entry::IndexStart
            },
        )?;
        if parsed.start != expected_entry.start || parsed.semantic != expected_entry.semantic {
            return Err(RawIndexError::Malformed);
        }
        offset = parsed.end;
        previous_path = Some(parsed.semantic.path);
    }
    if offset == limit {
        Ok(())
    } else {
        Err(RawIndexError::Malformed)
    }
}

fn decode_canonical_varint(
    bytes: &[u8],
    start: usize,
    limit: usize,
) -> Result<(usize, usize), RawIndexError> {
    let mut offset = start;
    let first = *bytes
        .get(offset)
        .filter(|_| offset < limit)
        .ok_or(RawIndexError::Malformed)?;
    offset += 1;
    let mut value = usize::from(first & 0x7f);
    let mut current = first;
    while current & 0x80 != 0 {
        current = *bytes
            .get(offset)
            .filter(|_| offset < limit)
            .ok_or(RawIndexError::Malformed)?;
        offset += 1;
        value = value
            .checked_add(1)
            .and_then(|value| value.checked_mul(128))
            .and_then(|value| value.checked_add(usize::from(current & 0x7f)))
            .ok_or(RawIndexError::ResourceLimit)?;
    }
    let encoded = encode_varint(value);
    if bytes.get(start..offset) != Some(encoded.as_slice()) {
        return Err(RawIndexError::Malformed);
    }
    Ok((value, offset))
}

fn encode_varint(mut value: usize) -> Vec<u8> {
    let mut reversed = [0_u8; 16];
    let mut position = reversed.len() - 1;
    reversed[position] = value.to_le_bytes()[0] & 0x7f;
    while {
        value >>= 7;
        value != 0
    } {
        value -= 1;
        position -= 1;
        reversed[position] = 0x80 | (value.to_le_bytes()[0] & 0x7f);
    }
    reversed[position..].to_vec()
}

fn read_u16(bytes: &[u8], offset: usize, limit: usize) -> Result<u16, RawIndexError> {
    let end = offset
        .checked_add(2)
        .filter(|end| *end <= limit)
        .ok_or(RawIndexError::Malformed)?;
    let value = <[u8; 2]>::try_from(bytes.get(offset..end).ok_or(RawIndexError::Malformed)?)
        .map_err(|_| RawIndexError::Malformed)?;
    Ok(u16::from_be_bytes(value))
}

fn read_u32(bytes: &[u8], offset: usize, limit: usize) -> Result<u32, RawIndexError> {
    let end = offset
        .checked_add(4)
        .filter(|end| *end <= limit)
        .ok_or(RawIndexError::Malformed)?;
    let value = <[u8; 4]>::try_from(bytes.get(offset..end).ok_or(RawIndexError::Malformed)?)
        .map_err(|_| RawIndexError::Malformed)?;
    Ok(u32::from_be_bytes(value))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Clone, Copy)]
    enum Checksum {
        Exact,
        Zero,
    }

    struct EntryBytes {
        bytes: Vec<u8>,
        starts: Vec<usize>,
        ends: Vec<usize>,
    }

    fn build_entries(version: u32, paths: &[&[u8]], restarts: &[usize]) -> EntryBytes {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(INDEX_SIGNATURE);
        bytes.extend_from_slice(&version.to_be_bytes());
        bytes.extend_from_slice(
            &u32::try_from(paths.len())
                .expect("test entry count fits u32")
                .to_be_bytes(),
        );
        let mut starts = Vec::new();
        let mut ends = Vec::new();
        let mut previous = Vec::new();
        for (index, path) in paths.iter().enumerate() {
            starts.push(bytes.len());
            bytes.extend_from_slice(&[0_u8; 24]);
            bytes.extend_from_slice(&REGULAR_FILE_MODE.to_be_bytes());
            bytes.extend_from_slice(&[0_u8; 12]);
            bytes.extend_from_slice(&[u8::try_from(index + 1).unwrap_or(1); SHA1_BYTES]);
            let name_length = u16::try_from(path.len().min(usize::from(NAME_LENGTH_MASK)))
                .expect("test path name mask fits u16");
            bytes.extend_from_slice(&name_length.to_be_bytes());
            if version == 4 {
                let common = if index == 0 || restarts.contains(&index) {
                    0
                } else {
                    previous
                        .iter()
                        .zip(path.iter())
                        .take_while(|(left, right)| left == right)
                        .count()
                };
                bytes.extend_from_slice(&encode_varint(previous.len() - common));
                bytes.extend_from_slice(&path[common..]);
                bytes.push(0);
            } else {
                bytes.extend_from_slice(path);
                let base = FIXED_ENTRY_BYTES + path.len();
                bytes.resize(bytes.len() + 8 - base % 8, 0);
            }
            previous = path.to_vec();
            ends.push(bytes.len());
        }
        EntryBytes {
            bytes,
            starts,
            ends,
        }
    }

    fn extension(signature: [u8; 4], data: &[u8]) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&signature);
        bytes.extend_from_slice(
            &u32::try_from(data.len())
                .expect("test extension length fits u32")
                .to_be_bytes(),
        );
        bytes.extend_from_slice(data);
        bytes
    }

    fn ieot_data(starts: &[usize], counts: &[usize]) -> Vec<u8> {
        let mut data = 1_u32.to_be_bytes().to_vec();
        let mut entry = 0_usize;
        for count in counts {
            data.extend_from_slice(
                &u32::try_from(starts[entry])
                    .expect("test index offset fits u32")
                    .to_be_bytes(),
            );
            data.extend_from_slice(
                &u32::try_from(*count)
                    .expect("test block count fits u32")
                    .to_be_bytes(),
            );
            entry += count;
        }
        data
    }

    fn eoie(entries_end: usize, preceding: &[Vec<u8>]) -> Vec<u8> {
        let mut hasher = Sha1::new();
        for value in preceding {
            hasher.update(&value[..8]);
        }
        let mut data = u32::try_from(entries_end)
            .expect("test entry end fits u32")
            .to_be_bytes()
            .to_vec();
        data.extend_from_slice(&hasher.finalize());
        extension(EOIE_EXTENSION, &data)
    }

    fn finish(mut content: Vec<u8>, extensions: &[Vec<u8>], checksum: Checksum) -> Vec<u8> {
        for value in extensions {
            content.extend_from_slice(value);
        }
        match checksum {
            Checksum::Exact => {
                let digest = Sha1::digest(&content);
                content.extend_from_slice(&digest);
            }
            Checksum::Zero => content.extend_from_slice(&[0_u8; SHA1_BYTES]),
        }
        content
    }

    fn resign(bytes: &mut Vec<u8>) {
        bytes.truncate(bytes.len() - SHA1_BYTES);
        let digest = Sha1::digest(bytes.as_slice());
        bytes.extend_from_slice(&digest);
    }

    fn simple(version: u32, paths: &[&[u8]]) -> Vec<u8> {
        finish(
            build_entries(version, paths, &[]).bytes,
            &[],
            Checksum::Exact,
        )
    }

    #[test]
    fn accepts_normal_v2_v3_and_v4_indexes() {
        for version in 2..=4 {
            let bytes = simple(version, &[b"a.md", b"dir/image.png"]);
            let parsed = parse_sha1_index(&bytes).expect("normal index parses");
            assert_eq!(parsed.version, version);
            assert_eq!(parsed.entries.len(), 2);
            assert_eq!(parsed.entries[0].path, b"a.md");
            assert_eq!(parsed.entries[1].path, b"dir/image.png");
            assert_eq!(parsed.entries[0].oid, [1_u8; SHA1_BYTES]);
        }
    }

    #[test]
    fn enforces_exact_or_explicitly_zero_checksum() {
        let exact = simple(2, &[b"note.md"]);
        assert!(parse_sha1_index(&exact).is_ok());

        let zero = finish(
            build_entries(2, &[b"note.md"], &[]).bytes,
            &[],
            Checksum::Zero,
        );
        assert!(parse_sha1_index(&zero).is_ok());

        let mut corrupted = exact;
        corrupted[20] ^= 1;
        assert_eq!(parse_sha1_index(&corrupted), Err(RawIndexError::Malformed));
        let last = corrupted.len() - 1;
        corrupted[last] ^= 1;
        assert_eq!(parse_sha1_index(&corrupted), Err(RawIndexError::Malformed));
    }

    #[test]
    fn rejects_non_normal_modes_oids_and_entry_flags() {
        let baseline = simple(3, &[b"note.md"]);
        for (offset, replacement) in [
            (HEADER_BYTES + 24, 0o100_755_u32.to_be_bytes().to_vec()),
            (HEADER_BYTES + 60, 0x8007_u16.to_be_bytes().to_vec()),
            (HEADER_BYTES + 60, 0x4007_u16.to_be_bytes().to_vec()),
            (HEADER_BYTES + 60, 0x1007_u16.to_be_bytes().to_vec()),
        ] {
            let mut bytes = baseline.clone();
            bytes[offset..offset + replacement.len()].copy_from_slice(&replacement);
            resign(&mut bytes);
            assert!(parse_sha1_index(&bytes).is_err());
        }

        let mut null_oid = baseline;
        null_oid[HEADER_BYTES + 40..HEADER_BYTES + 60].fill(0);
        resign(&mut null_oid);
        assert_eq!(parse_sha1_index(&null_oid), Err(RawIndexError::Unsupported));
    }

    #[test]
    fn rejects_name_length_mismatch_and_nonzero_v2_padding() {
        let mut length = simple(2, &[b"a.md"]);
        length[HEADER_BYTES + 61] = 3;
        resign(&mut length);
        assert_eq!(parse_sha1_index(&length), Err(RawIndexError::Malformed));

        let parts = build_entries(2, &[b"a.md"], &[]);
        let padding_byte = parts.ends[0] - 1;
        let mut padding = finish(parts.bytes, &[], Checksum::Exact);
        padding[padding_byte] = 1;
        resign(&mut padding);
        assert_eq!(parse_sha1_index(&padding), Err(RawIndexError::Malformed));
    }

    #[test]
    fn rejects_unsafe_paths_and_noncanonical_order() {
        for path in [
            b"/absolute".as_slice(),
            b"trailing/".as_slice(),
            b"two//parts".as_slice(),
            b".".as_slice(),
            b"../escape".as_slice(),
            b".git/config".as_slice(),
            b".GIT/config".as_slice(),
            b"windows\\path".as_slice(),
        ] {
            assert_eq!(
                parse_sha1_index(&simple(2, &[path])),
                Err(RawIndexError::Unsupported),
                "path should be outside the frozen profile: {path:?}"
            );
        }
        assert_eq!(
            parse_sha1_index(&simple(2, &[b"z", b"a"])),
            Err(RawIndexError::Malformed)
        );
        assert_eq!(
            parse_sha1_index(&simple(2, &[b"same", b"same"])),
            Err(RawIndexError::Malformed)
        );

        let invalid_utf8 = [b'n', b'o', b't', 0xff];
        assert_eq!(
            parse_sha1_index(&simple(2, &[invalid_utf8.as_slice()])),
            Err(RawIndexError::Unsupported)
        );
    }

    #[test]
    fn enforces_path_and_entry_resource_bounds() {
        let oversized = vec![b'a'; MAX_PATH_BYTES + 1];
        assert_eq!(
            parse_sha1_index(&simple(2, &[oversized.as_slice()])),
            Err(RawIndexError::ResourceLimit)
        );

        let mut too_many = Vec::new();
        too_many.extend_from_slice(INDEX_SIGNATURE);
        too_many.extend_from_slice(&2_u32.to_be_bytes());
        too_many.extend_from_slice(
            &u32::try_from(MAX_INDEX_ENTRIES + 1)
                .expect("test entry bound fits u32")
                .to_be_bytes(),
        );
        too_many.extend_from_slice(&[0_u8; SHA1_BYTES]);
        assert_eq!(
            parse_sha1_index(&too_many),
            Err(RawIndexError::ResourceLimit)
        );
    }

    #[test]
    fn validates_v4_canonical_varints_and_first_entry_semantics() {
        assert_eq!(encode_varint(0), [0x00]);
        assert_eq!(encode_varint(127), [0x7f]);
        assert_eq!(encode_varint(128), [0x80, 0x00]);
        assert_eq!(encode_varint(256), [0x81, 0x00]);
        assert_eq!(encode_varint(16_384), [0xff, 0x00]);

        let mut first_strip = build_entries(4, &[b"note.md"], &[]).bytes;
        first_strip[HEADER_BYTES + FIXED_ENTRY_BYTES] = 1;
        let first_strip = finish(first_strip, &[], Checksum::Exact);
        assert_eq!(
            parse_sha1_index(&first_strip),
            Err(RawIndexError::Malformed)
        );

        let mut overflow = build_entries(4, &[b"note.md"], &[]).bytes;
        let varint = HEADER_BYTES + FIXED_ENTRY_BYTES;
        overflow.splice(varint..=varint, [0xff; 16]);
        let overflow = finish(overflow, &[], Checksum::Exact);
        assert_eq!(
            parse_sha1_index(&overflow),
            Err(RawIndexError::ResourceLimit)
        );
    }

    #[test]
    fn accepts_only_the_frozen_unique_extension_set() {
        let parts = build_entries(2, &[b"note.md"], &[]);
        let allowed = [
            extension(TREE_EXTENSION, b"opaque-tree"),
            extension(REUC_EXTENSION, b"opaque-reuc"),
            extension(UNTR_EXTENSION, b"opaque-untracked"),
            extension(FSMN_EXTENSION, b"opaque-fsmonitor"),
        ];
        let bytes = finish(parts.bytes.clone(), &allowed, Checksum::Exact);
        assert!(parse_sha1_index(&bytes).is_ok());

        for signature in [*b"ABCD", *b"link", *b"sdir"] {
            let bytes = finish(
                parts.bytes.clone(),
                &[extension(signature, b"")],
                Checksum::Exact,
            );
            assert_eq!(parse_sha1_index(&bytes), Err(RawIndexError::Unsupported));
        }

        let tree = extension(TREE_EXTENSION, b"");
        let duplicate = finish(parts.bytes, &[tree.clone(), tree], Checksum::Exact);
        assert_eq!(
            parse_sha1_index(&duplicate),
            Err(RawIndexError::Unsupported)
        );
    }

    #[test]
    fn validates_eoie_offset_position_size_and_header_hash() {
        let parts = build_entries(2, &[b"note.md"], &[]);
        let tree = extension(TREE_EXTENSION, b"tree");
        let end = parts.bytes.len();
        let marker = eoie(end, std::slice::from_ref(&tree));
        let valid = finish(
            parts.bytes.clone(),
            &[tree.clone(), marker.clone()],
            Checksum::Exact,
        );
        assert!(parse_sha1_index(&valid).is_ok());

        let mut bad_offset = marker.clone();
        bad_offset[11] ^= 1;
        let bad_offset = finish(
            parts.bytes.clone(),
            &[tree.clone(), bad_offset],
            Checksum::Exact,
        );
        assert_eq!(parse_sha1_index(&bad_offset), Err(RawIndexError::Malformed));

        let mut bad_hash = marker.clone();
        bad_hash[12] ^= 1;
        let bad_hash = finish(
            parts.bytes.clone(),
            &[tree.clone(), bad_hash],
            Checksum::Exact,
        );
        assert_eq!(parse_sha1_index(&bad_hash), Err(RawIndexError::Malformed));

        let wrong_size = finish(
            parts.bytes.clone(),
            &[extension(EOIE_EXTENSION, &[0_u8; EOIE_DATA_BYTES - 1])],
            Checksum::Exact,
        );
        assert_eq!(parse_sha1_index(&wrong_size), Err(RawIndexError::Malformed));

        let not_last = finish(parts.bytes, &[marker, tree], Checksum::Exact);
        assert_eq!(parse_sha1_index(&not_last), Err(RawIndexError::Malformed));
    }

    #[test]
    fn ieot_with_or_without_eoie_validates_partition_offsets_counts_and_version() {
        let parts = build_entries(2, &[b"a", b"b", b"c"], &[]);
        let ieot = extension(IEOT_EXTENSION, &ieot_data(&parts.starts, &[1, 2]));
        let marker = eoie(parts.bytes.len(), std::slice::from_ref(&ieot));
        let valid = finish(
            parts.bytes.clone(),
            &[ieot.clone(), marker],
            Checksum::Exact,
        );
        assert!(parse_sha1_index(&valid).is_ok());

        let no_eoie = finish(parts.bytes.clone(), &[ieot], Checksum::Exact);
        assert!(parse_sha1_index(&no_eoie).is_ok());

        let mut bad_version = ieot_data(&parts.starts, &[1, 2]);
        bad_version[..4].copy_from_slice(&2_u32.to_be_bytes());
        let under_count = ieot_data(&parts.starts, &[1, 1]);
        let mut bad_offset = ieot_data(&parts.starts, &[1, 2]);
        bad_offset[4..8].copy_from_slice(&13_u32.to_be_bytes());
        for data in [bad_version, under_count, bad_offset] {
            let table = extension(IEOT_EXTENSION, &data);
            let marker = eoie(parts.bytes.len(), std::slice::from_ref(&table));
            let bytes = finish(parts.bytes.clone(), &[table, marker], Checksum::Exact);
            assert!(parse_sha1_index(&bytes).is_err());
        }

        let mut zero_count_data = ieot_data(&parts.starts, &[1, 2]);
        zero_count_data[11] = 0;
        zero_count_data[10] = 0;
        zero_count_data[9] = 0;
        zero_count_data[8] = 0;
        let table = extension(IEOT_EXTENSION, &zero_count_data);
        let marker = eoie(parts.bytes.len(), std::slice::from_ref(&table));
        let bytes = finish(parts.bytes, &[table, marker], Checksum::Exact);
        assert_eq!(parse_sha1_index(&bytes), Err(RawIndexError::Malformed));
    }

    #[test]
    fn independently_decodes_each_v4_ieot_block() {
        let paths = [b"alpha/one".as_slice(), b"alpha/two", b"alpha/zzz"];
        let parts = build_entries(4, &paths, &[2]);
        let table = extension(IEOT_EXTENSION, &ieot_data(&parts.starts, &[2, 1]));
        let marker = eoie(parts.bytes.len(), std::slice::from_ref(&table));
        let valid = finish(parts.bytes, &[table, marker], Checksum::Exact);
        assert!(parse_sha1_index(&valid).is_ok());

        let compressed = build_entries(4, &paths, &[]);
        let table = extension(IEOT_EXTENSION, &ieot_data(&compressed.starts, &[2, 1]));
        let marker = eoie(compressed.bytes.len(), std::slice::from_ref(&table));
        let invalid = finish(compressed.bytes, &[table, marker], Checksum::Exact);
        assert_eq!(parse_sha1_index(&invalid), Err(RawIndexError::Malformed));
    }

    #[test]
    fn malformed_ieot_shapes_and_extension_lengths_fail_closed() {
        let parts = build_entries(2, &[b"note.md"], &[]);
        for data in [Vec::new(), 1_u32.to_be_bytes().to_vec(), vec![0_u8; 13]] {
            let table = extension(IEOT_EXTENSION, &data);
            let marker = eoie(parts.bytes.len(), std::slice::from_ref(&table));
            let bytes = finish(parts.bytes.clone(), &[table, marker], Checksum::Exact);
            assert!(parse_sha1_index(&bytes).is_err());
        }

        let mut truncated_extension = parts.bytes.clone();
        truncated_extension.extend_from_slice(b"TREE");
        truncated_extension.extend_from_slice(&10_u32.to_be_bytes());
        truncated_extension.extend_from_slice(b"tiny");
        let truncated_extension = finish(truncated_extension, &[], Checksum::Exact);
        assert_eq!(
            parse_sha1_index(&truncated_extension),
            Err(RawIndexError::Malformed)
        );
    }

    #[test]
    fn every_truncation_returns_without_panicking() {
        let parts = build_entries(4, &[b"alpha/one", b"alpha/two", b"beta"], &[2]);
        let table = extension(IEOT_EXTENSION, &ieot_data(&parts.starts, &[2, 1]));
        let tree = extension(TREE_EXTENSION, b"opaque");
        let marker = eoie(parts.bytes.len(), &[table.clone(), tree.clone()]);
        let bytes = finish(parts.bytes, &[table, tree, marker], Checksum::Exact);
        assert!(parse_sha1_index(&bytes).is_ok());
        for length in 0..bytes.len() {
            let result = std::panic::catch_unwind(|| parse_sha1_index(&bytes[..length]));
            assert!(
                result.is_ok(),
                "parser panicked at truncation length {length}"
            );
            assert!(result.expect("no panic").is_err());
        }
    }
}
