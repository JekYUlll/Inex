//! Bounded Umbra projection rendering and private-block selection mapping.
//!
//! This module owns the canonical editor projection grammar. Clients receive a
//! rendered Markdown string and opaque byte ranges, never the encrypted
//! storage container grammar.

use std::collections::{BTreeMap, BTreeSet};

use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::umbra_config::{OuterMode, PrivateAnnotationKind};
use crate::umbra_document::{PrivateSlotPayloadV1, UmbraDocumentV1};

const MARKER_PREFIX: &str = "{{inex-private-slot:";
const MARKER_SUFFIX: &str = "}}";
const FENCE_START: &str = ":::inex-private\n";
const FENCE_END: &str = ":::\n";

/// A validated byte range in an UTF-8 Umbra projection.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct TextRange {
    pub start: usize,
    pub end: usize,
}

impl TextRange {
    /// Construct one non-empty range.
    ///
    /// # Errors
    ///
    /// Returns an error for reversed or empty boundaries.
    pub fn new(start: usize, end: usize) -> Result<Self, UmbraRenderError> {
        if start >= end {
            return Err(UmbraRenderError::InvalidTextRange);
        }
        Ok(Self { start, end })
    }
}

/// One private fenced block in the current rendered projection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RenderedPrivateSlot {
    pub slot_id: String,
    pub projection_range: TextRange,
}

/// Owned `RenderMap` representation used at the core/API boundary.
///
/// The generation is a digest of the complete rendered projection. It is not
/// a storage identifier and must be paired with the document `ETag` by the
/// daemon session registry before mutation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OwnedRenderMap {
    pub generation: [u8; 32],
    pub projection_len: usize,
    pub private_slots: Vec<RenderedPrivateSlot>,
}

/// Fully rendered Umbra Markdown and its selection map.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RenderedUmbraProjection {
    pub markdown: String,
    pub render_map: OwnedRenderMap,
}

/// Classification after range normalization and strict private-boundary
/// validation. The caller decides whether to wrap, unwrap, or edit.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SelectionClass {
    Plain(Vec<TextRange>),
    CompletePrivateBlocks(Vec<String>),
    InsidePrivateSlot(String),
    MixedOrPartial,
}

/// Render a canonical Umbra projection from an authenticated Outer container
/// and the already decrypted payload for every slot.
///
/// # Errors
///
/// Returns an error when markers and slots are not a one-to-one canonical
/// mapping, a payload is missing, or a payload is invalid.
pub fn render_umbra_projection(
    document: &UmbraDocumentV1,
    payloads: &BTreeMap<String, PrivateSlotPayloadV1>,
) -> Result<RenderedUmbraProjection, UmbraRenderError> {
    let mut markdown = String::with_capacity(document.outer_markdown.len());
    let mut slots = Vec::with_capacity(document.slots.len());
    let mut cursor = 0;
    let mut seen = BTreeSet::new();

    while let Some(relative_start) = document.outer_markdown[cursor..].find(MARKER_PREFIX) {
        let marker_start = cursor + relative_start;
        markdown.push_str(&document.outer_markdown[cursor..marker_start]);
        let id_start = marker_start + MARKER_PREFIX.len();
        let relative_end = document.outer_markdown[id_start..]
            .find(MARKER_SUFFIX)
            .ok_or(UmbraRenderError::InvalidOuterMarker)?;
        let id_end = id_start + relative_end;
        let slot_id = &document.outer_markdown[id_start..id_end];
        if !valid_slot_id(slot_id) || !seen.insert(slot_id.to_owned()) {
            return Err(UmbraRenderError::InvalidOuterMarker);
        }
        let entry = document
            .slots
            .get(slot_id)
            .ok_or(UmbraRenderError::MarkerSlotMismatch)?;
        let payload = payloads
            .get(slot_id)
            .ok_or(UmbraRenderError::MissingPrivatePayload)?;
        payload
            .validate()
            .map_err(|_| UmbraRenderError::InvalidPrivatePayload)?;
        let start = markdown.len();
        append_private_block(&mut markdown, slot_id, payload, &entry.outer.mode);
        let end = markdown.len();
        slots.push(RenderedPrivateSlot {
            slot_id: slot_id.to_owned(),
            projection_range: TextRange::new(start, end)?,
        });
        cursor = id_end + MARKER_SUFFIX.len();
    }
    markdown.push_str(&document.outer_markdown[cursor..]);
    if seen.len() != document.slots.len() || payloads.len() != document.slots.len() {
        return Err(UmbraRenderError::MarkerSlotMismatch);
    }
    let generation: [u8; 32] = Sha256::digest(markdown.as_bytes()).into();
    Ok(RenderedUmbraProjection {
        render_map: OwnedRenderMap {
            generation,
            projection_len: markdown.len(),
            private_slots: slots,
        },
        markdown,
    })
}

/// Verify that every Outer marker names one slot and every slot has exactly
/// one canonical marker. This checks public container structure only; it does
/// not decrypt payloads.
///
/// # Errors
///
/// Returns an error for malformed, duplicate, missing, or dangling markers.
pub fn validate_outer_marker_slots(document: &UmbraDocumentV1) -> Result<(), UmbraRenderError> {
    let mut cursor = 0;
    let mut seen = BTreeSet::new();
    while let Some(relative_start) = document.outer_markdown[cursor..].find(MARKER_PREFIX) {
        let marker_start = cursor + relative_start;
        let id_start = marker_start + MARKER_PREFIX.len();
        let relative_end = document.outer_markdown[id_start..]
            .find(MARKER_SUFFIX)
            .ok_or(UmbraRenderError::InvalidOuterMarker)?;
        let id_end = id_start + relative_end;
        let slot_id = &document.outer_markdown[id_start..id_end];
        if !valid_slot_id(slot_id)
            || !document.slots.contains_key(slot_id)
            || !seen.insert(slot_id.to_owned())
        {
            return Err(UmbraRenderError::MarkerSlotMismatch);
        }
        cursor = id_end + MARKER_SUFFIX.len();
    }
    if seen.len() == document.slots.len() {
        Ok(())
    } else {
        Err(UmbraRenderError::MarkerSlotMismatch)
    }
}

/// Normalize selections and classify their relation to private block ranges.
///
/// Empty ranges are rejected here; paragraph/line expansion is editor policy
/// and must occur before entering this security boundary.
///
/// # Errors
///
/// Returns an error for invalid UTF-8 byte boundaries or ranges outside the
/// exact projection length.
pub fn normalize_and_classify_selections(
    projection: &str,
    render_map: &OwnedRenderMap,
    selections: &[TextRange],
    merge_adjacent: bool,
) -> Result<SelectionClass, UmbraRenderError> {
    if projection.len() != render_map.projection_len
        || Sha256::digest(projection.as_bytes()).as_slice() != render_map.generation
    {
        return Err(UmbraRenderError::StaleRenderMap);
    }
    let mut normalized = selections.to_vec();
    for range in &normalized {
        if range.end > projection.len()
            || !projection.is_char_boundary(range.start)
            || !projection.is_char_boundary(range.end)
        {
            return Err(UmbraRenderError::InvalidTextRange);
        }
    }
    normalized.sort_unstable();
    let mut merged: Vec<TextRange> = Vec::with_capacity(normalized.len());
    for range in normalized {
        if let Some(last) = merged.last_mut()
            && (range.start < last.end || (merge_adjacent && range.start == last.end))
        {
            last.end = last.end.max(range.end);
            continue;
        }
        merged.push(range);
    }
    classify_normalized(&merged, &render_map.private_slots)
}

fn classify_normalized(
    selections: &[TextRange],
    slots: &[RenderedPrivateSlot],
) -> Result<SelectionClass, UmbraRenderError> {
    if selections.is_empty() {
        return Err(UmbraRenderError::InvalidTextRange);
    }
    let mut complete = Vec::new();
    let mut inside = None;
    let mut plain = true;
    for selection in selections {
        let mut hit = None;
        for slot in slots {
            let slot_range = slot.projection_range;
            if selection.start == slot_range.start && selection.end == slot_range.end {
                hit = Some((slot, HitKind::Complete));
                break;
            }
            if selection.start >= slot_range.start && selection.end <= slot_range.end {
                hit = Some((slot, HitKind::Inside));
                break;
            }
            if selection.start < slot_range.end && slot_range.start < selection.end {
                return Ok(SelectionClass::MixedOrPartial);
            }
        }
        match hit {
            None => {}
            Some((slot, HitKind::Complete)) => {
                plain = false;
                complete.push(slot.slot_id.clone());
            }
            Some((slot, HitKind::Inside)) => {
                plain = false;
                match &inside {
                    Some(existing) if existing != &slot.slot_id => {
                        return Ok(SelectionClass::MixedOrPartial);
                    }
                    _ => inside = Some(slot.slot_id.clone()),
                }
            }
        }
    }
    if plain {
        return Ok(SelectionClass::Plain(selections.to_vec()));
    }
    if let Some(slot_id) = inside {
        if complete.is_empty() {
            return Ok(SelectionClass::InsidePrivateSlot(slot_id));
        }
        return Ok(SelectionClass::MixedOrPartial);
    }
    if complete.len() == selections.len() {
        return Ok(SelectionClass::CompletePrivateBlocks(complete));
    }
    Ok(SelectionClass::MixedOrPartial)
}

#[derive(Clone, Copy)]
enum HitKind {
    Complete,
    Inside,
}

fn append_private_block(
    output: &mut String,
    slot_id: &str,
    payload: &PrivateSlotPayloadV1,
    outer: &OuterMode,
) {
    output.push_str(FENCE_START);
    output.push_str("id: ");
    output.push_str(slot_id);
    output.push('\n');
    output.push_str("kind: ");
    output.push_str(match payload.kind {
        PrivateAnnotationKind::Block => "block",
        PrivateAnnotationKind::Comment => "comment",
    });
    output.push('\n');
    output.push_str("tags: [");
    output.push_str(&payload.tag_ids.join(", "));
    output.push_str("]\nouter: ");
    output.push_str(match outer {
        OuterMode::Drop => "drop",
        OuterMode::Cover => "cover",
        OuterMode::Placeholder => "placeholder",
    });
    output.push_str("\n---\n");
    output.push_str(&payload.markdown);
    if !payload.markdown.ends_with('\n') {
        output.push('\n');
    }
    output.push_str(FENCE_END);
}

fn valid_slot_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value.bytes().enumerate().all(|(index, byte)| {
            byte.is_ascii_alphanumeric() || (index > 0 && matches!(byte, b'_' | b'-'))
        })
}

/// Projection and range errors are stable and deliberately omit Markdown,
/// tags, or private slot content.
#[derive(Debug, Error)]
pub enum UmbraRenderError {
    #[error("invalid Umbra projection text range")]
    InvalidTextRange,
    #[error("Umbra projection is stale")]
    StaleRenderMap,
    #[error("invalid Umbra Outer slot marker")]
    InvalidOuterMarker,
    #[error("Umbra Outer markers and slots do not match")]
    MarkerSlotMismatch,
    #[error("Umbra private slot payload is unavailable")]
    MissingPrivatePayload,
    #[error("invalid Umbra private slot payload")]
    InvalidPrivatePayload,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn payload(markdown: &str) -> PrivateSlotPayloadV1 {
        PrivateSlotPayloadV1 {
            format: "inex-private-slot".to_owned(),
            version: 1,
            kind: PrivateAnnotationKind::Comment,
            tag_ids: vec!["comment-content".to_owned(), "relationship".to_owned()],
            markdown: markdown.to_owned(),
            created_at_ms: 1,
            updated_at_ms: 1,
        }
    }

    #[test]
    fn renders_canonical_blocks_and_classifies_strict_ranges() {
        let mut document = UmbraDocumentV1::new(
            "before\n{{inex-private-slot:p_01}}\nafter\n{{inex-private-slot:p_02}}\n".to_owned(),
        );
        let entry = crate::umbra_document::OuterSlotEntry {
            outer: crate::umbra_document::OuterSlotStrategy {
                mode: OuterMode::Drop,
                cover_text: None,
            },
            umbra_cipher: crate::umbra_document::UmbraSlotCipher {
                alg: "xchacha20-poly1305".to_owned(),
                nonce: crate::vault_config::EncodedBytes::new([0; 24]),
                ciphertext: "AAAAAAAAAAAAAAAAAAAAAA".to_owned(),
            },
        };
        document.slots.insert("p_01".to_owned(), entry.clone());
        document.slots.insert("p_02".to_owned(), entry);
        let payloads = BTreeMap::from([
            ("p_01".to_owned(), payload("秘密一\n")),
            ("p_02".to_owned(), payload("秘密二\n")),
        ]);
        let rendered = render_umbra_projection(&document, &payloads).expect("render");
        assert!(
            rendered
                .markdown
                .contains("kind: comment\ntags: [comment-content, relationship]")
        );
        let first = rendered.render_map.private_slots[0].projection_range;
        let second = rendered.render_map.private_slots[1].projection_range;
        assert_eq!(
            normalize_and_classify_selections(
                &rendered.markdown,
                &rendered.render_map,
                &[second, first],
                false,
            )
            .expect("classify complete"),
            SelectionClass::CompletePrivateBlocks(vec!["p_01".to_owned(), "p_02".to_owned()])
        );
        let inside = TextRange::new(first.start + 1, first.start + 2).expect("range");
        assert_eq!(
            normalize_and_classify_selections(
                &rendered.markdown,
                &rendered.render_map,
                &[inside],
                false,
            )
            .expect("classify inside"),
            SelectionClass::InsidePrivateSlot("p_01".to_owned())
        );
        let partial = TextRange::new(first.start - 1, first.end).expect("range");
        assert_eq!(
            normalize_and_classify_selections(
                &rendered.markdown,
                &rendered.render_map,
                &[partial],
                false,
            )
            .expect("classify partial"),
            SelectionClass::MixedOrPartial
        );
    }

    #[test]
    fn rejects_missing_or_duplicate_marker_slots_and_stale_projection() {
        let document = UmbraDocumentV1::new("{{inex-private-slot:p_01}}".to_owned());
        assert!(matches!(
            render_umbra_projection(&document, &BTreeMap::new()),
            Err(UmbraRenderError::MarkerSlotMismatch)
        ));

        let map = OwnedRenderMap {
            generation: [0; 32],
            projection_len: 1,
            private_slots: Vec::new(),
        };
        assert!(matches!(
            normalize_and_classify_selections(
                "x",
                &map,
                &[TextRange::new(0, 1).expect("range")],
                false
            ),
            Err(UmbraRenderError::StaleRenderMap)
        ));
    }
}
