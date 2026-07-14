//! Registered required-feature identifiers shared by vault and EDRY readers.

/// Required feature id for bounded whole-file opaque assets.
pub const OPAQUE_ASSETS_V1: u32 = 1;
/// Required feature id for the Umbra private-annotation container and keyslot.
pub const UMBRA_PRIVATE_ANNOTATIONS_V1: u32 = 2;

/// Return whether this core understands one required feature identifier.
#[must_use]
pub const fn is_supported_required_feature(feature: u32) -> bool {
    matches!(feature, OPAQUE_ASSETS_V1)
}
