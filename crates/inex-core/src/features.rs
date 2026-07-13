//! Registered required-feature identifiers shared by vault and EDRY readers.

/// Required feature id for bounded whole-file opaque assets.
pub const OPAQUE_ASSETS_V1: u32 = 1;

/// Return whether this core understands one required feature identifier.
#[must_use]
pub const fn is_supported_required_feature(feature: u32) -> bool {
    matches!(feature, OPAQUE_ASSETS_V1)
}
