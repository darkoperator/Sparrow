//! Finding collector output folders and classifying the files inside them.

pub mod collections;
pub mod files;
pub mod registry;

pub use collections::{DiscoveredCollection, Tool, discover_collections};
pub use files::{
    CollectionFile, CollectionListing, EntryError, canonical_root_string, is_os_junk,
    list_collection_files,
};
pub use registry::{
    Classification, FileFormat, Registry, SNIFF_BYTES, format_from_path, normalize_rel_path,
    sniff_portal,
};
