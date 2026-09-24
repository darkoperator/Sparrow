//! Finding collector output folders and classifying the files inside them.

pub mod collections;
pub mod registry;

pub use collections::{DiscoveredCollection, Tool, discover_collections};
pub use registry::{Classification, FileFormat, Registry, format_from_path, normalize_rel_path};
