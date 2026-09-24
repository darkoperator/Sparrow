//! Finding collector output folders and classifying the files inside them.

pub mod collections;

pub use collections::{DiscoveredCollection, Tool, discover_collections};
