//! Synthetic collector output for Sparrow: Hawk 3.x / 4.x, Microsoft-Extractor-Suite 4.1.0 and
//! analyst portal exports, generated deterministically from a scenario and a seed, each tree
//! with a ground-truth manifest (spec Addendum B). Every domain, address, GUID and name is
//! reserved or synthetic; nothing comes from a real capture.

pub mod baseline;
pub mod coverage;
pub mod error;
pub mod events;
pub mod expect;
pub mod geo;
pub mod keys;
pub mod manifest;
pub mod names;
pub mod options;
pub mod profiles;
pub mod ps;
pub mod reserved;
pub mod rng;
pub mod scenario;
pub mod story;
pub mod tree;
pub mod ual;
pub mod world;
pub mod writers;

pub use error::{Error, Result};
