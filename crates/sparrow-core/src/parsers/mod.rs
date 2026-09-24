//! Built-in artifact parsers.

pub mod logs;

use crate::ingest::parser::ParserRegistry;

pub fn register_builtin(registry: &mut ParserRegistry) {
    logs::register(registry);
}
