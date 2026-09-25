//! Built-in artifact parsers.

pub mod logs;
pub mod records;
pub mod stage;
pub mod ual;

use crate::ingest::parser::ParserRegistry;

pub fn register_builtin(registry: &mut ParserRegistry) {
    logs::register(registry);
    ual::register(registry);
}
