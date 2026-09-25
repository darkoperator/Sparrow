//! Built-in artifact parsers.

pub mod apps;
pub mod directory;
pub mod exchange;
pub mod logs;
pub mod records;
pub mod risk;
pub mod stage;
pub mod ual;

use crate::ingest::parser::ParserRegistry;

pub fn register_builtin(registry: &mut ParserRegistry) {
    logs::register(registry);
    ual::register(registry);
    directory::register(registry);
    apps::register(registry);
    risk::register(registry);
    exchange::register(registry);
}
