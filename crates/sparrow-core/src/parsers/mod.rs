//! Built-in artifact parsers.

pub mod apps;
pub mod directory;
pub mod exchange;
pub mod flags;
pub mod logs;
pub mod mailbox;
pub mod records;
pub mod risk;
pub mod signins;
pub mod stage;
pub mod tenant_config;
pub mod ual;

use crate::ingest::parser::ParserRegistry;

pub fn register_builtin(registry: &mut ParserRegistry) {
    logs::register(registry);
    ual::register(registry);
    directory::register(registry);
    apps::register(registry);
    risk::register(registry);
    signins::register(registry);
    exchange::register(registry);
    mailbox::register(registry);
    tenant_config::register(registry);
    flags::register(registry);
}
