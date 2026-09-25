//! Built-in artifact parsers.

pub mod admin_audit;
pub mod apps;
pub mod directory;
pub mod directory_audits;
pub mod exchange;
pub mod flags;
pub mod logs;
pub mod mail_items_accessed;
pub mod mailbox;
pub mod mailbox_audit;
pub mod mailbox_audit_status;
pub mod mailbox_permissions;
pub mod message_trace;
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
    directory_audits::register(registry);
    apps::register(registry);
    risk::register(registry);
    signins::register(registry);
    exchange::register(registry);
    mail_items_accessed::register(registry);
    mailbox::register(registry);
    mailbox_audit::register(registry);
    mailbox_audit_status::register(registry);
    mailbox_permissions::register(registry);
    message_trace::register(registry);
    tenant_config::register(registry);
    admin_audit::register(registry);
    flags::register(registry);
}
