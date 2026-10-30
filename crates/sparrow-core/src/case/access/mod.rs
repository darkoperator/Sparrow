//! The access report: what the attacker reached through a compromised account. The records the analyst's accepted
//! malicious flags tie to the attacker (`scope`) are turned into items per category (mail read and sent, attachments,
//! SharePoint/OneDrive, Teams, Copilot, other apps), with how each is tied to the attacker and what the capture could not
//! see. Read-only: nothing is written and no audit entry is added.

mod items;
mod scope;

pub use items::{Item, items};
pub use scope::{Attributed, ScopeValue, Window, attributed, pending_flags, scope};

use serde::Serialize;

/// How a record is tied to the attacker. Every value but `Time` is direct evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Attribution {
    /// A flagged Entra session, or an Exchange session shared with a directly attributed record of the account.
    Session,
    /// The record itself was flagged malicious.
    Row,
    /// A flagged device.
    Device,
    /// A flagged IP or prefix, or an ASN flagged for the account.
    Ip,
    /// No session and no IP of its own, inside a window of the account's malicious activity.
    Time,
}

impl Attribution {
    pub fn as_str(self) -> &'static str {
        match self {
            Attribution::Session => "session",
            Attribution::Row => "row",
            Attribution::Device => "device",
            Attribution::Ip => "ip",
            Attribution::Time => "time",
        }
    }

    pub(crate) fn parse(s: &str) -> Option<Attribution> {
        [Self::Session, Self::Row, Self::Device, Self::Ip, Self::Time]
            .into_iter()
            .find(|a| a.as_str() == s)
    }
}

/// What an item is, in tile order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Category {
    MailRead,
    MailSent,
    Attachment,
    File,
    Teams,
    Copilot,
    Other,
}

impl Category {
    pub const ALL: [Category; 7] = [
        Category::MailRead,
        Category::MailSent,
        Category::Attachment,
        Category::File,
        Category::Teams,
        Category::Copilot,
        Category::Other,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Category::MailRead => "mail_read",
            Category::MailSent => "mail_sent",
            Category::Attachment => "attachment",
            Category::File => "file",
            Category::Teams => "teams",
            Category::Copilot => "copilot",
            Category::Other => "other",
        }
    }

    pub fn title(self) -> &'static str {
        match self {
            Category::MailRead => "Emails read",
            Category::MailSent => "Emails sent",
            Category::Attachment => "Attachments",
            Category::File => "SharePoint / OneDrive",
            Category::Teams => "Teams",
            Category::Copilot => "Copilot",
            Category::Other => "Other apps",
        }
    }

    pub(crate) fn parse(s: &str) -> Option<Category> {
        Self::ALL.into_iter().find(|c| c.as_str() == s)
    }
}
