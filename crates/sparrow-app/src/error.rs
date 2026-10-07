//! The error every command returns: a stable `kind` the frontend switches on and a message for the analyst. Never
//! carries case content beyond what core put in the message.

use serde::Serialize;

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct CmdError {
    /// One of `not_found`, `invalid`, `decision`, `writer_busy`, `read_only`, `no_case`, `internal`.
    pub kind: &'static str,
    pub message: String,
}

impl CmdError {
    pub fn new(kind: &'static str, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
        }
    }
}

impl From<sparrow_core::Error> for CmdError {
    fn from(e: sparrow_core::Error) -> Self {
        use sparrow_core::Error as E;
        let kind = match &e {
            E::NotFound(_) => "not_found",
            E::Invalid(_) => "invalid",
            E::Decision(_) => "decision",
            E::WriterBusy(_) => "writer_busy",
            _ => "internal",
        };
        // The inner text, not Display's prefix, when the variant carries one.
        let message = match e {
            E::NotFound(m) | E::Invalid(m) | E::Decision(m) | E::WriterBusy(m) => m,
            other => other.to_string(),
        };
        CmdError { kind, message }
    }
}

pub type CmdResult<T> = Result<T, CmdError>;

#[cfg(test)]
mod tests {
    use super::*;
    use sparrow_core::Error;

    #[test]
    fn kinds_map_from_core_errors() {
        assert_eq!(
            CmdError::from(Error::NotFound("x".into())).kind,
            "not_found"
        );
        assert_eq!(CmdError::from(Error::Invalid("x".into())).kind, "invalid");
        assert_eq!(CmdError::from(Error::Decision("x".into())).kind, "decision");
        assert_eq!(
            CmdError::from(Error::WriterBusy("x".into())).kind,
            "writer_busy"
        );
        let e = CmdError::from(Error::Decision("finding f1 changed".into()));
        assert_eq!(e.message, "finding f1 changed");
        // A variant without a kind of its own is internal and keeps core's whole message.
        let e = CmdError::from(Error::ChainBroken("audit chain broken at seq 3".into()));
        assert_eq!(e.kind, "internal");
        assert_eq!(e.message, "audit chain broken at seq 3");
    }
}
