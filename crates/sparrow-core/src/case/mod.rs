//! Analyst/agent-owned case state. Agent decisions go through `write` (findings), `indicators` and
//! `timeline_entries`; notes through `notes`; reviews through
//! `review`; `audit` is the only writer of `audit_trail`, inside the same transaction as each change.

pub mod actor;
pub mod audit;
pub mod indicators;
pub mod notes;
mod revert;
pub mod review;
pub mod text;
pub mod timeline_entries;
pub mod write;
