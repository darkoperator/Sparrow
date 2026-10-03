//! Analyst/agent-owned case state. Agent decisions go through `write` (findings) and `indicators`, reviews through
//! `review`; `audit` is the only writer of `audit_trail`, inside the same transaction as each change.

pub mod actor;
pub mod audit;
pub mod indicators;
mod revert;
pub mod review;
pub mod write;
