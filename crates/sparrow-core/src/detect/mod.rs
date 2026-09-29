//! Detection engine (spec §8, Addendum C): the rule model, the loader that embeds the built-in
//! rules and lists, and (from Task 2 on) the compiler, runner and lint.

pub mod compile;
pub mod coverage;
pub mod findings;
pub mod lint;
pub mod load;
pub mod rule;
pub mod rule_conn;
pub mod run;
mod scope;

pub use findings::fingerprint;
pub use run::{DetectOptions, DetectReport, RuleRunReport};
