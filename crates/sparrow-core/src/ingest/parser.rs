//! Parser plug-in point: one parser per artifact id.

use crate::Result;
use crate::ingest::context::ParseContext;
use std::collections::HashMap;

/// How a parser reads its file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InputMode {
    /// Record passes over the file ([`ParseContext::input`]); records arrive with their sightings.
    Stream,
    /// The whole content in memory ([`ParseContext::whole`]).
    Whole,
}

pub trait ArtifactParser: Send + Sync {
    /// Parse the file, writing evidence rows and provenance through `ctx`.
    /// Returning an error rolls back everything written for this file.
    fn parse(&self, ctx: &mut ParseContext<'_>) -> Result<()>;

    /// Whether the parser reads record passes or the whole content.
    fn input(&self) -> InputMode {
        InputMode::Stream
    }

    /// Names of the parser's steps, in order ([`ParseContext::set_step`] indexes them).
    fn steps(&self) -> &'static [&'static str] {
        &["Loading records"]
    }
}

#[derive(Default)]
pub struct ParserRegistry {
    parsers: HashMap<&'static str, Box<dyn ArtifactParser>>,
}

impl ParserRegistry {
    pub fn empty() -> Self {
        Self::default()
    }

    pub fn builtin() -> Self {
        let mut r = Self::default();
        crate::parsers::register_builtin(&mut r);
        r
    }

    pub fn register(&mut self, artifact_id: &'static str, parser: Box<dyn ArtifactParser>) {
        self.parsers.insert(artifact_id, parser);
    }

    pub fn get(&self, artifact_id: &str) -> Option<&dyn ArtifactParser> {
        self.parsers.get(artifact_id).map(|b| b.as_ref())
    }
}
