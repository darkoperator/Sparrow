//! SQL notebooks: named lists of saved, commented queries. The built-in notebook ships with Sparrow and is never
//! written; case notebooks are stored in the case and edited by the analyst (agents may only add queries and import
//! notebooks). A notebook leaves a case only as an exported `.sql` file.

pub mod builtin;
pub mod file;
pub mod leak;
pub mod placeholder;
pub mod store;

pub use file::{MARKER, NotebookFile, check_query_sql, parse_file, title, write_file};
pub use leak::{CaseValueHit, case_values_in};
pub use placeholder::{placeholders, refuse_placeholders};
pub use store::{
    BUILTIN_ID, BUILTIN_NAME, NotebookSummary, QuerySummary, SavedQuery, add_query,
    add_query_creating, create_notebook, create_notebook_with_query, delete_notebook, delete_query,
    export_text, find_query, import_text, list, move_query, notebook_queries, rename_notebook,
};
