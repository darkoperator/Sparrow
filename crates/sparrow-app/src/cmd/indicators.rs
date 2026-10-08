//! The indicators the highlights panel colours rows with: the case's active malicious and suspicious IOCs.

use crate::error::CmdResult;
use crate::state::{AppState, with_case};
use serde::Serialize;
use sparrow_core::case::indicators::{self, Verdict};

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct ActiveIndicator {
    pub ioc_type: String,
    pub value: String,
    pub verdict: String,
}

/// Every indicator not removed whose verdict is malicious or suspicious (a benign verdict is a judgement that the
/// value is fine, not something to highlight), in core's order: type, value, id.
pub fn indicators_active(state: &AppState) -> CmdResult<Vec<ActiveIndicator>> {
    with_case(state, |open| {
        Ok(indicators::list_indicators(open.case.conn(), None, false)?
            .into_iter()
            .filter(|i| matches!(i.verdict, Verdict::Malicious | Verdict::Suspicious))
            .map(|i| ActiveIndicator {
                ioc_type: i.ty.as_str().to_string(),
                value: i.value,
                verdict: i.verdict.as_str().to_string(),
            })
            .collect())
    })
}

pub mod commands {
    use super::*;
    use tauri::State;

    #[tauri::command(async)]
    pub fn indicators_active(state: State<'_, AppState>) -> CmdResult<Vec<ActiveIndicator>> {
        super::indicators_active(&state)
    }
}
