//! The pivot screen's commands: everything the case knows about one IP or one account.

use crate::error::{CmdError, CmdResult};
use crate::state::{AppState, with_case};
use sparrow_core::case::read::{self, Pivot};
use std::net::IpAddr;

pub const DEFAULT_CAP: usize = 200;
pub const MAX_CAP: usize = 1000;
/// The longest account name (a UPN / email address).
const MAX_UPN: usize = 320;

/// The row cap of each section: default 200, clamped to 1..=1000.
pub fn cap_of(cap: Option<usize>) -> usize {
    cap.unwrap_or(DEFAULT_CAP).clamp(1, MAX_CAP)
}

fn invalid(msg: String) -> CmdError {
    CmdError::new("invalid", msg)
}

/// The IP as typed: the case stores it as text, so it is looked up as text; it only has to parse. No trimming here,
/// the screen trims what the analyst typed or pasted.
fn check_ip(v: &str) -> CmdResult<&str> {
    if v.len() > 64 || v.parse::<IpAddr>().is_err() {
        return Err(invalid("that is not an IP address".into()));
    }
    Ok(v)
}

fn check_upn(v: &str) -> CmdResult<&str> {
    if v.trim().is_empty() {
        return Err(invalid("enter an account name".into()));
    }
    if v.chars().count() > MAX_UPN {
        return Err(invalid(format!(
            "an account name is at most {MAX_UPN} characters"
        )));
    }
    if v.chars().any(char::is_control) {
        return Err(invalid("an account name holds control characters".into()));
    }
    Ok(v)
}

pub fn pivot_ip(state: &AppState, value: &str, cap: Option<usize>) -> CmdResult<Pivot> {
    let ip = check_ip(value)?;
    with_case(state, |open| {
        Ok(read::pivot_ip(open.case.conn(), ip, cap_of(cap))?)
    })
}

pub fn pivot_user(state: &AppState, value: &str, cap: Option<usize>) -> CmdResult<Pivot> {
    let upn = check_upn(value)?;
    with_case(state, |open| {
        Ok(read::pivot_user(open.case.conn(), upn, cap_of(cap))?)
    })
}

pub mod commands {
    use super::*;
    use tauri::State;

    #[tauri::command(async)]
    pub fn pivot_ip(
        state: State<'_, AppState>,
        value: String,
        cap: Option<usize>,
    ) -> CmdResult<Pivot> {
        super::pivot_ip(&state, &value, cap)
    }

    #[tauri::command(async)]
    pub fn pivot_user(
        state: State<'_, AppState>,
        value: String,
        cap: Option<usize>,
    ) -> CmdResult<Pivot> {
        super::pivot_user(&state, &value, cap)
    }
}
