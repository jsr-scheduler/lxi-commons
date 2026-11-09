//! Unix accounts and their passwords, checked with PAM as JSR checks them
//! (`crates/auth-local/src/lib.rs`, 3b75827; JSR ADR-0016).
//!
//! [`Pam`] asks PAM directly, which with `pam_unix` needs root to read `/etc/shadow`.
//! [`helper`] lets an unprivileged service ask a minimal root helper instead, which answers
//! only yes, no or unavailable; the service then reads the account's groups itself.

use std::collections::BTreeSet;
use std::ffi::{OsStr, OsString};
use std::fmt;

use nix::unistd::{Gid, Group, Uid, User};
use nonstick::items::Items;
use nonstick::{
    AuthnFlags, ConversationAdapter, ErrorCode, PamShared, Transaction, TransactionBuilder,
};

pub mod helper;

/// Longest user name accepted, in bytes.
pub const MAX_USER: usize = 64;
/// Longest password accepted, in bytes.
pub const MAX_PASSWORD: usize = 1024;

/// A Unix account and the names of its groups (primary and supplementary).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Account {
    pub name: String,
    pub uid: u32,
    pub groups: BTreeSet<String>,
    /// uid 0.
    pub superuser: bool,
}

/// Denial is not unavailability: a service never turns the second into the first.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthError {
    /// Wrong user or password, or an account PAM does not accept. The text is for the log.
    Rejected(String),
    /// PAM, the helper or the user database could not answer.
    Unavailable(String),
}

impl fmt::Display for AuthError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Rejected(why) => write!(f, "rejected: {why}"),
            Self::Unavailable(why) => write!(f, "unavailable: {why}"),
        }
    }
}

impl std::error::Error for AuthError {}

/// A password check that says only whether `user` knows `password`. Blocking.
pub trait Check: Send + Sync {
    fn check(&self, user: &str, password: &str) -> Result<(), AuthError>;
}

/// A user name PAM and the user database may be asked about: 1–64 bytes of
/// `[A-Za-z0-9._@-]` (JSR `valid_user_name`).
pub fn valid_user_name(name: &str) -> bool {
    (1..=MAX_USER).contains(&name.len())
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-@".contains(&b))
}

/// The account with `uid` and primary `gid`.
pub fn account_of_uid(uid: u32, gid: u32) -> Result<Account, String> {
    let user = User::from_uid(Uid::from_raw(uid))
        .map_err(|e| format!("uid {uid}: {e}"))?
        .ok_or_else(|| format!("uid {uid} has no user name"))?;
    account_of(&user, gid)
}

/// The account named `user` as the user database has it now; `None` when it does not
/// exist. No PAM, no root.
pub fn lookup(user: &str) -> Result<Option<Account>, AuthError> {
    let Some(account) =
        User::from_name(user).map_err(|e| AuthError::Unavailable(format!("user database: {e}")))?
    else {
        return Ok(None);
    };
    account_of(&account, account.gid.as_raw())
        .map(Some)
        .map_err(AuthError::Unavailable)
}

fn account_of(user: &User, gid: u32) -> Result<Account, String> {
    let mut groups = BTreeSet::new();
    for gid in group_ids(user, gid)? {
        if let Ok(Some(group)) = Group::from_gid(gid) {
            groups.insert(group.name);
        }
    }
    Ok(Account {
        name: user.name.clone(),
        uid: user.uid.as_raw(),
        groups,
        superuser: user.uid.is_root(),
    })
}

#[cfg(target_os = "linux")]
fn group_ids(user: &User, gid: u32) -> Result<Vec<Gid>, String> {
    let name = std::ffi::CString::new(user.name.as_bytes()).map_err(|e| e.to_string())?;
    nix::unistd::getgrouplist(&name, Gid::from_raw(gid)).map_err(|e| e.to_string())
}

/// Platforms without `getgrouplist` in `nix` (macOS, for development): ask `id -G`.
#[cfg(not(target_os = "linux"))]
fn group_ids(user: &User, gid: u32) -> Result<Vec<Gid>, String> {
    let out = std::process::Command::new("id")
        .arg("-G")
        .arg(&user.name)
        .output()
        .map_err(|e| format!("id -G: {e}"))?;
    let mut gids: Vec<Gid> = String::from_utf8_lossy(&out.stdout)
        .split_whitespace()
        .filter_map(|g| g.parse().ok())
        .map(Gid::from_raw)
        .collect();
    gids.push(Gid::from_raw(gid));
    Ok(gids)
}

/// Answers PAM's prompts: the user name to plain prompts, the password to masked ones.
struct Answers {
    user: OsString,
    password: OsString,
}

impl ConversationAdapter for Answers {
    fn prompt(&self, _request: impl AsRef<OsStr>) -> nonstick::Result<OsString> {
        Ok(self.user.clone())
    }

    fn masked_prompt(&self, _request: impl AsRef<OsStr>) -> nonstick::Result<OsString> {
        Ok(self.password.clone())
    }

    fn error_msg(&self, _message: impl AsRef<OsStr>) {}

    fn info_msg(&self, _message: impl AsRef<OsStr>) {}
}

/// PAM errors that mean "PAM could not answer", as opposed to "PAM said no".
fn unavailable(code: ErrorCode) -> bool {
    matches!(
        code,
        ErrorCode::OpenError
            | ErrorCode::SymbolError
            | ErrorCode::ServiceError
            | ErrorCode::SystemError
            | ErrorCode::BufferError
    )
}

fn pam_error(step: &str, code: ErrorCode) -> AuthError {
    let message = format!("PAM {step}: {code}");
    if unavailable(code) {
        AuthError::Unavailable(message)
    } else {
        AuthError::Rejected(message)
    }
}

/// Checks passwords with the PAM service `service` (`/etc/pam.d/<service>`).
#[derive(Debug, Clone)]
pub struct Pam {
    service: String,
}

impl Pam {
    pub fn new(service: impl Into<String>) -> Self {
        Self {
            service: service.into(),
        }
    }

    /// PAM's answer, then the account as the user database has it.
    pub fn authenticate(&self, user: &str, password: &str) -> Result<Account, AuthError> {
        self.check(user, password)?;
        lookup(user)?.ok_or_else(|| AuthError::Rejected(format!("no user {user}")))
    }
}

impl Check for Pam {
    fn check(&self, user: &str, password: &str) -> Result<(), AuthError> {
        // PAM first, also for names that do not exist: answering those sooner would tell
        // which accounts exist.
        let answers = Answers {
            user: user.into(),
            password: password.into(),
        };
        let mut txn = TransactionBuilder::new_with_service(&self.service)
            .username(user)
            .build(answers.into_conversation())
            .map_err(|e| pam_error("start", e))?;
        txn.authenticate(AuthnFlags::empty())
            .map_err(|e| pam_error("authenticate", e))?;
        txn.account_management(AuthnFlags::empty())
            .map_err(|e| pam_error("account", e))?;
        // A module may map the name to another account (PAM_USER): the account would then
        // be one while PAM checked another. Refused (JSR security review S-50).
        let checked = txn
            .items()
            .user()
            .map_err(|e| pam_error("user", e))?
            .unwrap_or_default();
        if checked != OsStr::new(user) {
            return Err(AuthError::Rejected(format!(
                "PAM checked {} for {user}",
                checked.to_string_lossy()
            )));
        }
        Ok(())
    }
}
