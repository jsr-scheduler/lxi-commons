//! A root helper that answers only "does `user` know `password`?", and its client.
//!
//! One frame each way over a Unix stream ([`lxi_ipc`], series limits): the request
//! `{"v":1,"user","password"}` and the answer `{"v":1,"result":"accepted"|"rejected"|
//! "unavailable"}`. The helper checks the peer's UID before reading anything, never says
//! why, and never returns account data: the client reads the account itself, which needs
//! no privilege. The client checks the helper's UID before it sends the password. The
//! socket's own permissions (systemd `SocketUser`, `SocketMode=0600`) are the first
//! fence; the UID checks are the second.

use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::Duration;

use lxi_ipc::{Error, Limits};
use serde_json::{json, Value};
use zeroize::Zeroizing;

use crate::{lookup, valid_user_name, Account, AuthError, Check, MAX_PASSWORD};

/// How long the client waits for an answer: PAM's own fail delay is about 2 s.
pub const ANSWER_DEADLINE: Duration = Duration::from_secs(10);

const ANSWER: Limits = Limits {
    deadline: ANSWER_DEADLINE,
    ..Limits::SERIES
};

/// Answers one connection: the peer must have `allowed_uid`, the request the exact shape.
/// Anything else closes the connection without an answer and without asking `pam`.
pub fn serve(mut stream: UnixStream, pam: &dyn Check, allowed_uid: u32) -> Result<(), Error> {
    if lxi_ipc::peer_uid(&stream)? != allowed_uid {
        return Err(Error::Protocol);
    }
    let mut request = lxi_ipc::read_frame(&mut stream, &Limits::SERIES)?;
    let answer = {
        let (user, password) = fields(&request)?;
        match pam.check(user, &password) {
            Ok(()) => "accepted",
            Err(AuthError::Rejected(_)) => "rejected",
            Err(AuthError::Unavailable(_)) => "unavailable",
        }
    };
    lxi_ipc::scrub(&mut request, "password");
    lxi_ipc::write_frame(
        &mut stream,
        &json!({"v": 1, "result": answer}),
        &Limits::SERIES,
    )
}

fn fields(request: &Value) -> Result<(&str, Zeroizing<String>), Error> {
    lxi_ipc::exact(request, &["v", "user", "password"])?;
    if request.get("v").and_then(Value::as_u64) != Some(1) {
        return Err(Error::Protocol);
    }
    let user = lxi_ipc::text(request, "user", crate::MAX_USER)?;
    if !valid_user_name(user) {
        return Err(Error::Protocol);
    }
    let password = Zeroizing::new(lxi_ipc::text(request, "password", MAX_PASSWORD)?.to_owned());
    Ok((user, password))
}

/// Asks the helper listening on `socket`, which must run as `helper_uid` (0 for a root
/// helper).
#[derive(Debug, Clone)]
pub struct Client {
    socket: PathBuf,
    helper_uid: u32,
}

impl Client {
    pub fn new(socket: &Path, helper_uid: u32) -> Self {
        Self {
            socket: socket.to_path_buf(),
            helper_uid,
        }
    }

    /// The helper's answer for `user`; when it accepts, the account as this process reads
    /// it. A helper that cannot be reached or answers anything unexpected is unavailable.
    pub fn authenticate(&self, user: &str, password: &str) -> Result<Account, AuthError> {
        if !valid_user_name(user) {
            return Err(AuthError::Rejected("invalid user name".into()));
        }
        if password.is_empty() || password.len() > MAX_PASSWORD {
            return Err(AuthError::Rejected("invalid password length".into()));
        }
        let gone = |e: Error| AuthError::Unavailable(format!("PAM helper: {e}"));
        let mut stream = lxi_ipc::connect(&self.socket, &Limits::SERIES).map_err(gone)?;
        // Whoever could create the socket must not receive the password, nor answer yes.
        if lxi_ipc::peer_uid(&stream).map_err(gone)? != self.helper_uid {
            return Err(AuthError::Unavailable(
                "PAM helper: the socket's peer is not the helper's user".into(),
            ));
        }
        let mut request = json!({"v": 1, "user": user, "password": password});
        let sent = lxi_ipc::write_frame(&mut stream, &request, &Limits::SERIES);
        lxi_ipc::scrub(&mut request, "password");
        sent.map_err(gone)?;
        let reply = lxi_ipc::read_frame(&mut stream, &ANSWER).map_err(gone)?;
        let result = lxi_ipc::exact(&reply, &["v", "result"])
            .ok()
            .filter(|()| reply.get("v").and_then(Value::as_u64) == Some(1))
            .and_then(|()| reply.get("result").and_then(Value::as_str));
        match result {
            Some("accepted") => {
                lookup(user)?.ok_or_else(|| AuthError::Rejected(format!("no user {user}")))
            }
            Some("rejected") => Err(AuthError::Rejected("PAM helper: rejected".into())),
            Some("unavailable") => Err(AuthError::Unavailable("PAM helper: unavailable".into())),
            _ => Err(AuthError::Unavailable(
                "PAM helper: unexpected answer".into(),
            )),
        }
    }
}
