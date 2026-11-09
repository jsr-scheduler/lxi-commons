//! HTTPS pieces for the series, from JSR `crates/api-rest` (3b75827): sessions of local
//! users with sign-in throttling, the sign-in sequence, and the HTTPS server with its limits.

pub mod server;
pub mod sessions;
pub mod sign_in;
