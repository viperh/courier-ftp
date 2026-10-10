//! FTP and FTPS client for courier-ftp, written from scratch on tokio (D1).
//!
//! Implements the `Backend` trait from `courier-ftp-core`: the control
//! connection (T10), data connections and transfer modes (T11), FTPS with
//! rustls (T12), directory listing parsers (T13), the operations and the
//! backend itself (T14) and FTP proxies (T15).
//!
//! Layering: depends only on `courier-ftp-core`; never on a UI crate.

pub mod active; // T11
pub mod ascii; // T11
pub mod command; // T10
pub mod control; // T10
pub mod data; // T11
pub mod encoding; // T10
pub mod features; // T10
pub mod listing; // T13
pub mod login; // T10
pub mod passive; // T11
pub mod reply; // T10
#[cfg(any(test, feature = "test-util"))]
pub mod testing; // T10 (`FakeServer`), T11/T12 add steps
pub mod transfer; // T11

pub use active::{format_eprt, format_port, parse_eprt};
pub use ascii::{AsciiDecode, AsciiEncode};
pub use command::{Command, CommandArg};
pub use control::{
    BoxedIo, ControlConnection, ControlIo, ControlParams, ControlState, StreamUpgrade,
};
pub use data::{
    DataConfig, DataIo, DataMode, DataState, DataStream, DataTlsHook, RawData, TransferCommand,
};
pub use encoding::{LineDecoder, SessionEncoding};
pub use features::{Features, MlstFact, parse_feat};
pub use login::{LoginPromptInfo, LoginScript, LoginStep, LoginTarget, StepKind, StepValue};
pub use passive::{AddrParseError, is_unroutable, parse_epsv, parse_pasv};
pub use reply::{Reply, ReplyClass, ReplyCode, ReplyError, ReplyParser, parse_pwd};
pub use transfer::FtpData;
