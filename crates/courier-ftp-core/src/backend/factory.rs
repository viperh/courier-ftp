//! [`BackendContext`] and [`BackendFactory`].

use std::sync::Arc;

use super::{Backend, ConnectInfo};
use crate::Result;
use crate::events::{EventSender, SessionId, SessionLog};
use crate::settings::SharedSettings;

/// What every backend instance gets from its creator.
#[derive(Clone, Debug)]
pub struct BackendContext {
    /// The session the backend belongs to (log lines, prompts, events).
    pub session: SessionId,
    /// The event bus.
    pub events: EventSender,
    /// Live settings; backends read the network settings once at connect.
    pub settings: SharedSettings,
}

impl BackendContext {
    /// A [`SessionLog`] for this session.
    pub fn log(&self) -> SessionLog {
        SessionLog {
            events: self.events.clone(),
            session: self.session,
        }
    }
}

/// Creates backends. Implemented by the binary (T58: SFTP, T14: FTP), matching on
/// `address.protocol`; core never names the protocol crates. Trust stores (T12/T21)
/// are owned by the factory.
pub trait BackendFactory: Send + Sync {
    /// Construct (not connect) a backend.
    ///
    /// # Errors
    ///
    /// `InvalidInput` ([`ConnectInfo::validate`]), `Unsupported` (protocol not
    /// available in this build).
    fn create(&self, info: Arc<ConnectInfo>, ctx: BackendContext) -> Result<Box<dyn Backend>>;
}
