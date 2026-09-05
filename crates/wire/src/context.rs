/// Stable identity of one transaction-construction session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ProtocolSessionId([u8; 32]);

impl ProtocolSessionId {
    /// Construct an identity from its canonical bytes.
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Borrow the canonical identity bytes.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl AsRef<[u8]> for ProtocolSessionId {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

/// Exact application-protocol version used by a construction session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ProtocolVersion(u16);

impl ProtocolVersion {
    /// Construct a protocol version from its wire value.
    pub const fn new(value: u16) -> Self {
        Self(value)
    }

    /// Return the wire value.
    pub const fn get(self) -> u16 {
        self.0
    }

    pub(crate) const fn to_be_bytes(self) -> [u8; 2] {
        self.0.to_be_bytes()
    }
}

/// Logical context shared by every application message in one message set.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MessageContext {
    session_id: ProtocolSessionId,
    protocol_version: ProtocolVersion,
}

impl MessageContext {
    /// Construct a message context.
    pub const fn new(session_id: ProtocolSessionId, protocol_version: ProtocolVersion) -> Self {
        Self {
            session_id,
            protocol_version,
        }
    }

    /// Return the protocol-session identity.
    pub const fn session_id(self) -> ProtocolSessionId {
        self.session_id
    }

    /// Return the exact protocol version.
    pub const fn protocol_version(self) -> ProtocolVersion {
        self.protocol_version
    }
}
