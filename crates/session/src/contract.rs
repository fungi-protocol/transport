use std::fmt;

use fungi_wire::{MAX_MESSAGE_SIZE, MessageContext};

use crate::InvalidMessageSizeLimit;

/// Maximum complete canonical application-message size admitted by a session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MessageSizeLimit(u32);

impl MessageSizeLimit {
    /// Validate a nonzero limit no larger than the canonical wire hard cap.
    pub fn new(value: usize) -> Result<Self, InvalidMessageSizeLimit> {
        if value == 0 || value > MAX_MESSAGE_SIZE {
            return Err(InvalidMessageSizeLimit {
                value,
                maximum: MAX_MESSAGE_SIZE,
            });
        }
        Ok(Self(u32::try_from(value).expect(
            "MAX_MESSAGE_SIZE must fit in the hello's u32 field",
        )))
    }

    /// Return the limit as a platform message length.
    pub const fn get(self) -> usize {
        self.0 as usize
    }

    pub(crate) const fn to_be_bytes(self) -> [u8; 4] {
        self.0.to_be_bytes()
    }

    pub(crate) fn from_be_bytes(bytes: [u8; 4]) -> Result<Self, InvalidMessageSizeLimit> {
        Self::new(u32::from_be_bytes(bytes) as usize)
    }
}

/// Complete local contract required before a P2P link enters closed-group gossip.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SessionContract {
    context: MessageContext,
    max_message_size: MessageSizeLimit,
}

impl SessionContract {
    /// Construct a session contract from already validated components.
    pub const fn new(context: MessageContext, max_message_size: MessageSizeLimit) -> Self {
        Self {
            context,
            max_message_size,
        }
    }

    /// Return the message identity context.
    pub const fn context(self) -> MessageContext {
        self.context
    }

    /// Return the complete canonical-message limit.
    pub const fn max_message_size(self) -> MessageSizeLimit {
        self.max_message_size
    }
}

impl fmt::Display for MessageSizeLimit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}
