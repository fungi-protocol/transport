use std::{fmt, future::Future, sync::OnceLock};

use fungi_transport::{
    Channel, GossipBroadcast, RecvError, RecvHalf, SendError, SendHalf, SessionBound, SplitChannel,
};
use fungi_wire::CanonicalMessage;
use futures_util::future::{try_join, try_join_all};

use crate::{SessionBindingError, SessionContract, error::ApplicationViolation, hello};

/// First violation that ended a channel, replayed on every later use.
///
/// A bare flag would say only THAT the link died. Which of the several
/// unrelated causes did it is what a group debugging a stalled construction
/// actually needs, so the diagnosis is kept, not just the bit.
#[derive(Debug, Default)]
struct Poison(OnceLock<String>);

impl Poison {
    /// Record a cause. The FIRST one is retained: a later failure is a
    /// consequence of it, never a better explanation.
    fn record(&self, cause: &impl fmt::Display) {
        let _ = self.0.set(cause.to_string());
    }

    fn is_dead(&self) -> bool {
        self.0.get().is_some()
    }

    fn cause(&self) -> Option<&str> {
        self.0.get().map(String::as_str)
    }
}

/// P2P channel admitted to one exact protocol-session context.
///
/// Every message crossing it is checked against the contract validated at
/// binding time: complete canonical form, the exact session and version, and
/// the negotiated size limit.
///
/// A PEER violation is fatal: the operation that observes it reports the
/// violation itself, and every later call reports
/// [`Closed`](SendError::Closed), the one signal every layer above knows how
/// to act on. The diagnosis stays available through [`failure`].
///
/// A violation this node commits locally is not fatal: a message refused here
/// never reached the wire, so the link is untouched and the error is the
/// caller's to correct, exactly like [`SendError::TooLarge`]. This mirrors the
/// framing layer, where poisoning means the wire itself may be torn.
///
/// [`failure`]: SessionBoundChannel::failure
///
/// Cancel-safety is inherited unchanged from the underlying halves: the checks
/// add no await point, so dropping a `send` or `recv` future loses precisely
/// what dropping the inner one would.
#[derive(Debug)]
pub struct SessionBoundChannel<C> {
    inner: C,
    contract: SessionContract,
    poison: Poison,
}

impl<C> SessionBoundChannel<C> {
    /// Return the contract validated during connection-local binding.
    pub const fn contract(&self) -> SessionContract {
        self.contract
    }

    /// Why this channel died, if it did. Later calls report only
    /// [`Closed`](SendError::Closed) so the dead-channel signal survives
    /// unchanged through the layers above; the cause is kept here instead of
    /// being flattened into that signal.
    pub fn failure(&self) -> Option<&str> {
        self.poison.cause()
    }
}

/// A bound channel has earned admission: everything crossing it is checked
/// against the session contract, in both directions.
impl<C: SplitChannel> SessionBound for SessionBoundChannel<C> {}

/// Bind one raw P2P channel before admitting application traffic.
///
/// Both hellos go out concurrently, so the local session is on the wire before
/// the peer's has been seen: anyone who completes a transport connection learns
/// which session this node is constructing. That follows from the identity
/// being context rather than a credential, and it is why a handshake that ever
/// has to AUTHENTICATE membership cannot be built by extending this one — it
/// would have to commit to the secret instead of revealing it.
///
/// There is no internal deadline: a peer that never sends its hello leaves
/// this pending for as long as the transport keeps the connection open. Bound
/// it externally — over an anonymising transport that wait is otherwise
/// unbounded.
pub async fn bind<C>(
    mut channel: C,
    contract: SessionContract,
) -> Result<SessionBoundChannel<C>, SessionBindingError>
where
    C: SplitChannel,
{
    let local = hello::encode(contract);
    let remote = {
        let (mut sender, mut receiver) = channel.split();
        let send = async { sender.send(&local).await.map_err(SessionBindingError::Send) };
        let receive = async { receiver.recv().await.map_err(SessionBindingError::Receive) };
        let (_, remote) = try_join(send, receive).await?;
        remote
    };
    hello::validate(contract, hello::decode(&remote)?)?;
    Ok(SessionBoundChannel {
        inner: channel,
        contract,
        poison: Poison::default(),
    })
}

/// Bind every P2P link concurrently, returning no partially admitted group.
///
/// The first failure abandons the rest, so no channel outlives a group that
/// never formed. Like [`bind`], this imposes no deadline of its own.
///
/// Reach for it only when the group is not a [`GossipBroadcast`]: otherwise
/// [`bind_group`] does the same and applies the negotiated size limit, which
/// is the step easiest to leave out.
pub async fn bind_all<C>(
    channels: Vec<C>,
    contract: SessionContract,
) -> Result<Vec<SessionBoundChannel<C>>, SessionBindingError>
where
    C: SplitChannel,
{
    try_join_all(channels.into_iter().map(|channel| bind(channel, contract))).await
}

/// Bind every link and form the group's gossip node, in one step.
///
/// This is the production path, and it closes both ways a group could be
/// formed wrongly: links that were never admitted are refused by the type
/// system, and the size limit applied is the one both ends actually agreed to
/// rather than one the caller has to remember to repeat.
pub async fn bind_group<C>(
    channels: Vec<C>,
    contract: SessionContract,
) -> Result<GossipBroadcast, SessionBindingError>
where
    C: SplitChannel + 'static,
{
    let channels = bind_all(channels, contract).await?;
    Ok(GossipBroadcast::new(channels).with_max_msg_len(contract.max_message_size().get()))
}

pub(crate) fn validate_application(
    contract: SessionContract,
    bytes: &[u8],
) -> Result<(), ApplicationViolation> {
    match CanonicalMessage::validate(bytes) {
        Ok(context) if context == contract.context() => Ok(()),
        Ok(context) => Err(ApplicationViolation::ContextMismatch {
            expected: contract.context(),
            received: context,
        }),
        // Only bytes that are no application message at all are classified by
        // shape, so a hello-shaped frame that IS valid traffic keeps its
        // meaning instead of being mistaken for a repeated handshake.
        Err(_) if hello::looks_like(bytes) => Err(ApplicationViolation::UnexpectedHandshake),
        Err(error) => Err(ApplicationViolation::Malformed(error)),
    }
}

async fn send_checked<S: SendHalf>(
    sender: &mut S,
    contract: SessionContract,
    poison: &Poison,
    message: &[u8],
) -> Result<(), SendError> {
    if poison.is_dead() {
        return Err(SendError::Closed);
    }
    if message.len() > contract.max_message_size().get() {
        return Err(SendError::TooLarge {
            max: contract.max_message_size().get(),
        });
    }
    if let Err(violation) = validate_application(contract, message) {
        return Err(SendError::Transport(violation.into()));
    }
    match sender.send(message).await {
        Err(error) if !matches!(error, SendError::TooLarge { .. }) => {
            poison.record(&error);
            Err(error)
        }
        result => result,
    }
}

async fn recv_checked<R: RecvHalf>(
    receiver: &mut R,
    contract: SessionContract,
    poison: &Poison,
) -> Result<Vec<u8>, RecvError> {
    if poison.is_dead() {
        return Err(RecvError::Closed);
    }
    let message = match receiver.recv().await {
        Ok(message) => message,
        Err(error) => {
            poison.record(&error);
            return Err(error);
        }
    };
    if message.len() > contract.max_message_size().get() {
        let violation = ApplicationViolation::TooLarge {
            actual: message.len(),
            max: contract.max_message_size(),
        };
        poison.record(&violation);
        return Err(RecvError::Transport(violation.into()));
    }
    if let Err(violation) = validate_application(contract, &message) {
        poison.record(&violation);
        return Err(RecvError::Transport(violation.into()));
    }
    Ok(message)
}

impl<C: SplitChannel> Channel for SessionBoundChannel<C> {
    async fn send(&mut self, message: &[u8]) -> Result<(), SendError> {
        let (mut sender, _) = self.inner.split();
        send_checked(&mut sender, self.contract, &self.poison, message).await
    }

    async fn recv(&mut self) -> Result<Vec<u8>, RecvError> {
        let (_, mut receiver) = self.inner.split();
        recv_checked(&mut receiver, self.contract, &self.poison).await
    }
}

/// Sending half of a session-bound P2P channel.
#[derive(Debug)]
pub struct SessionSendHalf<'a, S> {
    inner: S,
    contract: SessionContract,
    poison: &'a Poison,
}

impl<S: SendHalf> SendHalf for SessionSendHalf<'_, S> {
    fn send(&mut self, message: &[u8]) -> impl Future<Output = Result<(), SendError>> + Send {
        send_checked(&mut self.inner, self.contract, self.poison, message)
    }
}

/// Receiving half of a session-bound P2P channel.
#[derive(Debug)]
pub struct SessionRecvHalf<'a, R> {
    inner: R,
    contract: SessionContract,
    poison: &'a Poison,
}

impl<R: RecvHalf> RecvHalf for SessionRecvHalf<'_, R> {
    fn recv(&mut self) -> impl Future<Output = Result<Vec<u8>, RecvError>> + Send {
        recv_checked(&mut self.inner, self.contract, self.poison)
    }
}

impl<C: SplitChannel> SplitChannel for SessionBoundChannel<C> {
    type SendHalf<'a>
        = SessionSendHalf<'a, C::SendHalf<'a>>
    where
        Self: 'a;
    type RecvHalf<'a>
        = SessionRecvHalf<'a, C::RecvHalf<'a>>
    where
        Self: 'a;

    fn split(&mut self) -> (Self::SendHalf<'_>, Self::RecvHalf<'_>) {
        let (sender, receiver) = self.inner.split();
        (
            SessionSendHalf {
                inner: sender,
                contract: self.contract,
                poison: &self.poison,
            },
            SessionRecvHalf {
                inner: receiver,
                contract: self.contract,
                poison: &self.poison,
            },
        )
    }
}
