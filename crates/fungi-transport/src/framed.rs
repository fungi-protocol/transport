//! Length-prefix framing: adapt any byte stream into a datagram [`Channel`].
//!
//! Wire format: 4-byte big-endian payload length, then the payload — the
//! least machinery that restores message boundaries over a raw byte stream.
//! Kept intentionally minimal because a typed (TLV) format is expected to
//! replace the wire format later, leaving the [`Channel`] interface intact.
//!
//! Cancel safety: all partial-frame state lives in [`FramedChannel`], not in
//! the `recv` future, so a `recv` dropped mid-frame (e.g. by `select!`)
//! resumes exactly where it stopped. `send` is NOT cancel safe: dropping a
//! `send` future mid-write can leave a half-written frame on the stream —
//! treat the channel as dead afterwards. A send that FAILS poisons the
//! channel itself: later sends and recvs return `Closed`.

use std::future::Future;
use std::sync::atomic::{AtomicBool, Ordering};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadHalf, WriteHalf};

use crate::channel::{Channel, RecvHalf, SendHalf, SplitChannel};
use crate::error::{RecvError, SendError};

/// Default maximum message size (1 MiB).
pub const DEFAULT_MAX_MSG_LEN: usize = 1024 * 1024;

/// A [`Channel`] over any byte stream, delimiting messages with a 4-byte
/// big-endian length prefix. Generic over the stream so one framing layer
/// serves every byte-stream backend — a tor daemon's `TcpStream`, an
/// in-process arti data stream — instead of each reimplementing framing.
#[derive(Debug)]
pub struct FramedChannel<S> {
    writer: WriteHalf<S>,
    reader: ReadHalf<S>,
    max_msg_len: usize,
    read: ReadState,
    // Set on protocol violation or a write error (torn frame); every later
    // send and recv returns Closed. Shared rather than owned by one
    // direction: either direction can poison, and both must see it — that
    // is what keeps one object one fate once the halves are split apart.
    poisoned: AtomicBool,
}

/// Partial-frame read state (cancel safety: lives in the channel, not in the
/// `recv` future).
#[derive(Debug, Default)]
struct ReadState {
    header: [u8; 4],
    header_filled: usize,
    payload: Vec<u8>,
    payload_filled: usize,
}

impl<S> FramedChannel<S>
where
    S: AsyncRead + AsyncWrite,
{
    /// Wrap `stream`. `max_msg_len` bounds both directions: larger sends
    /// fail with [`SendError::TooLarge`], larger incoming frames poison the
    /// channel (a peer announcing a huge frame must not induce the
    /// allocation).
    ///
    /// The stream is split into its two directions on the way in, so the
    /// channel can hand them out separately later ([`SplitChannel`]) without
    /// ever giving up single ownership of the stream.
    ///
    /// # Panics
    ///
    /// If `max_msg_len` does not fit in the u32 length prefix.
    pub fn new(stream: S, max_msg_len: usize) -> Self {
        assert!(
            u32::try_from(max_msg_len).is_ok(),
            "max_msg_len must fit in the u32 length prefix"
        );
        let (reader, writer) = tokio::io::split(stream);
        Self {
            writer,
            reader,
            max_msg_len,
            read: ReadState::default(),
            poisoned: AtomicBool::new(false),
        }
    }
}

/// Write-side errors: peer/stream gone maps to `Closed`, the rest is opaque.
fn map_send_io(e: std::io::Error) -> SendError {
    use std::io::ErrorKind::*;
    match e.kind() {
        BrokenPipe | ConnectionReset | ConnectionAborted | UnexpectedEof | WriteZero => {
            SendError::Closed
        }
        _ => SendError::Transport(e.into()),
    }
}

/// Read-side errors: reset means the peer is gone, the rest is opaque.
fn map_recv_io(e: std::io::Error) -> RecvError {
    use std::io::ErrorKind::*;
    match e.kind() {
        ConnectionReset | ConnectionAborted => RecvError::Closed,
        _ => RecvError::Transport(e.into()),
    }
}

/// The whole write path, shared by the unified channel and its sending half
/// so the two can never drift.
async fn send_frame<W>(
    writer: &mut W,
    max_msg_len: usize,
    poisoned: &AtomicBool,
    msg: &[u8],
) -> Result<(), SendError>
where
    W: AsyncWrite + Send + Unpin,
{
    if poisoned.load(Ordering::Relaxed) {
        return Err(SendError::Closed);
    }
    if msg.len() > max_msg_len {
        return Err(SendError::TooLarge { max: max_msg_len });
    }
    // Any io error may leave a torn frame on the wire; poison so no later
    // send writes a fresh frame over bytes the peer would misparse.
    // (`TooLarge` above never touches the stream — the one recoverable send
    // error.)
    let result: Result<(), std::io::Error> = async {
        // max_msg_len fits in u32 (checked in new), so msg.len() does too.
        let prefix = (msg.len() as u32).to_be_bytes();
        writer.write_all(&prefix).await?;
        writer.write_all(msg).await?;
        writer.flush().await
    }
    .await;
    result.map_err(|e| {
        poisoned.store(true, Ordering::Relaxed);
        map_send_io(e)
    })
}

/// The whole read path, shared by the unified channel and its receiving
/// half. All partial-frame state is in `state`, never in this future.
async fn recv_frame<R>(
    reader: &mut R,
    state: &mut ReadState,
    max_msg_len: usize,
    poisoned: &AtomicBool,
) -> Result<Vec<u8>, RecvError>
where
    R: AsyncRead + Send + Unpin,
{
    if poisoned.load(Ordering::Relaxed) {
        return Err(RecvError::Closed);
    }
    while state.header_filled < 4 {
        let n = reader
            .read(&mut state.header[state.header_filled..])
            .await
            .map_err(map_recv_io)?;
        if n == 0 {
            // EOF between frames is a clean close; inside one, a truncation.
            if state.header_filled == 0 {
                return Err(RecvError::Closed);
            }
            poisoned.store(true, Ordering::Relaxed);
            return Err(RecvError::Transport("stream ended mid-frame".into()));
        }
        state.header_filled += n;
    }
    let len = u32::from_be_bytes(state.header) as usize;
    if len > max_msg_len {
        poisoned.store(true, Ordering::Relaxed);
        return Err(RecvError::Transport(
            format!("peer announced a {len}-byte frame, exceeding the {max_msg_len}-byte maximum")
                .into(),
        ));
    }
    // First entry for this frame: payload was taken (empty) after the
    // previous one. On cancel-resume it is already sized.
    if state.payload.len() != len {
        state.payload.resize(len, 0);
    }
    while state.payload_filled < len {
        let n = reader
            .read(&mut state.payload[state.payload_filled..])
            .await
            .map_err(map_recv_io)?;
        if n == 0 {
            poisoned.store(true, Ordering::Relaxed);
            return Err(RecvError::Transport("stream ended mid-frame".into()));
        }
        state.payload_filled += n;
    }
    state.header_filled = 0;
    state.payload_filled = 0;
    Ok(std::mem::take(&mut state.payload))
}

impl<S> Channel for FramedChannel<S>
where
    S: AsyncRead + AsyncWrite + Send + Unpin,
{
    fn send(&mut self, msg: &[u8]) -> impl Future<Output = Result<(), SendError>> + Send {
        send_frame(&mut self.writer, self.max_msg_len, &self.poisoned, msg)
    }

    fn recv(&mut self) -> impl Future<Output = Result<Vec<u8>, RecvError>> + Send {
        recv_frame(
            &mut self.reader,
            &mut self.read,
            self.max_msg_len,
            &self.poisoned,
        )
    }
}

/// Sending half of a split [`FramedChannel`].
#[derive(Debug)]
pub struct FramedSendHalf<'a, S> {
    writer: &'a mut WriteHalf<S>,
    max_msg_len: usize,
    poisoned: &'a AtomicBool,
}

/// Receiving half of a split [`FramedChannel`], carrying the partial-frame
/// state so a cancelled `recv` still resumes where it stopped.
#[derive(Debug)]
pub struct FramedRecvHalf<'a, S> {
    reader: &'a mut ReadHalf<S>,
    read: &'a mut ReadState,
    max_msg_len: usize,
    poisoned: &'a AtomicBool,
}

impl<S> SendHalf for FramedSendHalf<'_, S>
where
    S: AsyncRead + AsyncWrite + Send + Unpin,
{
    fn send(&mut self, msg: &[u8]) -> impl Future<Output = Result<(), SendError>> + Send {
        send_frame(self.writer, self.max_msg_len, self.poisoned, msg)
    }
}

impl<S> RecvHalf for FramedRecvHalf<'_, S>
where
    S: AsyncRead + AsyncWrite + Send + Unpin,
{
    fn recv(&mut self) -> impl Future<Output = Result<Vec<u8>, RecvError>> + Send {
        recv_frame(self.reader, self.read, self.max_msg_len, self.poisoned)
    }
}

impl<S> SplitChannel for FramedChannel<S>
where
    S: AsyncRead + AsyncWrite + Send + Unpin,
{
    type SendHalf<'a>
        = FramedSendHalf<'a, S>
    where
        Self: 'a;
    type RecvHalf<'a>
        = FramedRecvHalf<'a, S>
    where
        Self: 'a;

    fn split(&mut self) -> (FramedSendHalf<'_, S>, FramedRecvHalf<'_, S>) {
        (
            FramedSendHalf {
                writer: &mut self.writer,
                max_msg_len: self.max_msg_len,
                poisoned: &self.poisoned,
            },
            FramedRecvHalf {
                reader: &mut self.reader,
                read: &mut self.read,
                max_msg_len: self.max_msg_len,
                poisoned: &self.poisoned,
            },
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testkit;

    /// A connected pair of framed channels over an in-process duplex pipe.
    fn framed_pair(
        max: usize,
    ) -> (
        FramedChannel<tokio::io::DuplexStream>,
        FramedChannel<tokio::io::DuplexStream>,
    ) {
        // 64 KiB pipe buffer: big enough that small test frames never
        // deadlock on unread data. Partial-read coverage lives in the
        // byte-dribble tests (`cancelled_recv_mid_frame_resumes`), not here.
        let (a, b) = tokio::io::duplex(64 * 1024);
        (FramedChannel::new(a, max), FramedChannel::new(b, max))
    }

    #[tokio::test]
    async fn roundtrip_both_directions() {
        let (a, b) = framed_pair(DEFAULT_MAX_MSG_LEN);
        testkit::roundtrip_both_directions(a, b).await;
    }

    #[tokio::test]
    async fn too_large_is_rejected() {
        let (a, _b) = framed_pair(16);
        testkit::too_large(a, 16).await;
    }

    #[tokio::test]
    async fn too_large_is_recoverable() {
        let (a, b) = framed_pair(16);
        testkit::too_large_is_recoverable(a, b, 16).await;
    }

    /// AsyncRead/AsyncWrite double that injects exactly one write error once
    /// `fail_at` total bytes have been written — an io failure mid-frame.
    struct FailOnce {
        inner: tokio::io::DuplexStream,
        written: usize,
        fail_at: usize,
        failed: bool,
    }

    impl tokio::io::AsyncWrite for FailOnce {
        fn poll_write(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
            buf: &[u8],
        ) -> std::task::Poll<std::io::Result<usize>> {
            if !self.failed && self.written + buf.len() > self.fail_at {
                self.failed = true;
                return std::task::Poll::Ready(Err(std::io::Error::other(
                    "injected mid-frame failure",
                )));
            }
            let n = std::task::ready!(std::pin::Pin::new(&mut self.inner).poll_write(cx, buf))?;
            self.written += n;
            std::task::Poll::Ready(Ok(n))
        }
        fn poll_flush(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::pin::Pin::new(&mut self.inner).poll_flush(cx)
        }
        fn poll_shutdown(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::pin::Pin::new(&mut self.inner).poll_shutdown(cx)
        }
    }

    impl tokio::io::AsyncRead for FailOnce {
        fn poll_read(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
            buf: &mut tokio::io::ReadBuf<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::pin::Pin::new(&mut self.inner).poll_read(cx, buf)
        }
    }

    /// An io error mid-frame leaves a torn frame on the wire; the channel
    /// must refuse everything afterwards rather than write a fresh frame
    /// over garbage the peer would misparse.
    #[tokio::test]
    async fn send_error_poisons_the_channel() {
        use crate::error::SendError;
        let (raw, _other) = tokio::io::duplex(64 * 1024);
        let mut ch = FramedChannel::new(
            FailOnce {
                inner: raw,
                written: 0,
                fail_at: 6, // 4-byte prefix + 2 payload bytes: fails mid-payload
                failed: false,
            },
            1024,
        );
        assert!(matches!(
            ch.send(b"hello").await,
            Err(SendError::Transport(_))
        ));
        assert!(matches!(ch.send(b"next").await, Err(SendError::Closed)));
        assert!(matches!(ch.recv().await, Err(RecvError::Closed)));
    }

    #[tokio::test]
    async fn recv_after_peer_drop_is_closed() {
        let (a, b) = framed_pair(DEFAULT_MAX_MSG_LEN);
        testkit::closed_after_peer_drop(a, b).await;
    }

    #[tokio::test]
    async fn recv_is_cancel_safe() {
        let (a, b) = framed_pair(DEFAULT_MAX_MSG_LEN);
        testkit::recv_is_cancel_safe(a, b).await;
    }

    use crate::error::RecvError;

    #[tokio::test]
    async fn empty_message_roundtrips() {
        let (mut a, mut b) = framed_pair(DEFAULT_MAX_MSG_LEN);
        a.send(b"").await.unwrap();
        a.send(b"after").await.unwrap();
        assert_eq!(b.recv().await.unwrap(), b"");
        assert_eq!(b.recv().await.unwrap(), b"after");
    }

    /// A peer announcing a frame larger than our maximum must not induce
    /// the allocation: the channel errors and is dead afterwards.
    #[tokio::test]
    async fn oversized_incoming_frame_poisons_channel() {
        use tokio::io::AsyncWriteExt;
        let (raw, b) = tokio::io::duplex(64 * 1024);
        let mut b = FramedChannel::new(b, 16);
        let mut raw = raw;
        // Hand-written frame header announcing 17 bytes (max is 16).
        raw.write_all(&17u32.to_be_bytes()).await.unwrap();
        assert!(matches!(b.recv().await, Err(RecvError::Transport(_))));
        // Poisoned: even though bytes could still arrive, the channel is dead.
        assert!(matches!(b.recv().await, Err(RecvError::Closed)));
    }

    /// Cancelling recv mid-frame (header split across writes) must not lose
    /// or corrupt the message — the next recv resumes where it stopped.
    #[tokio::test]
    async fn cancelled_recv_mid_frame_resumes() {
        use tokio::io::AsyncWriteExt;
        let (raw, b) = tokio::io::duplex(64 * 1024);
        let mut b = FramedChannel::new(b, DEFAULT_MAX_MSG_LEN);
        let mut raw = raw;
        let frame = {
            let mut f = 5u32.to_be_bytes().to_vec();
            f.extend_from_slice(b"hello");
            f
        };
        // Dribble the frame one byte at a time; cancel a recv between bytes.
        for &byte in &frame[..frame.len() - 1] {
            raw.write_all(&[byte]).await.unwrap();
            raw.flush().await.unwrap();
            // recv cannot complete yet; time it out (= cancel the future).
            let poll = tokio::time::timeout(std::time::Duration::from_millis(5), b.recv()).await;
            assert!(poll.is_err(), "recv completed on a partial frame");
        }
        raw.write_all(&frame[frame.len() - 1..]).await.unwrap();
        assert_eq!(b.recv().await.unwrap(), b"hello");
    }

    /// EOF in the middle of a frame is a truncation, not a clean close.
    #[tokio::test]
    async fn eof_mid_frame_is_transport_error() {
        use tokio::io::AsyncWriteExt;
        let (raw, b) = tokio::io::duplex(64 * 1024);
        let mut b = FramedChannel::new(b, DEFAULT_MAX_MSG_LEN);
        let mut raw = raw;
        raw.write_all(&5u32.to_be_bytes()).await.unwrap();
        raw.write_all(b"he").await.unwrap();
        drop(raw); // EOF with 3 payload bytes missing
        assert!(matches!(b.recv().await, Err(RecvError::Transport(_))));
    }

    /// send after max-size check writes prefix+payload+flush; a message of
    /// exactly max_msg_len is allowed.
    #[tokio::test]
    async fn exactly_max_size_is_allowed() {
        let (mut a, mut b) = framed_pair(8);
        a.send(&[7u8; 8]).await.unwrap();
        assert_eq!(b.recv().await.unwrap(), [7u8; 8]);
    }

    mod properties {
        use super::*;
        use proptest::prelude::*;

        fn rt() -> tokio::runtime::Runtime {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("building the proptest runtime")
        }

        proptest! {
            #![proptest_config(ProptestConfig::with_cases(64))]

            /// Any sequence of within-limit messages survives framing intact
            /// and in order (framing over one stream preserves order).
            #[test]
            fn arbitrary_messages_roundtrip(
                msgs in proptest::collection::vec(
                    proptest::collection::vec(any::<u8>(), 0..2048),
                    1..8,
                ),
            ) {
                rt().block_on(async {
                    let (mut a, mut b) = framed_pair(2048);
                    for msg in &msgs {
                        a.send(msg).await.unwrap();
                        assert_eq!(&b.recv().await.unwrap(), msg);
                    }
                });
            }

            /// Arbitrary bytes on the wire never panic the reader: every recv
            /// yields a message within the limit or an error, and once it
            /// errors the channel stays dead instead of hanging.
            #[test]
            fn arbitrary_garbage_never_panics(
                bytes in proptest::collection::vec(any::<u8>(), 0..512),
            ) {
                rt().block_on(async {
                    use tokio::io::AsyncWriteExt;
                    let (mut raw, rx) = tokio::io::duplex(64 * 1024);
                    let mut ch = FramedChannel::new(rx, 64);
                    raw.write_all(&bytes).await.unwrap();
                    drop(raw); // EOF bounds the loop: recv must terminate
                    while let Ok(msg) = ch.recv().await {
                        assert!(msg.len() <= 64);
                    }
                    assert!(ch.recv().await.is_err());
                });
            }
        }
    }

    /// Once the peer is gone, sends must map to `SendError::Closed`, not an
    /// opaque `Transport` error. A tokio duplex pipe surfaces BrokenPipe on
    /// a write to a dropped peer — sometimes only after it has buffered one
    /// write — so retry a bounded number of times.
    #[tokio::test]
    async fn send_after_peer_drop_is_closed() {
        use crate::error::SendError;
        let (mut a, b) = framed_pair(DEFAULT_MAX_MSG_LEN);
        drop(b);
        let mut last = None;
        for _ in 0..16 {
            match a.send(b"x").await {
                Ok(()) => continue,
                Err(err) => {
                    last = Some(err);
                    break;
                }
            }
        }
        let err = last.expect("send never errored after peer drop");
        assert!(matches!(err, SendError::Closed));
    }

    // The property the split exists for, on the layer the real backends use:
    // two peers pushing while draining each other over a pipe too narrow to
    // hold more than a frame, so every write after the first waits on the
    // reader. Driven through `Channel` alone this pair deadlocks.
    #[tokio::test]
    async fn mutual_bursts_converge_over_a_narrow_stream() {
        // Frames here are 6 bytes (4-byte prefix + 2-byte payload), so an
        // 8-byte pipe cannot hold two of them.
        let (a, b) = tokio::io::duplex(8);
        let a = FramedChannel::new(a, DEFAULT_MAX_MSG_LEN);
        let b = FramedChannel::new(b, DEFAULT_MAX_MSG_LEN);
        testkit::mutual_bursts_converge(a, b, 64).await;
    }
}
