//! Opaque identity of a message's sender, for attributable channels.
//!
//! [`SenderId`] is the identity an [`AttributableChannel`](crate::AttributableChannel)
//! exposes: which peer a message is from. It is a lookup key — compared and
//! hashed, never interpreted. Each backend implements it for its own identity
//! type (a Tor onion key, an OHTTP mailbox credential), so the transport
//! layer imposes no representation; consumers receive `impl SenderId` and can
//! only use it as a key.

use std::hash::Hash;

/// An opaque sender identity: a lookup key for who sent a message.
///
/// Implementors are the identity types of individual backends. The bounds are
/// the whole contract: [`Eq`] + [`Hash`] make it a map key, [`Clone`] lets a
/// consumer keep a copy, and `Send + Sync` let it cross tasks. Consumers do
/// not construct or interpret one — they compare it and use it as a key.
///
/// [`as_bytes`](SenderId::as_bytes) exposes a stable byte form ONLY for the
/// points that must serialize an identity (carrying it across a plugin
/// boundary, or keying a type-erased collection). It is not a way to read the
/// identity's meaning — the value stays opaque.
pub trait SenderId: Clone + Eq + Hash + Send + Sync + 'static {
    /// The identity's stable byte encoding, for serialization at a transport
    /// boundary. Two ids are equal iff their bytes are equal.
    fn as_bytes(&self) -> &[u8];
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    /// A minimal `SenderId` implementor, standing in for a backend's identity
    /// type, to exercise the trait's contract.
    #[derive(Clone, Debug, PartialEq, Eq, Hash)]
    struct TestSender(Vec<u8>);

    impl SenderId for TestSender {
        fn as_bytes(&self) -> &[u8] {
            &self.0
        }
    }

    /// A `SenderId` works as a map key: equal ids collide, distinct ids don't,
    /// and the value is retrievable by an equal (cloned) key.
    #[test]
    fn sender_id_is_a_lookup_key() {
        let a = TestSender(b"alice".to_vec());
        let b = TestSender(b"bob".to_vec());
        let mut seen: HashMap<TestSender, u32> = HashMap::new();
        seen.insert(a.clone(), 1);
        seen.insert(b.clone(), 2);

        assert_eq!(seen.get(&a.clone()), Some(&1));
        assert_eq!(seen.get(&b), Some(&2));
        assert_eq!(seen.get(&TestSender(b"carol".to_vec())), None);
    }

    /// Equality follows the bytes: same bytes are equal, different bytes are not.
    #[test]
    fn equality_follows_bytes() {
        let a = TestSender(b"alice".to_vec());
        assert_eq!(a, TestSender(b"alice".to_vec()));
        assert_ne!(a, TestSender(b"alicE".to_vec()));
        assert_eq!(a.as_bytes(), b"alice");
    }

    /// The trait is a generic bound, not a trait object — a consumer takes
    /// `impl SenderId` and uses it as a key without ever seeing a concrete type.
    fn assert_usable_as_bound<S: SenderId>(id: &S) -> Vec<u8> {
        id.as_bytes().to_vec()
    }

    #[test]
    fn usable_through_a_generic_bound() {
        assert_eq!(assert_usable_as_bound(&TestSender(b"x".to_vec())), b"x");
    }
}
