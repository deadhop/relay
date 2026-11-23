//! Nostr events (NIP-01): parsing, the canonical id, and the Schnorr signature.
//!
//! Only what this relay needs. The event keeps the exact JSON it arrived as,
//! so subscribers get the bytes the author signed and the relay serialises
//! each event once.

use std::sync::{Arc, LazyLock};

use secp256k1::{schnorr, Message, Secp256k1, VerifyOnly, XOnlyPublicKey};
use serde::Deserialize;
use serde_json::value::RawValue;
use sha2::{Digest, Sha256};

/// A ContextVM message (MCP over Nostr), plain or signed by the sender.
pub const CTXVM: u16 = 25910;
/// A NIP-59 gift wrap: the encrypted form of a ContextVM message.
pub const GIFT_WRAP: u16 = 1059;
/// The ephemeral gift wrap ContextVM uses so relays need not keep it.
pub const EPHEMERAL_GIFT_WRAP: u16 = 21059;
/// NIP-42 authentication.
pub const AUTH: u16 = 22242;

/// Kinds a ContextVM peer sends to another: requests and replies.
pub const MESSAGE_KINDS: [u16; 3] = [CTXVM, GIFT_WRAP, EPHEMERAL_GIFT_WRAP];

/// Kinds only a whitelisted key may publish about itself: its profile, its
/// relay list and the ContextVM announcements (server, tools, resources,
/// resource templates, prompts).
pub const ANNOUNCE_KINDS: [u16; 7] = [0, 10002, 11316, 11317, 11318, 11319, 11320];

/// A 32-byte key or id.
pub type Key = [u8; 32];

static SECP: LazyLock<Secp256k1<VerifyOnly>> = LazyLock::new(Secp256k1::verification_only);

#[derive(Deserialize)]
struct Wire {
    id: String,
    pubkey: String,
    created_at: u64,
    kind: u16,
    tags: Vec<Vec<String>>,
    content: String,
    sig: String,
}

/// A parsed event. `raw` is the JSON object exactly as received.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Event {
    pub id: Key,
    pub pubkey: Key,
    pub created_at: u64,
    pub kind: u16,
    pub tags: Vec<Vec<String>>,
    pub content: String,
    pub sig: [u8; 64],
    pub raw: Arc<str>,
}

/// Decode exactly `N` bytes of lowercase or uppercase hex.
pub fn hex_bytes<const N: usize>(s: &str) -> Option<[u8; N]> {
    let mut out = [0u8; N];
    hex::decode_to_slice(s, &mut out).ok().map(|()| out)
}

impl Event {
    /// Parse an event object. Fails on a malformed shape, never on a bad id or
    /// signature: those are checked by [`Event::verify`], after the cheaper
    /// policy checks have run.
    pub fn parse(raw: &RawValue) -> Result<Event, String> {
        let w: Wire = serde_json::from_str(raw.get()).map_err(|e| format!("invalid: bad event ({e})"))?;
        let id = hex_bytes::<32>(&w.id).ok_or("invalid: id is not 32 bytes of hex")?;
        let pubkey = hex_bytes::<32>(&w.pubkey).ok_or("invalid: pubkey is not 32 bytes of hex")?;
        let sig = hex_bytes::<64>(&w.sig).ok_or("invalid: sig is not 64 bytes of hex")?;
        Ok(Event {
            id,
            pubkey,
            created_at: w.created_at,
            kind: w.kind,
            tags: w.tags,
            content: w.content,
            sig,
            raw: Arc::from(raw.get()),
        })
    }

    /// The NIP-01 id: sha256 of `[0, pubkey, created_at, kind, tags, content]`.
    pub fn compute_id(&self) -> Key {
        let canon = (
            0,
            hex::encode(self.pubkey),
            self.created_at,
            self.kind,
            &self.tags,
            &self.content,
        );
        Sha256::digest(serde_json::to_vec(&canon).expect("strings and numbers always serialise")).into()
    }

    /// Check the id and the signature.
    pub fn verify(&self) -> Result<(), &'static str> {
        if self.compute_id() != self.id {
            return Err("invalid: event id does not match its content");
        }
        let ok = XOnlyPublicKey::from_slice(&self.pubkey).ok().is_some_and(|pk| {
            let sig = schnorr::Signature::from_slice(&self.sig).expect("64 bytes is a signature's length");
            SECP.verify_schnorr(&sig, &Message::from_digest(self.id), &pk).is_ok()
        });
        if ok {
            Ok(())
        } else {
            Err("invalid: bad signature")
        }
    }

    /// Values of every tag named `name` (`["p", value, ...]` gives `value`).
    pub fn tag_values<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a str> + 'a {
        self.tags
            .iter()
            .filter(move |t| t.first().is_some_and(|n| n == name))
            .filter_map(|t| t.get(1).map(String::as_str))
    }

    /// The keys this event is addressed to (its `p` tags).
    pub fn recipients(&self) -> Vec<Key> {
        self.tag_values("p").filter_map(hex_bytes::<32>).collect()
    }

    /// The value of the event's first tag named `name`.
    pub fn first_tag<'a>(&'a self, name: &'a str) -> Option<&'a str> {
        self.tag_values(name).next()
    }

    pub fn is_ephemeral(&self) -> bool {
        (20000..30000).contains(&self.kind)
    }

    /// Replaceable (NIP-01): the relay keeps only the latest per author and kind.
    pub fn is_replaceable(&self) -> bool {
        self.kind == 0 || self.kind == 3 || (10000..20000).contains(&self.kind)
    }
}

/// NIP-13: the number of leading zero bits of an id.
pub fn leading_zero_bits(id: &Key) -> u32 {
    let mut bits = 0;
    for b in id {
        bits += b.leading_zeros();
        if *b != 0 {
            break;
        }
    }
    bits
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use nostr_sdk::prelude::{EventBuilder, Keys, Kind, Tag};
    use proptest::prelude::*;

    /// Turn an nostr-sdk event into this crate's event, through JSON.
    pub fn from_sdk(e: &nostr_sdk::Event) -> Event {
        let json = serde_json::to_string(e).unwrap();
        let raw: Box<RawValue> = serde_json::from_str(&json).unwrap();
        Event::parse(&raw).unwrap()
    }

    pub fn signed(keys: &Keys, kind: u16, content: &str, tags: Vec<Tag>) -> Event {
        from_sdk(
            &EventBuilder::new(Kind::Custom(kind), content)
                .tags(tags)
                .sign_with_keys(keys)
                .unwrap(),
        )
    }

    #[test]
    fn a_signed_event_verifies_and_keeps_its_bytes() {
        let keys = Keys::generate();
        let target = Keys::generate().public_key();
        let e = signed(&keys, CTXVM, "{\"x\":1}", vec![Tag::public_key(target)]);
        assert_eq!(e.verify(), Ok(()));
        assert_eq!(e.recipients(), vec![target.to_bytes()]);
        assert_eq!(e.first_tag("p"), Some(target.to_hex().as_str()));
        assert_eq!(e.first_tag("e"), None);
        assert!(e.raw.contains("\"sig\""));
        assert!(e.is_ephemeral() && !e.is_replaceable());
    }

    #[test]
    fn a_changed_event_fails() {
        let keys = Keys::generate();
        let mut e = signed(&keys, GIFT_WRAP, "hello", vec![]);
        assert!(!e.is_ephemeral());
        e.content.push('!');
        assert_eq!(e.verify(), Err("invalid: event id does not match its content"));
        let mut e = signed(&keys, GIFT_WRAP, "hello", vec![]);
        e.sig[0] ^= 1;
        assert_eq!(e.verify(), Err("invalid: bad signature"));
        // A pubkey that is not on the curve.
        let mut e = signed(&keys, GIFT_WRAP, "hello", vec![]);
        e.pubkey = [0xff; 32];
        e.id = e.compute_id();
        assert_eq!(e.verify(), Err("invalid: bad signature"));
    }

    #[test]
    fn replaceable_kinds() {
        let keys = Keys::generate();
        for (kind, r) in [
            (0, true),
            (3, true),
            (10002, true),
            (11316, true),
            (1, false),
            (21059, false),
        ] {
            assert_eq!(signed(&keys, kind, "", vec![]).is_replaceable(), r, "kind {kind}");
        }
    }

    #[test]
    fn malformed_events_say_why() {
        let bad = |json: &str| {
            let raw: Box<RawValue> = serde_json::from_str(json).unwrap();
            Event::parse(&raw).unwrap_err()
        };
        assert!(bad("{}").starts_with("invalid: bad event"));
        let good = signed(&Keys::generate(), CTXVM, "", vec![]);
        let v: serde_json::Value = serde_json::from_str(&good.raw).unwrap();
        for (field, val, want) in [
            ("id", "zz", "invalid: id is not 32 bytes of hex"),
            ("pubkey", "00", "invalid: pubkey is not 32 bytes of hex"),
            ("sig", "00", "invalid: sig is not 64 bytes of hex"),
        ] {
            let mut v = v.clone();
            v[field] = serde_json::Value::String(val.into());
            assert_eq!(bad(&v.to_string()), want);
        }
    }

    #[test]
    fn leading_zeros() {
        let mut id = [0u8; 32];
        assert_eq!(leading_zero_bits(&id), 256);
        id[1] = 0x10;
        assert_eq!(leading_zero_bits(&id), 11);
        id[0] = 0x80;
        assert_eq!(leading_zero_bits(&id), 0);
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(64))]
        /// The id this crate computes matches nostr-sdk's for any content and
        /// tag text, including quotes, backslashes, control and non-ASCII characters.
        #[test]
        fn ids_match_nostr_sdk(content in "\\PC*|[\\x00-\\x1f\"\\\\/\u{7f}\u{2028}é😀]{0,40}", tag in "[\\x00-\\x7f]{0,20}") {
            let keys = Keys::generate();
            let sdk = EventBuilder::new(Kind::Custom(CTXVM), &content)
                .tag(Tag::parse(["x", tag.as_str()]).unwrap())
                .sign_with_keys(&keys)
                .unwrap();
            let e = from_sdk(&sdk);
            prop_assert_eq!(e.compute_id(), sdk.id.to_bytes());
            prop_assert_eq!(e.verify(), Ok(()));
        }
    }
}
