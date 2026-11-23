//! Subscription filters (NIP-01), with size limits.

use serde_json::{Map, Value};

use crate::event::{hex_bytes, Event, Key};

/// Most values one filter field may list.
pub const MAX_VALUES: usize = 64;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Filter {
    pub ids: Option<Vec<Key>>,
    pub authors: Option<Vec<Key>>,
    pub kinds: Option<Vec<u16>>,
    /// `#p` and other single-letter tag conditions.
    pub tags: Vec<(String, Vec<String>)>,
    pub since: Option<u64>,
    pub until: Option<u64>,
    pub limit: Option<usize>,
}

fn list(v: &Value, field: &str) -> Result<Vec<Value>, String> {
    match v {
        Value::Array(a) if a.len() <= MAX_VALUES => Ok(a.clone()),
        Value::Array(_) => Err(format!("invalid: {field} lists more than {MAX_VALUES} values")),
        _ => Err(format!("invalid: {field} must be a list")),
    }
}

fn keys(v: &Value, field: &str) -> Result<Vec<Key>, String> {
    list(v, field)?
        .iter()
        .map(|k| {
            k.as_str()
                .and_then(hex_bytes::<32>)
                .ok_or(format!("invalid: {field} holds a value that is not 32 bytes of hex"))
        })
        .collect()
}

fn number(v: &Value, field: &str) -> Result<u64, String> {
    v.as_u64().ok_or(format!("invalid: {field} must be a whole number"))
}

impl Filter {
    /// Parse one filter object.
    pub fn parse(v: &Value) -> Result<Filter, String> {
        let Some(obj) = v.as_object() else {
            return Err("invalid: a filter must be an object".into());
        };
        Self::from_map(obj)
    }

    fn from_map(obj: &Map<String, Value>) -> Result<Filter, String> {
        let mut f = Filter::default();
        for (k, v) in obj {
            match k.as_str() {
                "ids" => f.ids = Some(keys(v, "ids")?),
                "authors" => f.authors = Some(keys(v, "authors")?),
                "kinds" => {
                    let kinds = list(v, "kinds")?
                        .iter()
                        .map(|k| k.as_u64().filter(|k| *k <= u64::from(u16::MAX)).map(|k| k as u16))
                        .collect::<Option<Vec<u16>>>()
                        .ok_or("invalid: kinds holds a value that is not a kind")?;
                    f.kinds = Some(kinds);
                }
                "since" => f.since = Some(number(v, "since")?),
                "until" => f.until = Some(number(v, "until")?),
                "limit" => f.limit = Some(number(v, "limit")? as usize),
                tag if tag.len() == 2 && tag.starts_with('#') => {
                    let values = list(v, tag)?
                        .iter()
                        .map(|s| s.as_str().map(str::to_string))
                        .collect::<Option<Vec<String>>>()
                        .ok_or(format!("invalid: {tag} must list strings"))?;
                    f.tags.push((tag[1..].to_string(), values));
                }
                other => return Err(format!("invalid: unknown filter field {other}")),
            }
        }
        Ok(f)
    }

    /// The `#p` values this filter asks for, decoded as keys.
    pub fn p_keys(&self) -> Vec<Key> {
        self.tags
            .iter()
            .filter(|(n, _)| n == "p")
            .flat_map(|(_, vals)| vals.iter().filter_map(|v| hex_bytes::<32>(v)))
            .collect()
    }

    /// Whether the filter is narrowed to named keys (`#p` or `authors`), as
    /// this relay requires of every subscription.
    pub fn is_scoped(&self) -> bool {
        self.authors.as_ref().is_some_and(|a| !a.is_empty()) || !self.p_keys().is_empty()
    }

    pub fn matches(&self, e: &Event) -> bool {
        self.ids.as_ref().is_none_or(|ids| ids.contains(&e.id))
            && self.authors.as_ref().is_none_or(|a| a.contains(&e.pubkey))
            && self.kinds.as_ref().is_none_or(|k| k.contains(&e.kind))
            && self.since.is_none_or(|s| e.created_at >= s)
            && self.until.is_none_or(|u| e.created_at <= u)
            && self
                .tags
                .iter()
                .all(|(name, vals)| e.tag_values(name).any(|v| vals.iter().any(|w| w == v)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::tests::signed;
    use crate::event::CTXVM;
    use nostr_sdk::prelude::{Keys, Tag};
    use serde_json::json;

    #[test]
    fn parses_and_matches_a_contextvm_subscription() {
        let me = Keys::generate();
        let author = Keys::generate();
        let e = signed(&author, CTXVM, "{}", vec![Tag::public_key(me.public_key())]);
        let f = Filter::parse(&json!({"kinds": [25910, 1059], "#p": [me.public_key().to_hex()], "since": e.created_at, "until": e.created_at, "limit": 5})).unwrap();
        assert!(f.is_scoped());
        assert_eq!(f.p_keys(), vec![me.public_key().to_bytes()]);
        assert_eq!(f.limit, Some(5));
        assert!(f.matches(&e));
        let by_author =
            Filter::parse(&json!({"authors": [author.public_key().to_hex()], "ids": ["00".repeat(32)]})).unwrap();
        assert!(by_author.is_scoped());
        assert!(!by_author.matches(&e), "the id differs");
        let by_id = Filter::parse(&json!({"ids": [hex::encode(e.id)]})).unwrap();
        assert!(by_id.matches(&e) && !by_id.is_scoped());
        for miss in [
            json!({"kinds": [1059]}),
            json!({"since": e.created_at + 1}),
            json!({"until": e.created_at - 1}),
            json!({"#p": [author.public_key().to_hex()]}),
            json!({"#e": ["x"]}),
            json!({"authors": [me.public_key().to_hex()]}),
        ] {
            assert!(!Filter::parse(&miss).unwrap().matches(&e), "{miss}");
        }
        assert!(!Filter::parse(&json!({"authors": []})).unwrap().is_scoped());
        assert!(!Filter::parse(&json!({"#p": ["not hex"]})).unwrap().is_scoped());
    }

    #[test]
    fn refuses_bad_filters() {
        let too_many: Vec<String> = (0..=MAX_VALUES).map(|i| format!("{i}")).collect();
        for (v, want) in [
            (json!([]), "invalid: a filter must be an object"),
            (json!({"ids": "x"}), "invalid: ids must be a list"),
            (json!({"#p": too_many}), "invalid: #p lists more than 64 values"),
            (
                json!({"authors": ["zz"]}),
                "invalid: authors holds a value that is not 32 bytes of hex",
            ),
            (
                json!({"kinds": [70000]}),
                "invalid: kinds holds a value that is not a kind",
            ),
            (json!({"since": -1}), "invalid: since must be a whole number"),
            (json!({"#p": [1]}), "invalid: #p must list strings"),
            (json!({"search": "x"}), "invalid: unknown filter field search"),
        ] {
            assert_eq!(Filter::parse(&v).unwrap_err(), want);
        }
    }
}
