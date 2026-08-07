//! Human-readable duration type used throughout the v1 config model.
//!
//! Accepts humantime strings (`"5s"`, `"100ms"`, `"2m 30s"`) as well as
//! bare numbers, which are interpreted as seconds.

use std::fmt;
use std::time::Duration;

use schemars::gen::SchemaGenerator;
use schemars::schema::{InstanceType, Schema, SchemaObject};
use schemars::JsonSchema;
use serde::de::{self, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// A [`Duration`] that serializes as a humantime string (e.g. `"5s"`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct HumanDuration(pub Duration);

impl HumanDuration {
    pub const fn from_secs(secs: u64) -> Self {
        Self(Duration::from_secs(secs))
    }

    pub const fn from_millis(millis: u64) -> Self {
        Self(Duration::from_millis(millis))
    }

    pub fn as_secs(&self) -> u64 {
        self.0.as_secs()
    }

    pub fn as_millis(&self) -> u128 {
        self.0.as_millis()
    }
}

impl From<Duration> for HumanDuration {
    fn from(d: Duration) -> Self {
        Self(d)
    }
}

impl From<HumanDuration> for Duration {
    fn from(d: HumanDuration) -> Self {
        d.0
    }
}

impl fmt::Display for HumanDuration {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", humantime::format_duration(self.0))
    }
}

impl Serialize for HumanDuration {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&humantime::format_duration(self.0).to_string())
    }
}

struct HumanDurationVisitor;

impl Visitor<'_> for HumanDurationVisitor {
    type Value = HumanDuration;

    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("a duration string like \"5s\" or a number of seconds")
    }

    fn visit_str<E: de::Error>(self, value: &str) -> Result<Self::Value, E> {
        humantime::parse_duration(value)
            .map(HumanDuration)
            .map_err(|err| E::custom(format!("invalid duration {value:?}: {err}")))
    }

    fn visit_u64<E: de::Error>(self, value: u64) -> Result<Self::Value, E> {
        Ok(HumanDuration(Duration::from_secs(value)))
    }

    fn visit_i64<E: de::Error>(self, value: i64) -> Result<Self::Value, E> {
        if value < 0 {
            return Err(E::custom("duration cannot be negative"));
        }
        Ok(HumanDuration(Duration::from_secs(value as u64)))
    }

    fn visit_f64<E: de::Error>(self, value: f64) -> Result<Self::Value, E> {
        if !value.is_finite() || value < 0.0 {
            return Err(E::custom("duration must be a finite, non-negative number"));
        }
        Ok(HumanDuration(Duration::from_secs_f64(value)))
    }
}

impl<'de> Deserialize<'de> for HumanDuration {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_any(HumanDurationVisitor)
    }
}

impl JsonSchema for HumanDuration {
    fn schema_name() -> String {
        "HumanDuration".to_string()
    }

    fn json_schema(_gen: &mut SchemaGenerator) -> Schema {
        let mut schema = SchemaObject::default();
        schema.metadata().description = Some(
            "Human-readable duration (e.g. \"5s\", \"100ms\", \"2m 30s\") or a bare number of seconds"
                .to_string(),
        );
        schema.subschemas().any_of = Some(vec![
            Schema::Object(SchemaObject {
                instance_type: Some(InstanceType::String.into()),
                ..Default::default()
            }),
            Schema::Object(SchemaObject {
                instance_type: Some(InstanceType::Number.into()),
                ..Default::default()
            }),
        ]);
        Schema::Object(schema)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, Deserialize, Serialize, PartialEq)]
    struct Holder {
        d: HumanDuration,
    }

    #[test]
    fn parses_humantime_strings() {
        let h: Holder = serde_yaml::from_str("d: 5s").unwrap();
        assert_eq!(h.d, HumanDuration::from_secs(5));

        let h: Holder = serde_yaml::from_str("d: 100ms").unwrap();
        assert_eq!(h.d, HumanDuration::from_millis(100));

        let h: Holder = serde_yaml::from_str("d: 2m 30s").unwrap();
        assert_eq!(h.d, HumanDuration::from_secs(150));
    }

    #[test]
    fn parses_bare_numbers_as_seconds() {
        let h: Holder = serde_yaml::from_str("d: 30").unwrap();
        assert_eq!(h.d, HumanDuration::from_secs(30));
    }

    #[test]
    fn rejects_garbage() {
        assert!(serde_yaml::from_str::<Holder>("d: banana").is_err());
        assert!(serde_yaml::from_str::<Holder>("d: -5").is_err());
    }

    #[test]
    fn serializes_as_string() {
        let yaml = serde_yaml::to_string(&Holder {
            d: HumanDuration::from_secs(90),
        })
        .unwrap();
        assert_eq!(yaml.trim(), "d: 1m 30s");
    }
}
