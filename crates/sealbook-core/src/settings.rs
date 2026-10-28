//! The account settings payload: which keys a writer owns, how one is written,
//! and how one is read back.
//!
//! The web and Android each kept the object on their own. They agreed on the
//! keys but not on what a save keeps: Android rebuilt `features` from the five
//! flags it knows, so a flag a newer build had added was dropped by the next
//! toggle on that device, and the web kept only the unknown flags that were
//! booleans.
//!
//! **A flag this build does not know survives.** [`CoreAccountSettings`] carries
//! them in `unknown_features`, and the writer lays the features it owns over the
//! stored `features` object rather than replacing it.
//!
//! **A missing flag is on.** A build that predates a feature writes no flag for
//! it, and that must not read as the user having switched it off.
//!
//! **At least one feature stays on.** The writer repairs an all-off set to the
//! first feature, so a client that skipped the rule cannot write an empty
//! account.

use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};

use crate::payload::{as_object, declared_readable, refuse_newer_major, write_payload};
use crate::CoreError;
use sealbook_protocol::PAYLOAD_SCHEMA_VERSION;

pub use sealbook_protocol::ACCOUNT_SETTINGS_ID;

/// A client that does not know this content type ignores the object, so the
/// toggles degrade to everything enabled there.
pub const ACCOUNT_SETTINGS_CONTENT_TYPE: &str = "application/sealbook.settings+json";

/// Where the web client sealed these settings before the default calendar took
/// the id. Read only to migrate them off it.
pub const LEGACY_ACCOUNT_SETTINGS_ID: &str = "00000000-0000-0000-0000-000000000003";

pub const ACCOUNT_SETTINGS_KEYS: &[&str] =
    &["@type", "version", "features", "contactMode", "accent"];

/// Also the order the features appear in the UI.
pub const FEATURES: &[&str] = &["contacts", "calendar", "notes", "bookmarks", "tasks"];

pub const CONTACT_MODES: &[&str] = &["basic", "detailed"];
pub const DEFAULT_CONTACT_MODE: &str = "basic";

/// Also the order the swatches appear in the UI.
pub const ACCENTS: &[&str] = &["blue", "cyan", "green", "amber", "rose", "purple"];
pub const DEFAULT_ACCENT: &str = "blue";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct CoreFeatureFlag {
    pub key: String,
    pub enabled: bool,
}

/// The settings as they are drafted.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct CoreAccountSettingsDraft {
    /// A flag missing here is on.
    pub features: Vec<CoreFeatureFlag>,
    /// Flags from a newer build, written back untouched. A feature this build
    /// knows but the host has no screen for rides here too.
    #[serde(default)]
    pub unknown_features: Vec<CoreFeatureFlag>,
    pub contact_mode: String,
    pub accent: String,
    /// The stored payload this edit starts from.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub raw: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct CoreAccountSettings {
    /// Every known feature, in [`FEATURES`] order.
    pub features: Vec<CoreFeatureFlag>,
    /// Boolean flags this build does not know, sorted by key.
    pub unknown_features: Vec<CoreFeatureFlag>,
    pub contact_mode: String,
    pub accent: String,
    /// Whether this build reads the schema major the payload declares. False
    /// means the fields above were still read, but [`settings_write`] refuses.
    pub readable: bool,
    pub raw: String,
}

impl CoreAccountSettings {
    /// The draft that writes these settings back unchanged.
    pub fn draft(&self) -> CoreAccountSettingsDraft {
        CoreAccountSettingsDraft {
            features: self.features.clone(),
            unknown_features: self.unknown_features.clone(),
            contact_mode: self.contact_mode.clone(),
            accent: self.accent.clone(),
            raw: Some(self.raw.clone()),
        }
    }

    pub fn is_enabled(&self, feature: &str) -> bool {
        self.features
            .iter()
            .find(|flag| flag.key == feature)
            .map(|flag| flag.enabled)
            .unwrap_or(true)
    }
}

/// An account that has never chosen: everything on, basic contacts, blue.
pub fn default_account_settings() -> CoreAccountSettings {
    settings_parse("")
}

pub fn normalize_contact_mode(value: &str) -> String {
    if value == "detailed" {
        "detailed"
    } else {
        DEFAULT_CONTACT_MODE
    }
    .to_string()
}

pub fn normalize_accent(value: &str) -> String {
    if ACCENTS.contains(&value) {
        value
    } else {
        DEFAULT_ACCENT
    }
    .to_string()
}

/// Reads a stored settings payload.
///
/// Lenient throughout: a payload that will not parse reads as the defaults, so
/// it never takes the vault down or hides a feature the user still has data in.
pub fn settings_parse(raw: &str) -> CoreAccountSettings {
    let object = as_object(raw);
    let stored = object
        .as_ref()
        .and_then(|object| object.get("features"))
        .and_then(Value::as_object);
    let flag = |key: &str| stored.and_then(|stored| stored.get(key)) != Some(&Value::Bool(false));
    let features: Vec<(String, bool)> = FEATURES
        .iter()
        .map(|key| (key.to_string(), flag(key)))
        .collect();
    let mut unknown: Vec<CoreFeatureFlag> = stored
        .into_iter()
        .flatten()
        .filter(|(key, _)| !FEATURES.contains(&key.as_str()))
        .filter_map(|(key, value)| {
            value.as_bool().map(|enabled| CoreFeatureFlag {
                key: key.clone(),
                enabled,
            })
        })
        .collect();
    unknown.sort_by(|a, b| a.key.cmp(&b.key));
    let text = |key: &str| {
        object
            .as_ref()
            .and_then(|object| object.get(key))
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string()
    };
    CoreAccountSettings {
        features: repaired(features),
        unknown_features: unknown,
        contact_mode: normalize_contact_mode(&text("contactMode")),
        accent: normalize_accent(&text("accent")),
        readable: object.as_ref().map(declared_readable).unwrap_or(true),
        raw: raw.to_string(),
    }
}

/// The flags in [`FEATURES`] order, with the first one switched on if none is.
fn repaired(flags: Vec<(String, bool)>) -> Vec<CoreFeatureFlag> {
    let none_on = flags.iter().all(|(_, enabled)| !enabled);
    flags
        .into_iter()
        .enumerate()
        .map(|(index, (key, enabled))| CoreFeatureFlag {
            key,
            enabled: enabled || (none_on && index == 0),
        })
        .collect()
}

/// Serialises settings onto `draft.raw`. Refuses over a newer schema major.
pub fn settings_write(draft: &CoreAccountSettingsDraft) -> Result<String, CoreError> {
    refuse_newer_major(draft.raw.as_deref())?;

    // A host that has no screen for a feature passes its flag among the unknown
    // ones, so a known flag is looked for in both lists.
    let named = |key: &str| {
        draft
            .features
            .iter()
            .chain(&draft.unknown_features)
            .find(|flag| flag.key == key)
            .map(|flag| flag.enabled)
            .unwrap_or(true)
    };
    let known = repaired(
        FEATURES
            .iter()
            .map(|key| (key.to_string(), named(key)))
            .collect(),
    );

    // The stored object is the base, so a flag of any type this build does not
    // know is written back as it was found.
    let mut features: Map<String, Value> = draft
        .raw
        .as_deref()
        .and_then(as_object)
        .and_then(|object| match object.get("features") {
            Some(Value::Object(stored)) => Some(stored.clone()),
            _ => None,
        })
        .unwrap_or_default();
    for flag in draft
        .unknown_features
        .iter()
        .filter(|flag| !FEATURES.contains(&flag.key.as_str()))
        .chain(&known)
    {
        features.insert(flag.key.clone(), json!(flag.enabled));
    }

    Ok(write_payload(
        draft.raw.as_deref(),
        json!({
            "@type": "AccountSettings",
            "version": PAYLOAD_SCHEMA_VERSION,
            "features": features,
            "contactMode": normalize_contact_mode(&draft.contact_mode),
            "accent": normalize_accent(&draft.accent),
        }),
        ACCOUNT_SETTINGS_KEYS,
    ))
}

/// False for the last enabled feature, which is the one the rule protects, and
/// for one that is already off or not a feature.
pub fn can_disable_feature(settings: &CoreAccountSettings, feature: &str) -> bool {
    FEATURES.contains(&feature)
        && settings.is_enabled(feature)
        && settings.features.iter().filter(|flag| flag.enabled).count() > 1
}

/// The settings with one feature flipped, or unchanged when the change would
/// leave the account with no features at all or names no feature.
pub fn settings_with_feature(
    settings: &CoreAccountSettings,
    feature: &str,
    enabled: bool,
) -> CoreAccountSettings {
    if !FEATURES.contains(&feature) || (!enabled && !can_disable_feature(settings, feature)) {
        return settings.clone();
    }
    let mut next = settings.clone();
    for flag in &mut next.features {
        if flag.key == feature {
            flag.enabled = enabled;
        }
    }
    next
}

/// Everything above, in the shapes the bindings can carry.
#[cfg(feature = "uniffi")]
pub mod ffi {
    use super::{CoreAccountSettings, CoreAccountSettingsDraft, CoreError};

    #[uniffi::export(name = "account_settings_keys")]
    pub fn account_settings_keys() -> Vec<String> {
        super::ACCOUNT_SETTINGS_KEYS
            .iter()
            .map(|key| key.to_string())
            .collect()
    }

    #[uniffi::export(name = "default_account_settings")]
    pub fn default_account_settings() -> CoreAccountSettings {
        super::default_account_settings()
    }

    #[uniffi::export(name = "settings_parse")]
    pub fn settings_parse(raw: String) -> CoreAccountSettings {
        super::settings_parse(&raw)
    }

    #[uniffi::export(name = "settings_write")]
    pub fn settings_write(draft: CoreAccountSettingsDraft) -> Result<String, CoreError> {
        super::settings_write(&draft)
    }

    #[uniffi::export(name = "settings_with_feature")]
    pub fn settings_with_feature(
        settings: CoreAccountSettings,
        feature: String,
        enabled: bool,
    ) -> CoreAccountSettings {
        super::settings_with_feature(&settings, &feature, enabled)
    }

    #[uniffi::export(name = "can_disable_feature")]
    pub fn can_disable_feature(settings: CoreAccountSettings, feature: String) -> bool {
        super::can_disable_feature(&settings, &feature)
    }
}
