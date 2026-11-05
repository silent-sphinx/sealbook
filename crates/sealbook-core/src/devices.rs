//! Device labels: the friendly name, kind and platform each device seals into
//! the vault, joined onto the verified roster for display.
//!
//! A label is an ordinary sealed object, so the server sees neither the name
//! nor the platform. It is display only: which devices exist, and which keys
//! they hold, is still decided by the roster alone.

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use uuid::Uuid;

use crate::payload::{as_object, declared_readable, refuse_newer_major, trimmed, write_payload};
use crate::CoreError;
use sealbook_protocol::PAYLOAD_SCHEMA_VERSION;

pub use sealbook_protocol::DEVICE_LABEL_CONTENT_TYPE;

pub const DEVICE_LABEL_KEYS: &[&str] =
    &["@type", "version", "deviceId", "name", "kind", "platform"];

pub const MAX_DEVICE_NAME_CHARS: usize = 40;
pub const MAX_DEVICE_PLATFORM_CHARS: usize = 60;

pub const DEVICE_KINDS: &[&str] = &["web", "firefox", "android", "cli"];

const ADJECTIVES: [&str; 64] = [
    "Amber", "Arctic", "Bold", "Brave", "Bright", "Brisk", "Calm", "Clever", "Cosmic", "Crimson",
    "Curious", "Dapper", "Dawn", "Eager", "Electric", "Emerald", "Fabled", "Fern", "Fleet",
    "Frosty", "Gentle", "Gilded", "Glad", "Golden", "Hazel", "Humble", "Indigo", "Ivory", "Jade",
    "Jolly", "Keen", "Kind", "Lively", "Lucky", "Lunar", "Mellow", "Misty", "Mossy", "Nimble",
    "Noble", "Ochre", "Patient", "Plucky", "Polar", "Quiet", "Rapid", "Rosy", "Russet", "Rustic",
    "Sandy", "Scarlet", "Silent", "Silver", "Smoky", "Snowy", "Solar", "Steady", "Sunny", "Swift",
    "Teal", "Tidal", "Velvet", "Witty", "Zesty",
];

const NOUNS: [&str; 64] = [
    "Badger", "Beacon", "Bison", "Brook", "Canyon", "Cedar", "Comet", "Condor", "Coral", "Crane",
    "Dolphin", "Dune", "Eagle", "Ember", "Falcon", "Finch", "Fjord", "Fox", "Gecko", "Glacier",
    "Grove", "Harbor", "Hare", "Heron", "Ibis", "Jaguar", "Kestrel", "Koala", "Lagoon", "Lark",
    "Lynx", "Maple", "Marten", "Meadow", "Meteor", "Moose", "Nebula", "Newt", "Orca", "Osprey",
    "Otter", "Owl", "Panda", "Pebble", "Pine", "Puffin", "Quail", "Raven", "Reef", "Ridge",
    "Robin", "Sparrow", "Spruce", "Summit", "Swan", "Thistle", "Tiger", "Tundra", "Valley",
    "Walrus", "Willow", "Wren", "Yak", "Zephyr",
];

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
pub enum CoreDeviceKind {
    Web,
    Firefox,
    Android,
    Cli,
    Unknown,
}

impl CoreDeviceKind {
    fn from_wire(value: &str) -> Self {
        match value {
            "web" => Self::Web,
            "firefox" => Self::Firefox,
            "android" => Self::Android,
            "cli" => Self::Cli,
            _ => Self::Unknown,
        }
    }

    fn wire(self) -> Option<&'static str> {
        match self {
            Self::Web => Some("web"),
            Self::Firefox => Some("firefox"),
            Self::Android => Some("android"),
            Self::Cli => Some("cli"),
            Self::Unknown => None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct CoreDeviceLabel {
    #[cfg_attr(feature = "wasm", tsify(type = "string"))]
    pub device_id: Uuid,
    /// Empty when the payload carries none; display falls back to the default.
    pub name: String,
    pub kind: CoreDeviceKind,
    pub platform: String,
    pub readable: bool,
}

/// A sealed label as the host holds it: the object id and its plaintext.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct CoreDeviceLabelObject {
    pub object_id: String,
    pub payload: String,
}

/// One roster device as the devices screen shows it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct CoreDeviceEntry {
    #[cfg_attr(feature = "wasm", tsify(type = "string"))]
    pub device_id: Uuid,
    pub name: String,
    pub kind: CoreDeviceKind,
    /// "Firefox extension · macOS", or a note that the device has not reported.
    pub detail: String,
    pub is_current: bool,
    /// The label object to write a rename over, absent when there is none yet.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "wasm", tsify(optional))]
    pub label: Option<CoreDeviceLabelObject>,
}

pub const UNREPORTED_DEVICE_DETAIL: &str = "Device type not reported yet";

/// The name a device has before anyone renames it, stable for its id.
pub fn device_default_name(device_id: Uuid) -> String {
    let bytes = device_id.as_bytes();
    format!(
        "{} {}",
        ADJECTIVES[(bytes[14] % 64) as usize],
        NOUNS[(bytes[15] % 64) as usize]
    )
}

fn clamp(value: &str, max: usize) -> String {
    value
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .chars()
        .filter(|c| !c.is_control())
        .take(max)
        .collect::<String>()
        .trim_end()
        .to_string()
}

/// Whitespace collapsed and capped at [`MAX_DEVICE_NAME_CHARS`]. Empty means
/// "use the default".
pub fn normalize_device_name(name: &str) -> String {
    clamp(name, MAX_DEVICE_NAME_CHARS)
}

pub fn device_kind_label(kind: CoreDeviceKind) -> String {
    match kind {
        CoreDeviceKind::Web => "Web browser",
        CoreDeviceKind::Firefox => "Firefox extension",
        CoreDeviceKind::Android => "Android device",
        CoreDeviceKind::Cli => "CLI",
        CoreDeviceKind::Unknown => "Device",
    }
    .to_string()
}

/// The browser family named by a user agent, or empty when none is recognised.
pub fn user_agent_browser(ua: &str) -> String {
    let has = |needle: &str| ua.contains(needle);
    if has("Firefox/") || has("FxiOS/") {
        "Firefox"
    } else if has("Edg/") || has("EdgA/") || has("EdgiOS/") {
        "Edge"
    } else if has("OPR/") || has("Opera") {
        "Opera"
    } else if has("SamsungBrowser/") {
        "Samsung Internet"
    } else if has("Chrome/") || has("CriOS/") || has("Chromium/") {
        "Chrome"
    } else if has("Safari/") && has("Version/") {
        "Safari"
    } else {
        ""
    }
    .to_string()
}

/// The operating system named by a user agent, or empty when none is recognised.
pub fn user_agent_os(ua: &str) -> String {
    let has = |needle: &str| ua.contains(needle);
    if has("iPad") {
        "iPadOS"
    } else if has("iPhone") || has("iPod") {
        "iOS"
    } else if has("Android") {
        "Android"
    } else if has("CrOS") {
        "ChromeOS"
    } else if has("Windows") {
        "Windows"
    } else if has("Macintosh") || has("Mac OS X") {
        "macOS"
    } else if has("Linux") || has("X11") {
        "Linux"
    } else {
        ""
    }
    .to_string()
}

/// "Firefox on macOS", for a web client's platform line.
pub fn describe_user_agent(ua: &str) -> String {
    let browser = user_agent_browser(ua);
    let os = user_agent_os(ua);
    match (browser.is_empty(), os.is_empty()) {
        (false, false) => format!("{browser} on {os}"),
        (false, true) => browser,
        (true, false) => os,
        (true, true) => String::new(),
    }
}

/// A Rust `std::env::consts::OS` value as people write it.
pub fn os_display_name(os: &str) -> String {
    match os {
        "macos" => "macOS".to_string(),
        "ios" => "iOS".to_string(),
        "linux" => "Linux".to_string(),
        "windows" => "Windows".to_string(),
        "android" => "Android".to_string(),
        "freebsd" => "FreeBSD".to_string(),
        "openbsd" => "OpenBSD".to_string(),
        "netbsd" => "NetBSD".to_string(),
        other => {
            let mut chars = other.chars();
            chars
                .next()
                .map(|first| first.to_uppercase().chain(chars).collect())
                .unwrap_or_default()
        }
    }
}

/// "Google Pixel 8a" from Android's `Build.MANUFACTURER` and `Build.MODEL`,
/// without repeating a manufacturer the model already names.
pub fn android_model_name(manufacturer: &str, model: &str) -> String {
    let manufacturer = manufacturer.trim();
    let model = model.trim();
    let brand = if manufacturer.chars().any(char::is_uppercase) {
        manufacturer.to_string()
    } else {
        os_display_name(manufacturer)
    };
    let named = if manufacturer.is_empty()
        || model
            .to_lowercase()
            .starts_with(&manufacturer.to_lowercase())
    {
        model.to_string()
    } else {
        format!("{brand} {model}")
    };
    clamp(&named, MAX_DEVICE_PLATFORM_CHARS)
}

/// Reads a stored label. `None` when the payload names no valid device.
pub fn device_label_parse(raw: &str) -> Option<CoreDeviceLabel> {
    let object = as_object(raw)?;
    let device_id = trimmed(&object, "deviceId")?.parse::<Uuid>().ok()?;
    Some(CoreDeviceLabel {
        device_id,
        name: normalize_device_name(&trimmed(&object, "name").unwrap_or_default()),
        kind: CoreDeviceKind::from_wire(&trimmed(&object, "kind").unwrap_or_default()),
        platform: clamp(
            &trimmed(&object, "platform").unwrap_or_default(),
            MAX_DEVICE_PLATFORM_CHARS,
        ),
        readable: declared_readable(&object),
    })
}

fn write_label(
    previous: Option<&str>,
    device_id: Uuid,
    name: &str,
    kind: Option<String>,
    platform: &str,
) -> Result<String, CoreError> {
    refuse_newer_major(previous)?;
    let mut fields = json!({
        "@type": "DeviceLabel",
        "version": PAYLOAD_SCHEMA_VERSION,
        "deviceId": device_id.to_string(),
        "name": normalize_device_name(name),
    });
    if let Some(kind) = kind {
        fields["kind"] = Value::String(kind);
    }
    let platform = clamp(platform, MAX_DEVICE_PLATFORM_CHARS);
    if !platform.is_empty() {
        fields["platform"] = Value::String(platform);
    }
    Ok(write_payload(previous, fields, DEVICE_LABEL_KEYS))
}

/// The label for `device_id` among `labels`, the lowest object id winning when
/// a race left two.
fn label_for(
    labels: &[CoreDeviceLabelObject],
    device_id: Uuid,
) -> Option<(CoreDeviceLabelObject, CoreDeviceLabel)> {
    labels
        .iter()
        .filter_map(|object| {
            device_label_parse(&object.payload)
                .filter(|label| label.device_id == device_id)
                .map(|label| (object.clone(), label))
        })
        .min_by(|a, b| a.0.object_id.cmp(&b.0.object_id))
}

/// What this device should write so its label says what it is, or `None` when
/// the stored one already does. A new label takes a fresh object id; an
/// existing one keeps its name.
pub fn device_label_ensure(
    labels: &[CoreDeviceLabelObject],
    device_id: Uuid,
    kind: CoreDeviceKind,
    platform: &str,
) -> Result<Option<CoreDeviceLabelObject>, CoreError> {
    let platform = clamp(platform, MAX_DEVICE_PLATFORM_CHARS);
    let existing = label_for(labels, device_id);
    if let Some((_, label)) = &existing {
        if !label.readable
            || (label.kind == kind && label.platform == platform && !label.name.is_empty())
        {
            return Ok(None);
        }
    }
    let name = existing
        .as_ref()
        .map(|(_, label)| label.name.clone())
        .filter(|name| !name.is_empty())
        .unwrap_or_else(|| device_default_name(device_id));
    let object_id = existing
        .as_ref()
        .map(|(object, _)| object.object_id.clone())
        .unwrap_or_else(|| Uuid::new_v4().to_string());
    let previous = existing.as_ref().map(|(object, _)| object.payload.as_str());
    let payload = write_label(
        previous,
        device_id,
        &name,
        kind.wire().map(str::to_string),
        &platform,
    )?;
    Ok(Some(CoreDeviceLabelObject { object_id, payload }))
}

/// Renames a device. The kind and platform are kept as stored, including a
/// kind this build does not know. An empty name restores the default.
pub fn device_label_rename(
    labels: &[CoreDeviceLabelObject],
    device_id: Uuid,
    name: &str,
) -> Result<CoreDeviceLabelObject, CoreError> {
    let existing = label_for(labels, device_id);
    let previous = existing.as_ref().map(|(object, _)| object.payload.as_str());
    let stored = previous.and_then(as_object);
    let raw_kind = stored.as_ref().and_then(|object| trimmed(object, "kind"));
    let platform = stored
        .as_ref()
        .and_then(|object| trimmed(object, "platform"))
        .unwrap_or_default();
    let name = match normalize_device_name(name) {
        empty if empty.is_empty() => device_default_name(device_id),
        named => named,
    };
    let payload = write_label(previous, device_id, &name, raw_kind, &platform)?;
    let object_id = existing
        .map(|(object, _)| object.object_id)
        .unwrap_or_else(|| Uuid::new_v4().to_string());
    Ok(CoreDeviceLabelObject { object_id, payload })
}

/// The roster's devices with their labels, this device first and the rest in
/// roster order. A name two devices share gets each one's id prefix appended.
pub fn device_entries(
    roster: &[Uuid],
    labels: &[CoreDeviceLabelObject],
    current: Uuid,
) -> Vec<CoreDeviceEntry> {
    let mut entries: Vec<CoreDeviceEntry> = roster
        .iter()
        .map(|&device_id| {
            let found = label_for(labels, device_id);
            let (name, kind, detail) = match &found {
                Some((_, label)) => {
                    let mut detail = device_kind_label(label.kind);
                    if !label.platform.is_empty() {
                        detail = format!("{detail} · {}", label.platform);
                    }
                    let name = if label.name.is_empty() {
                        device_default_name(device_id)
                    } else {
                        label.name.clone()
                    };
                    (name, label.kind, detail)
                }
                None => (
                    device_default_name(device_id),
                    CoreDeviceKind::Unknown,
                    UNREPORTED_DEVICE_DETAIL.to_string(),
                ),
            };
            CoreDeviceEntry {
                device_id,
                name,
                kind,
                detail,
                is_current: device_id == current,
                label: found.map(|(object, _)| object),
            }
        })
        .collect();
    let names: Vec<String> = entries.iter().map(|e| e.name.to_lowercase()).collect();
    for (index, entry) in entries.iter_mut().enumerate() {
        if names.iter().filter(|name| **name == names[index]).count() > 1 {
            let short = entry.device_id.simple().to_string();
            entry.name = format!("{} ({})", entry.name, &short[short.len() - 4..]);
        }
    }
    entries.sort_by_key(|entry| !entry.is_current);
    entries
}

/// Label objects to tombstone: those for devices no longer on the roster, and
/// the losing copies a write race left behind.
pub fn stale_device_labels(roster: &[Uuid], labels: &[CoreDeviceLabelObject]) -> Vec<String> {
    let kept: Vec<String> = roster
        .iter()
        .filter_map(|&device| label_for(labels, device).map(|(object, _)| object.object_id))
        .collect();
    labels
        .iter()
        .filter(|object| !kept.contains(&object.object_id))
        .map(|object| object.object_id.clone())
        .collect()
}

#[cfg(feature = "uniffi")]
pub mod ffi {
    use super::{CoreDeviceEntry, CoreDeviceKind, CoreDeviceLabel, CoreDeviceLabelObject};
    use crate::CoreError;
    use uuid::Uuid;

    #[uniffi::export(name = "device_default_name")]
    pub fn device_default_name(device_id: Uuid) -> String {
        super::device_default_name(device_id)
    }

    #[uniffi::export(name = "normalize_device_name")]
    pub fn normalize_device_name(name: String) -> String {
        super::normalize_device_name(&name)
    }

    #[uniffi::export(name = "device_kind_label")]
    pub fn device_kind_label(kind: CoreDeviceKind) -> String {
        super::device_kind_label(kind)
    }

    #[uniffi::export(name = "android_model_name")]
    pub fn android_model_name(manufacturer: String, model: String) -> String {
        super::android_model_name(&manufacturer, &model)
    }

    #[uniffi::export(name = "device_label_parse")]
    pub fn device_label_parse(raw: String) -> Option<CoreDeviceLabel> {
        super::device_label_parse(&raw)
    }

    #[uniffi::export(name = "device_label_ensure")]
    pub fn device_label_ensure(
        labels: Vec<CoreDeviceLabelObject>,
        device_id: Uuid,
        kind: CoreDeviceKind,
        platform: String,
    ) -> Result<Option<CoreDeviceLabelObject>, CoreError> {
        super::device_label_ensure(&labels, device_id, kind, &platform)
    }

    #[uniffi::export(name = "device_label_rename")]
    pub fn device_label_rename(
        labels: Vec<CoreDeviceLabelObject>,
        device_id: Uuid,
        name: String,
    ) -> Result<CoreDeviceLabelObject, CoreError> {
        super::device_label_rename(&labels, device_id, &name)
    }

    #[uniffi::export(name = "device_entries")]
    pub fn device_entries(
        roster: Vec<Uuid>,
        labels: Vec<CoreDeviceLabelObject>,
        current: Uuid,
    ) -> Vec<CoreDeviceEntry> {
        super::device_entries(&roster, &labels, current)
    }

    #[uniffi::export(name = "stale_device_labels")]
    pub fn stale_device_labels(
        roster: Vec<Uuid>,
        labels: Vec<CoreDeviceLabelObject>,
    ) -> Vec<String> {
        super::stale_device_labels(&roster, &labels)
    }
}
