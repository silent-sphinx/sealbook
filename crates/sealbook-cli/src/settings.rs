//! `settings`: which features the account shows.
//!
//! The rules are core's: a flag no build knows survives a save, a missing flag
//! is on, and the last feature left on cannot be switched off. The display
//! preferences (`contactMode`, `accent`) are the web's and Android's to set;
//! they are shown here and written back as stored.

use anyhow::{bail, Context, Result};
use clap::{Subcommand, ValueEnum};
use sealbook_client::{
    can_disable_feature, settings_with_feature, settings_write, CoreAccountSettings, SealbookClient,
};

#[derive(Clone, Copy, ValueEnum)]
pub enum Switch {
    On,
    Off,
}

#[derive(Subcommand)]
pub enum SettingsCommand {
    /// Show which features are on, and the display preferences.
    Show,
    /// Turn a feature on or off: contacts, calendar, notes, bookmarks or tasks.
    ///
    /// Switching one off hides it in the web and Android apps; its data stays.
    /// The last feature left on cannot be switched off.
    Feature { name: String, state: Switch },
}

pub fn show_lines(settings: &CoreAccountSettings) -> Vec<String> {
    let mut lines: Vec<String> = settings
        .features
        .iter()
        .map(|flag| {
            format!(
                "{:<10} {}",
                flag.key,
                if flag.enabled { "on" } else { "off" }
            )
        })
        .collect();
    lines.push(format!("contact mode: {}", settings.contact_mode));
    lines.push(format!("accent: {}", settings.accent));
    if !settings.readable {
        lines.push(
            "(these settings come from a newer app; they can be read but not changed)".into(),
        );
    }
    lines
}

/// The settings with one feature changed, or the reason it cannot be.
pub fn changed(
    settings: &CoreAccountSettings,
    feature: &str,
    enabled: bool,
) -> Result<CoreAccountSettings> {
    let name = feature.trim().to_lowercase();
    if !settings.features.iter().any(|flag| flag.key == name) {
        let known: Vec<&str> = settings.features.iter().map(|f| f.key.as_str()).collect();
        bail!("unknown feature {feature}: use one of {}", known.join(", "));
    }
    if settings.is_enabled(&name) == enabled {
        return Ok(settings.clone());
    }
    if !enabled && !can_disable_feature(settings, &name) {
        bail!("{name} is the only feature left on, and one must stay on");
    }
    Ok(settings_with_feature(settings, &name, enabled))
}

pub async fn run(client: &mut SealbookClient, command: SettingsCommand) -> Result<()> {
    let settings = client.account_settings().await.context("settings")?;
    match command {
        SettingsCommand::Show => {
            for line in show_lines(&settings) {
                println!("{line}");
            }
        }
        SettingsCommand::Feature { name, state } => {
            let enabled = matches!(state, Switch::On);
            let next = changed(&settings, &name, enabled)?;
            if next == settings {
                println!(
                    "{} is already {}",
                    name.trim().to_lowercase(),
                    if enabled { "on" } else { "off" }
                );
                return Ok(());
            }
            // The stored object is the base, so flags and keys this build does
            // not know come back as they were found.
            let payload = settings_write(&next.draft())?;
            client
                .put_account_settings(&payload)
                .await
                .context("write settings")?;
            println!(
                "{} is now {}",
                name.trim().to_lowercase(),
                if enabled { "on" } else { "off" }
            );
        }
    }
    Ok(())
}

/// A warning for a command whose feature is off, since the apps hide it.
pub fn disabled_note(settings: &CoreAccountSettings, feature: &str) -> Option<String> {
    (!settings.is_enabled(feature)).then(|| {
        format!("note: {feature} is switched off in settings, so the apps hide what this writes")
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use sealbook_client::settings_parse;

    fn parsed(raw: &str) -> CoreAccountSettings {
        settings_parse(raw)
    }

    #[test]
    fn a_new_account_has_everything_on() {
        let lines = show_lines(&parsed(""));
        assert!(lines.contains(&"tasks      on".to_string()), "{lines:?}");
        assert!(lines.contains(&"accent: blue".to_string()));
    }

    #[test]
    fn switching_off_keeps_flags_from_a_newer_build_and_the_preferences() {
        let raw = r#"{"@type":"AccountSettings","version":"1.0","features":{"tasks":true,"vault":false,"future":"x"},"contactMode":"detailed","accent":"rose","extra":1}"#;
        let settings = parsed(raw);
        let next = changed(&settings, "Tasks", false).unwrap();
        let written: serde_json::Value =
            serde_json::from_str(&settings_write(&next.draft()).unwrap()).unwrap();
        assert_eq!(written["features"]["tasks"], false);
        assert_eq!(written["features"]["vault"], false);
        assert_eq!(written["features"]["future"], "x");
        assert_eq!(written["contactMode"], "detailed");
        assert_eq!(written["accent"], "rose");
        assert_eq!(written["extra"], 1);
    }

    #[test]
    fn the_last_feature_on_cannot_be_switched_off() {
        let raw = r#"{"@type":"AccountSettings","version":"1.0","features":{"contacts":false,"calendar":false,"notes":false,"bookmarks":false,"tasks":true}}"#;
        let err = changed(&parsed(raw), "tasks", false)
            .unwrap_err()
            .to_string();
        assert!(err.contains("only feature left"), "{err}");
    }

    #[test]
    fn an_unknown_feature_is_refused_with_the_names() {
        let err = changed(&parsed(""), "mail", true).unwrap_err().to_string();
        assert!(
            err.contains("contacts, calendar, notes, bookmarks, tasks"),
            "{err}"
        );
    }

    #[test]
    fn a_disabled_feature_is_noted_not_refused() {
        let raw = r#"{"@type":"AccountSettings","version":"1.0","features":{"tasks":false}}"#;
        assert!(disabled_note(&parsed(raw), "tasks").is_some());
        assert!(disabled_note(&parsed(raw), "notes").is_none());
    }
}
