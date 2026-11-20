//! Loaded only on the screens that set a password. The check itself is core's
//! `password_strength`; this crate exists so the dictionaries ship in a module
//! of their own.

use wasm_bindgen::prelude::*;

/// Scores a password the way every client does. The result is core's
/// `PasswordStrength`.
#[wasm_bindgen]
pub fn password_strength(password: &str, username: &str) -> Result<JsValue, JsError> {
    let strength = sealbook_core::strength::password_strength(password, username);
    serde_wasm_bindgen::to_value(&strength).map_err(|e| JsError::new(&e.to_string()))
}
