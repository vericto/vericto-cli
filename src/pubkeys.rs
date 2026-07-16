//! Bundled Vericto public keys for offline receipt verification (§7.1).
//!
//! Receipts are signed by a backend private key; `vericto verify-receipt` checks
//! them against the matching **public** key, which is safe to ship inside the
//! binary. Keys are keyed by the `public_key_id` a receipt carries, so more than
//! one can be bundled at once — this is what lets verification survive a key
//! rotation: when the signing key rotates, add the new public key here (keeping
//! the old one) and ship it, and both old and new receipts keep verifying. That
//! is deliberately different from "one key, rotated via a major-version bump",
//! which would strand receipts signed by the previous key.
//!
//! Until an official key is published, this registry is empty and verification
//! requires `--public-key <PEM>` (fetch it from
//! `GET /api/v1/meta/export-signing-key`). Populate [`BUNDLED_KEYS`] with the
//! published PEM(s) to make verification work with zero flags.

/// (key_id, PEM) pairs trusted for verification. Add the official Vericto key(s)
/// here — each entry is a `-----BEGIN PUBLIC KEY-----` PEM string. Multiple
/// entries coexist so a rotation doesn't invalidate older receipts.
///
/// Example once published:
/// ```ignore
/// pub const BUNDLED_KEYS: &[(&str, &str)] = &[
///     ("2026-ed25519", include_str!("../keys/vericto-2026-ed25519.pem")),
/// ];
/// ```
pub const BUNDLED_KEYS: &[(&str, &str)] = &[
    // No official key bundled yet — see module docs. Verification falls back to
    // the --public-key flag until an entry is added here.
];

/// Returns the bundled PEM for `key_id`, if one is trusted.
pub fn key_for(key_id: &str) -> Option<&'static str> {
    BUNDLED_KEYS
        .iter()
        .find(|(id, _)| *id == key_id)
        .map(|(_, pem)| *pem)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_key_id_returns_none() {
        assert!(key_for("does-not-exist").is_none());
    }

    #[test]
    fn bundled_keys_are_wellformed_pem() {
        // Every bundled key must actually parse, so a bad paste is caught in CI
        // rather than at a customer's `verify-receipt`.
        use ed25519_dalek::pkcs8::DecodePublicKey;
        for (id, pem) in BUNDLED_KEYS {
            ed25519_dalek::VerifyingKey::from_public_key_pem(pem)
                .unwrap_or_else(|e| panic!("bundled key '{id}' is not valid PEM: {e}"));
        }
    }
}
