//! Offline verification of signed run receipts (§7.1).
//!
//! A receipt is self-contained evidence that a check ran, verifiable without a
//! network call or a Vetro account — the property that makes it durable audit
//! evidence independent of dashboard retention. The backend signs the receipt's
//! `payload` with Ed25519 over the SHA-256 digest of its **canonical JSON**
//! (recursively sorted object keys, compact) — scheme `ed25519-sha256`
//! (`services/ci-receipt.ts` + `utils/signing.ts`). This module reproduces that
//! canonicalization and checks the signature against a trusted public key.
//!
//! Canonicalization note: `serde_json`'s object map is sorted (BTreeMap-backed)
//! and `to_string` is compact, so re-serializing the parsed `payload` yields the
//! same bytes the backend hashed. We also recompute the SHA-256 and compare it
//! to the receipt's `sha256`, so a canonicalization mismatch surfaces as a clear
//! error rather than a confusing signature failure.

use base64::Engine;
use ed25519_dalek::pkcs8::DecodePublicKey;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};

use crate::api::Receipt;

/// The signature scheme this verifier understands.
const SCHEME: &str = "ed25519-sha256";

/// Why a receipt failed to verify. Each maps to a clear, actionable message.
#[derive(Debug)]
pub enum VerifyError {
    /// The receipt's `scheme` isn't one we implement.
    UnsupportedScheme(String),
    /// No public key available for the receipt's `public_key_id` (and no
    /// `--public-key` override given).
    UnknownKey(String),
    /// The supplied/bundled public key PEM couldn't be parsed.
    BadPublicKey(String),
    /// The `signature` field isn't valid base64 / wrong length.
    BadSignature(String),
    /// The recomputed SHA-256 of the canonical payload didn't match the
    /// receipt's `sha256` — the payload was altered or canonicalization drifted.
    DigestMismatch { expected: String, actual: String },
    /// The Ed25519 signature did not verify against the digest + key.
    SignatureInvalid,
}

impl std::fmt::Display for VerifyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VerifyError::UnsupportedScheme(s) => {
                write!(
                    f,
                    "unsupported signature scheme '{s}' (expected '{SCHEME}')"
                )
            }
            VerifyError::UnknownKey(id) => write!(
                f,
                "no trusted public key for key id '{id}'. Pass --public-key <PEM> \
                 (fetch it from GET /api/v1/meta/export-signing-key or your admin)."
            ),
            VerifyError::BadPublicKey(e) => write!(f, "invalid public key: {e}"),
            VerifyError::BadSignature(e) => write!(f, "malformed signature: {e}"),
            VerifyError::DigestMismatch { expected, actual } => write!(
                f,
                "payload digest mismatch (receipt says {expected}, computed {actual}) — \
                 the receipt payload was altered"
            ),
            VerifyError::SignatureInvalid => {
                write!(f, "signature does not verify — receipt is not authentic")
            }
        }
    }
}

/// The canonical JSON bytes of a receipt payload: the same recursively
/// sorted-keys, compact serialization the backend signs. `serde_json` sorts
/// object keys (BTreeMap) and `to_string` is compact, so this matches
/// `canonicalJson` in `ci-receipt.ts` byte-for-byte.
pub fn canonicalize(payload: &serde_json::Value) -> String {
    // to_string on a Value already produces sorted-key compact JSON.
    serde_json::to_string(payload).unwrap_or_default()
}

/// Hex-encoded lowercase SHA-256 of `bytes`.
fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut s = String::with_capacity(digest.len() * 2);
    for b in digest {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// Verifies `receipt` against `public_key_pem`. Checks the scheme, recomputes
/// the payload digest (guards against a tampered payload with a clearer error
/// than a bare signature failure), then verifies the Ed25519 signature over that
/// digest — the same message the backend signed.
pub fn verify_with_key(receipt: &Receipt, public_key_pem: &str) -> Result<(), VerifyError> {
    if receipt.scheme != SCHEME {
        return Err(VerifyError::UnsupportedScheme(receipt.scheme.clone()));
    }

    let canonical = canonicalize(&receipt.payload);
    let digest = Sha256::digest(canonical.as_bytes());
    let actual_hex = sha256_hex(canonical.as_bytes());
    if !receipt.sha256.is_empty() && actual_hex != receipt.sha256.to_lowercase() {
        return Err(VerifyError::DigestMismatch {
            expected: receipt.sha256.clone(),
            actual: actual_hex,
        });
    }

    let key = VerifyingKey::from_public_key_pem(public_key_pem)
        .map_err(|e| VerifyError::BadPublicKey(e.to_string()))?;

    let sig_bytes = base64::engine::general_purpose::STANDARD
        .decode(receipt.signature.trim())
        .map_err(|e| VerifyError::BadSignature(e.to_string()))?;
    let sig =
        Signature::from_slice(&sig_bytes).map_err(|e| VerifyError::BadSignature(e.to_string()))?;

    // The backend signs the 32-byte SHA-256 digest as the message (Ed25519ph is
    // NOT used — it's plain Ed25519 over the digest bytes; see utils/signing.ts).
    key.verify(&digest, &sig)
        .map_err(|_| VerifyError::SignatureInvalid)
}

/// Resolves the public key for a receipt and verifies it. `override_pem` (from
/// `--public-key`) wins; otherwise a bundled key matching `public_key_id` is
/// used (see [`crate::pubkeys`]).
pub fn verify(receipt: &Receipt, override_pem: Option<&str>) -> Result<(), VerifyError> {
    let pem = match override_pem {
        Some(p) => p.to_string(),
        None => crate::pubkeys::key_for(&receipt.public_key_id)
            .ok_or_else(|| VerifyError::UnknownKey(receipt.public_key_id.clone()))?
            .to_string(),
    };
    verify_with_key(receipt, &pem)
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;
    use ed25519_dalek::pkcs8::EncodePublicKey;
    use ed25519_dalek::{Signer, SigningKey};

    /// A payload whose keys are deliberately out of order, to prove
    /// canonicalization sorts them.
    fn sample_payload() -> serde_json::Value {
        serde_json::json!({
            "version": 1,
            "kind": "vetro-ci-receipt",
            "workspace_id": "ws_1",
            "exit_code": 1,
            "summary": { "total": 2, "blocked": 1, "allowed": 1 },
            "queries": [{ "line": 1, "status": "BLOCKED" }],
            "dialect": "postgres",
            "file_name": "m.sql",
            "provenance": null,
            "signed_at": "2026-07-10T00:00:00Z"
        })
    }

    #[test]
    fn canonicalize_sorts_keys_recursively_and_is_compact() {
        let c = canonicalize(&sample_payload());
        // Top-level keys sorted: dialect < exit_code < file_name < kind < ...
        assert!(c.starts_with(
            r#"{"dialect":"postgres","exit_code":1,"file_name":"m.sql","kind":"vetro-ci-receipt""#
        ));
        // Nested object sorted too: allowed < blocked < total.
        assert!(c.contains(r#""summary":{"allowed":1,"blocked":1,"total":2}"#));
        // Compact — no spaces after colons/commas.
        assert!(!c.contains(": "));
    }

    /// Signs `sample_payload` with a fresh keypair the way the backend does, and
    /// returns (receipt, public_key_pem).
    fn signed_receipt() -> (Receipt, String) {
        let payload = sample_payload();
        let canonical = canonicalize(&payload);
        let digest = Sha256::digest(canonical.as_bytes());

        // Deterministic test key (32 zero bytes is fine for a unit test).
        let signing = SigningKey::from_bytes(&[7u8; 32]);
        let sig = signing.sign(&digest);
        let pem = signing
            .verifying_key()
            .to_public_key_pem(Default::default())
            .unwrap();

        let receipt = Receipt {
            payload,
            scheme: SCHEME.to_string(),
            signature: base64::engine::general_purpose::STANDARD.encode(sig.to_bytes()),
            public_key_id: "test".to_string(),
            sha256: super::sha256_hex(canonical.as_bytes()),
        };
        (receipt, pem)
    }

    #[test]
    fn verify_accepts_a_valid_receipt() {
        let (receipt, pem) = signed_receipt();
        assert!(verify_with_key(&receipt, &pem).is_ok());
    }

    #[test]
    fn verify_rejects_a_tampered_payload() {
        let (mut receipt, pem) = signed_receipt();
        // Flip a value in the payload — digest no longer matches sha256, and the
        // signature wouldn't verify either.
        receipt.payload["exit_code"] = serde_json::json!(0);
        match verify_with_key(&receipt, &pem) {
            Err(VerifyError::DigestMismatch { .. }) => {}
            other => panic!("expected DigestMismatch, got {other:?}"),
        }
    }

    #[test]
    fn verify_rejects_a_bad_signature() {
        let (mut receipt, pem) = signed_receipt();
        // Keep the payload (so digest matches) but corrupt the signature.
        let mut raw = base64::engine::general_purpose::STANDARD
            .decode(receipt.signature.as_bytes())
            .unwrap();
        raw[0] ^= 0xff;
        receipt.signature = base64::engine::general_purpose::STANDARD.encode(&raw);
        match verify_with_key(&receipt, &pem) {
            Err(VerifyError::SignatureInvalid) => {}
            other => panic!("expected SignatureInvalid, got {other:?}"),
        }
    }

    #[test]
    fn verify_rejects_unknown_scheme() {
        let (mut receipt, pem) = signed_receipt();
        receipt.scheme = "hmac-sha256".to_string();
        assert!(matches!(
            verify_with_key(&receipt, &pem),
            Err(VerifyError::UnsupportedScheme(_))
        ));
    }
}
