//! Public token-provenance read surface (§7.5).

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::{json, Map, Value};

use crate::error::ApiError;
use crate::hexutil::{decode_hex_exact, encode_hex};
use crate::kernel::kernel_v1::{GetTokenProvenanceRequest, TokenProvenance};
use crate::kernel::KernelHandle;

/// Returns captured issuance terms for an asset when the node holds them.
///
/// This Class B surface is public and is never capability- or feature-gated (§6.4/§4.6).
pub async fn get_token_provenance(
    State(kernel): State<KernelHandle>,
    Path(asset_id_hex): Path<String>,
) -> Result<Response, ApiError> {
    let asset_id = decode_hex_exact(&asset_id_hex, 32)
        .map_err(|e| ApiError::malformed(format!("asset_id: {e}")))?;
    let provenance = kernel
        .get_token_provenance(GetTokenProvenanceRequest {
            asset_id: asset_id.clone(),
        })
        .await?;
    let body = token_provenance_to_json(&asset_id, &provenance)?;
    Ok((StatusCode::OK, Json(body)).into_response())
}

fn token_provenance_to_json(
    asset_id: &[u8],
    provenance: &TokenProvenance,
) -> Result<Value, ApiError> {
    match provenance.issuance_version {
        1 => {
            if !provenance.cap_total.is_empty() || !provenance.terms_salt.is_empty() {
                return Err(ApiError::internal(
                    "kernel returned v1 token provenance with v2-only fields",
                ));
            }
        }
        2 => {
            if provenance.cap_total.is_empty() || provenance.terms_salt.is_empty() {
                return Err(ApiError::internal(
                    "kernel returned v2 token provenance without all v2 fields",
                ));
            }
        }
        version => {
            return Err(ApiError::internal(format!(
                "kernel returned unsupported token issuance_version {version}"
            )));
        }
    }

    let mut body = Map::new();
    body.insert("asset_id".to_owned(), json!(encode_hex(asset_id)));
    body.insert(
        "issuance_version".to_owned(),
        json!(provenance.issuance_version),
    );
    body.insert(
        "creator_pubkey".to_owned(),
        json!(require_hex32(
            "token provenance creator_pubkey",
            &provenance.creator_pubkey,
        )?),
    );
    body.insert("name".to_owned(), json!(encode_hex(&provenance.name)));
    let decimals = u8::try_from(provenance.decimals).map_err(|_| {
        ApiError::internal(format!(
            "kernel returned token provenance decimals {} exceeding the §7.5 u8 range",
            provenance.decimals
        ))
    })?;
    body.insert("decimals".to_owned(), json!(decimals));

    if provenance.issuance_version == 2 {
        let cap_total = provenance.cap_total.parse::<u128>().map_err(|_| {
            ApiError::internal(format!(
                "kernel returned token provenance cap_total {:?} that is not a decimal u128",
                provenance.cap_total
            ))
        })?;
        body.insert("cap_total".to_owned(), json!(cap_total.to_string()));
        body.insert(
            "terms_salt".to_owned(),
            json!(require_hex32(
                "token provenance terms_salt",
                &provenance.terms_salt,
            )?),
        );
    }

    Ok(Value::Object(body))
}

fn require_hex32(field: &str, bytes: &[u8]) -> Result<String, ApiError> {
    if bytes.len() != 32 {
        return Err(ApiError::internal(format!(
            "kernel returned {field} with invalid width: expected 32 bytes, got {}",
            bytes.len()
        )));
    }
    Ok(encode_hex(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_v1() -> TokenProvenance {
        TokenProvenance {
            issuance_version: 1,
            creator_pubkey: vec![0x11; 32],
            name: b"MyToken".to_vec(),
            decimals: 8,
            cap_total: String::new(),
            terms_salt: Vec::new(),
        }
    }

    #[test]
    fn token_provenance_rejects_unknown_issuance_version() {
        let mut provenance = valid_v1();
        provenance.issuance_version = 3;
        assert!(token_provenance_to_json(&[0xaa; 32], &provenance).is_err());
    }

    #[test]
    fn token_provenance_rejects_decimals_exceeding_u8() {
        let mut provenance = valid_v1();
        provenance.decimals = 256; // §7.5 decimals is u8; a wider kernel value must fail closed
        assert!(token_provenance_to_json(&[0xaa; 32], &provenance).is_err());
    }

    #[test]
    fn token_provenance_rejects_non_u128_cap_total() {
        let mut provenance = valid_v1();
        provenance.issuance_version = 2;
        provenance.cap_total = "not-a-number".to_owned();
        provenance.terms_salt = vec![0x22; 32];
        assert!(token_provenance_to_json(&[0xaa; 32], &provenance).is_err());
    }

    #[test]
    fn token_provenance_rejects_v1_with_v2_fields() {
        let mut provenance = valid_v1();
        provenance.cap_total = "1".to_owned();
        assert!(token_provenance_to_json(&[0xaa; 32], &provenance).is_err());
    }

    #[test]
    fn token_provenance_rejects_incomplete_v2_fields() {
        let mut provenance = valid_v1();
        provenance.issuance_version = 2;
        provenance.cap_total = "1".to_owned();
        assert!(token_provenance_to_json(&[0xaa; 32], &provenance).is_err());
    }

    #[test]
    fn token_provenance_rejects_invalid_creator_pubkey_width() {
        let mut provenance = valid_v1();
        provenance.creator_pubkey = vec![0x11; 31];
        assert!(token_provenance_to_json(&[0xaa; 32], &provenance).is_err());
    }

    #[test]
    fn token_provenance_rejects_invalid_terms_salt_width() {
        let mut provenance = valid_v1();
        provenance.issuance_version = 2;
        provenance.cap_total = "1".to_owned();
        provenance.terms_salt = vec![0x22; 31];
        assert!(token_provenance_to_json(&[0xaa; 32], &provenance).is_err());
    }
}
