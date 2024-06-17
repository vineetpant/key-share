#[macro_use]
extern crate rocket;

use base64::{engine::general_purpose, Engine};
use rocket::{
    http::Status,
    response,
    serde::{json::Json, Deserialize, Serialize},
    Request, Response, State,
};
use std::collections::HashMap;
use std::sync::RwLock;
use threshold_crypto::{Ciphertext, DecryptionShare, PublicKeySet, SecretKeySet, SecretKeyShare};

pub const THRESHOLD: usize = 2;
pub struct SharedState {
    pub pub_key_set: PublicKeySet,
    pub sec_key_share: SecretKeySet,
}

#[derive(Serialize, Deserialize)]
pub struct DecryptionRequest {
    pub ciphertext: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DecryptionResponse {
    pub decryption_shares: HashMap<usize, DecryptionShare>,
}

#[derive(Serialize, Deserialize)]
pub struct PublicKeyResponse {
    pub pub_key_set: String,
}

#[derive(Debug)]
pub enum ServiceError {
    ServiceBusy,
    InvalidCiphertextFormat,
    DecryptionFailed,
    InvalidBase64,
    PublicKeyReadError,
    UnknownError,
}

impl std::fmt::Display for ServiceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match *self {
            ServiceError::InvalidCiphertextFormat => write!(f, "Invalid ciphertext format"),
            ServiceError::DecryptionFailed => write!(f, "Decryption failed"),
            ServiceError::InvalidBase64 => write!(f, "Invalid base64 encoding"),
            ServiceError::ServiceBusy => write!(f, "Service is busy"),
            ServiceError::PublicKeyReadError => write!(f, "Unable to read public key"),
            ServiceError::UnknownError => write!(f, "Unknown Error"),
        }
    }
}

impl std::error::Error for ServiceError {}

impl<'r> response::Responder<'r, 'static> for ServiceError {
    fn respond_to(self, _: &'r Request<'_>) -> response::Result<'static> {
        let (status, message) = match self {
            ServiceError::InvalidCiphertextFormat => (Status::BadRequest, self.to_string()),
            ServiceError::DecryptionFailed => (Status::InternalServerError, self.to_string()),
            ServiceError::InvalidBase64 => (Status::BadRequest, self.to_string()),
            ServiceError::ServiceBusy => (Status::InternalServerError, self.to_string()),
            ServiceError::PublicKeyReadError => (Status::InternalServerError, self.to_string()),
            ServiceError::UnknownError => (Status::InternalServerError, self.to_string()),
        };

        Response::build()
            .status(status)
            .header(rocket::http::ContentType::JSON)
            .sized_body(message.len(), std::io::Cursor::new(message))
            .ok()
    }
}

/// Fetches the public key set.
///
/// This endpoint returns the public key set used for encryption.
///
/// # Returns
///
/// * `PublicKeyResponse` - The response containing the public key set.
///
/// # Errors
///
/// This function will return an error if the public key set cannot be fetched.
#[get("/public_key")]
pub fn get_public_key(
    state: &State<RwLock<SharedState>>,
) -> Result<Json<PublicKeyResponse>, ServiceError> {
    let state = state.read().map_err(|_| ServiceError::ServiceBusy)?;
    let pub_key_set =
        serde_json::to_string(&state.pub_key_set).map_err(|_| ServiceError::PublicKeyReadError)?;
    Ok(Json(PublicKeyResponse { pub_key_set }))
}

/// Decrypts the given ciphertext using the secret key shares.
///
/// # Arguments
///
/// * `request` - A JSON body containing the ciphertext to be decrypted.
/// * `state` - The shared state containing the secret key set.
///
/// # Returns
///
/// * `DecryptionResponse` - The response containing the decryption shares.
///
/// # Errors
///
/// This function will return an error if decryption fails.
#[post("/decrypt", data = "<request>")]
pub fn threshold_decrypt(
    request: Json<DecryptionRequest>,
    state: &State<RwLock<SharedState>>,
) -> Result<Json<DecryptionResponse>, ServiceError> {
    let state = state.read().map_err(|_| ServiceError::ServiceBusy)?;
    let ciphertext_bytes = general_purpose::STANDARD
        .decode(&request.ciphertext)
        .map_err(|_| ServiceError::InvalidBase64)?;
    let ciphertext_str =
        String::from_utf8(ciphertext_bytes).map_err(|_| ServiceError::InvalidCiphertextFormat)?;
    let ciphertext: Ciphertext =
        serde_json::from_str(&ciphertext_str).map_err(|_| ServiceError::InvalidCiphertextFormat)?;

    let mut shares = HashMap::new();
    for i in 0..=THRESHOLD {
        // Collecting t+1 shares to perform decryption
        // In real world solution we will request servers to perform decryption and return the result with shares
        let sec_key_share: SecretKeyShare = state.sec_key_share.secret_key_share(i);
        let decryption_share: DecryptionShare = sec_key_share
            .decrypt_share(&ciphertext)
            .ok_or(ServiceError::DecryptionFailed)?;
        shares.insert(i, decryption_share);
    }

    Ok(Json(DecryptionResponse {
        decryption_shares: shares,
    }))
}
