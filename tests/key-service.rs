use base64::{engine::general_purpose, Engine};
use key_share_service::{
    encrypt, get_public_key, threshold_decrypt, DecryptionResponse, EncryptionResponse,
    PublicKeyResponse, SharedState, THRESHOLD,
};
use rocket::{
    http::{ContentType, Status},
    local::asynchronous::Client,
    routes,
    serde::json::json,
};
use std::collections::HashMap;
use std::sync::RwLock;
use threshold_crypto::{Ciphertext, PublicKeySet, SecretKeySet};

#[rocket::async_test]
async fn test_get_public_key() -> Result<(), Box<dyn std::error::Error>> {
    let sec_key_share = SecretKeySet::random(THRESHOLD, &mut rand::thread_rng());
    let pub_key_set = sec_key_share.public_keys();

    let rocket = rocket::build()
        .manage(RwLock::new(SharedState {
            pub_key_set,
            sec_key_share,
        }))
        .mount("/", routes![get_public_key]);

    let client = Client::tracked(rocket).await?;
    let response = client.get("/public_key").dispatch().await;

    assert_eq!(response.status(), Status::Ok);
    let response_json: PublicKeyResponse = response
        .into_json()
        .await
        .ok_or_else(|| "Invalid PublicKey response")?;
    assert!(!response_json.pub_key_set.is_empty());
    Ok(())
}

#[rocket::async_test]
async fn test_encrypt_decrypt() -> Result<(), Box<dyn std::error::Error>> {
    let threshold = 2;
    let sec_key_share = SecretKeySet::random(threshold, &mut rand::thread_rng());
    let pub_key_set = sec_key_share.public_keys();

    let rocket = rocket::build()
        .manage(RwLock::new(SharedState {
            pub_key_set,
            sec_key_share,
        }))
        .mount("/", routes![get_public_key, encrypt, threshold_decrypt]);

    let client = Client::tracked(rocket).await?;

    // Encrypt a message
    let plaintext = "Hello, world!";
    let encrypt_response = client
        .post("/encrypt")
        .header(ContentType::JSON)
        .body(json!({ "plaintext": plaintext }).to_string())
        .dispatch()
        .await;

    assert_eq!(encrypt_response.status(), Status::Ok);
    let encrypt_response_json: EncryptionResponse = encrypt_response
        .into_json()
        .await
        .ok_or_else(|| "Invalid Encryption response")?;
    assert!(!encrypt_response_json.ciphertext.is_empty());

    // Decrypt the message
    let decrypt_response = client
        .post("/decrypt")
        .header(ContentType::JSON)
        .body(json!({ "ciphertext": encrypt_response_json.ciphertext }).to_string())
        .dispatch()
        .await;

    assert_eq!(decrypt_response.status(), Status::Ok);
    let decrypt_response_json: DecryptionResponse = decrypt_response
        .into_json()
        .await
        .ok_or_else(|| "Invalid Decryption response")?;
    assert!(!decrypt_response_json.decryption_shares.is_empty());

    // Combine the decryption shares to retrieve the plaintext
    let pub_key_resp: PublicKeyResponse = client
        .get("/public_key")
        .dispatch()
        .await
        .into_json()
        .await
        .ok_or_else(|| "Invalid PublicKey response")?;

    let pub_key_set: PublicKeySet = serde_json::from_str(&pub_key_resp.pub_key_set)?;
    let ciphertext_bytes = general_purpose::STANDARD.decode(&encrypt_response_json.ciphertext)?;
    let ciphertext_str = String::from_utf8(ciphertext_bytes)?;
    let ciphertext: Ciphertext = serde_json::from_str(&ciphertext_str)?;

    let mut shares = HashMap::new();
    for (i, share) in decrypt_response_json.decryption_shares {
        shares.insert(i, share);
    }

    let plaintext_bytes = pub_key_set
        .decrypt(&shares, &ciphertext)
        .map_err(|_| "decryption failed")?;
    let plaintext_result = String::from_utf8(plaintext_bytes)?;

    assert_eq!(plaintext_result, plaintext);
    Ok(())
}
