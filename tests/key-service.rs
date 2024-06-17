use base64::{engine::general_purpose, Engine};
use key_share_service::{
    get_public_key, threshold_decrypt, DecryptionResponse, PublicKeyResponse, SharedState,
    THRESHOLD,
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
    let pub_key_set = &sec_key_share.public_keys();

    let rocket = rocket::build()
        .manage(RwLock::new(SharedState {
            pub_key_set: pub_key_set.to_owned(),
            sec_key_share,
        }))
        .mount("/", routes![get_public_key, threshold_decrypt]);

    let client = Client::tracked(rocket).await?;

    // Encrypt a message
    let plaintext = "Hello, world!";

    let pub_key = pub_key_set.public_key();
    let ciphertext: Ciphertext = pub_key.encrypt(plaintext.as_bytes());

    let ciphertext_str = serde_json::to_string(&ciphertext)?;
    let ciphertext_base64 = general_purpose::STANDARD.encode(ciphertext_str.as_bytes());

    // Decrypt the message
    let decrypt_response = client
        .post("/decrypt")
        .header(ContentType::JSON)
        .body(json!({ "ciphertext": ciphertext_base64 }).to_string())
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
    let ciphertext_bytes = general_purpose::STANDARD.decode(&ciphertext_base64)?;
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
