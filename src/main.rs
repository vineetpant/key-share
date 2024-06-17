#[macro_use]
extern crate rocket;

use key_share_service::{get_public_key, threshold_decrypt, SharedState, THRESHOLD};
use rocket::routes;
use std::sync::RwLock;
use threshold_crypto::SecretKeySet;

#[launch]
fn rocket() -> _ {
    // Generate keys
    let sec_key_set = SecretKeySet::random(THRESHOLD, &mut rand::thread_rng());
    let pub_key_set = sec_key_set.public_keys();

    // Ideally we would be storing the secret key shares to different servers
    let state = SharedState {
        pub_key_set,
        sec_key_share: sec_key_set,
    };

    rocket::build()
        .manage(RwLock::new(state))
        .mount("/", routes![get_public_key, threshold_decrypt])
}
