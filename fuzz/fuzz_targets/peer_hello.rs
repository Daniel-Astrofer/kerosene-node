#![no_main]

use kerosene_contracts::{CanonicalSignable, PeerHelloV1};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(value) = serde_json::from_slice::<PeerHelloV1>(data) {
        std::hint::black_box(value.signing_bytes());
    }
});
