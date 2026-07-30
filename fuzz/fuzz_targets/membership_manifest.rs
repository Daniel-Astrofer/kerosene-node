#![no_main]

use kerosene_contracts::{canonical_hash, CanonicalSignable, MembershipManifestV1};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(value) = serde_json::from_slice::<MembershipManifestV1>(data) {
        std::hint::black_box(value.signing_bytes());
        std::hint::black_box(canonical_hash(&value));
    }
});
