#![no_main]

use kerosene_contracts::{AdmissionRequestV1, CanonicalSignable};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(value) = serde_json::from_slice::<AdmissionRequestV1>(data) {
        std::hint::black_box(value.signing_bytes());
    }
});
