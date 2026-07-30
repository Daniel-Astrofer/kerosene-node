// ---------------------------------------------------------------------------
// Shared Test Helpers
//
// Provides consistent key generation and QC signing for all test modules.
// ---------------------------------------------------------------------------

use crate::certificate::QuorumCertificate;

/// Generate a real Ed25519 keypair for testing.
pub fn test_keypair() -> (ed25519_dalek::SigningKey, ed25519_dalek::VerifyingKey) {
    let signing_key = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng());
    let verifying_key = signing_key.verifying_key();
    (signing_key, verifying_key)
}

/// Sign a message with the given signing key and return the hex-encoded signature.
pub fn sign_message(signing_key: &ed25519_dalek::SigningKey, message: &[u8]) -> String {
    use ed25519_dalek::Signer;
    let signature = signing_key.sign(message);
    hex::encode(signature.to_bytes())
}

/// Create a QuorumCertificate whose embedded Ed25519 signature is valid against
/// the QC's own `signing_message()`. Returns the QC and the hex-encoded public key.
pub fn make_signed_qc(
    cluster_id: &str,
    epoch: u64,
    view: u64,
    sequence: u64,
    command_hash: &str,
    previous_state_root: &str,
    resulting_state_root: &str,
    node_id: &str,
) -> (QuorumCertificate, String) {
    let (sk, vk) = test_keypair();
    let pk_hex = hex::encode(vk.to_bytes());

    // First build a stub QC to get the signing message
    let stub = QuorumCertificate::single_node(
        cluster_id,
        epoch,
        view,
        sequence,
        command_hash,
        previous_state_root,
        resulting_state_root,
        node_id,
        "",
        &pk_hex,
    );

    let msg = stub.signing_message();
    let sig_hex = sign_message(&sk, &msg);

    // Return the real QC with a valid signature
    let qc = QuorumCertificate::single_node(
        cluster_id,
        epoch,
        view,
        sequence,
        command_hash,
        previous_state_root,
        resulting_state_root,
        node_id,
        &sig_hex,
        &pk_hex,
    );
    (qc, pk_hex)
}
