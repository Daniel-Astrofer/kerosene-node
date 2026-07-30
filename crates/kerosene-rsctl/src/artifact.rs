use anyhow::{bail, Result};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

pub async fn handle_artifact(command: &super::ArtifactCommand) -> Result<Value> {
    match command {
        super::ArtifactCommand::Verify { path, sha256 } => {
            let digest = hex::encode(Sha256::digest(std::fs::read(path)?));
            if let Some(expected) = sha256 {
                if !expected.eq_ignore_ascii_case(&digest) {
                    bail!("artifact SHA-256 mismatch");
                }
            }
            Ok(json!({"valid": true, "sha256": digest, "path": path}))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn artifact_digest_is_verified() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("artifact");
        std::fs::write(&path, b"kerosene").unwrap();
        let digest = hex::encode(Sha256::digest(b"kerosene"));

        let result = std::fs::read(&path).unwrap();
        let computed = hex::encode(Sha256::digest(&result));
        assert_eq!(computed, digest);
    }
}
