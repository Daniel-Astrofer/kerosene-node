use serde_json::Value;

/// Field paths that contain sensitive data and must be redacted.
const SENSITIVE_FIELD_PATHS: &[&str] = &[
    "identity",
    "identity_pem",
    "secret",
    "secret_key",
    "private_key",
    "root_private_key",
    "signing_key",
    "token",
    "access_token",
    "bearer",
    "authorization",
    "password",
    "passphrase",
    "tls_key",
    "certificate_key",
    "ca_key",
    "proxy_password",
    "socks5_password",
    "cookie",
    "session",
];

/// Redact sensitive fields from a JSON value in place.
///
/// Scans both top-level keys and nested objects. String values at matching
/// keys are replaced with `"<REDACTED>"`. Nested objects and arrays are
/// traversed recursively.
pub fn redact_value(value: &mut Value) {
    match value {
        Value::Object(map) => {
            let sensitive_keys: Vec<String> = map
                .keys()
                .filter(|k| is_sensitive_key(k))
                .cloned()
                .collect();
            for key in sensitive_keys {
                if let Some(field) = map.get_mut(&key) {
                    if field.is_string() {
                        *field = Value::String("<REDACTED>".to_string());
                    }
                }
            }
            for val in map.values_mut() {
                redact_value(val);
            }
        }
        Value::Array(arr) => {
            for val in arr.iter_mut() {
                redact_value(val);
            }
        }
        _ => {}
    }
}

/// Redact sensitive fields and return a new JSON value (cloned).
pub fn redacted_copy(value: &Value) -> Value {
    let mut cloned = value.clone();
    redact_value(&mut cloned);
    cloned
}

fn is_sensitive_key(key: &str) -> bool {
    let lower = key.to_lowercase();
    SENSITIVE_FIELD_PATHS
        .iter()
        .any(|pat| lower.contains(pat) || lower == *pat)
}

/// Redact the authorization header value.
pub fn redact_header(value: &str) -> String {
    if value.len() > 8 {
        let prefix = &value[..std::cmp::min(4, value.len())];
        format!("{}...<REDACTED>", prefix)
    } else {
        "<REDACTED>".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn root_sensitive_key_is_redacted() {
        let mut value = json!({"identity": "deadbeef", "network": "testnet"});
        redact_value(&mut value);
        assert_eq!(value["identity"], "<REDACTED>");
        assert_eq!(value["network"], "testnet");
    }

    #[test]
    fn nested_sensitive_key_is_redacted() {
        let mut value = json!({"member": {"identity": "abcdef", "name": "alice"}});
        redact_value(&mut value);
        assert_eq!(value["member"]["identity"], "<REDACTED>");
        assert_eq!(value["member"]["name"], "alice");
    }

    #[test]
    fn array_elements_are_redacted() {
        let mut value = json!([{"secret_key": "abcdef"}, {"secret_key": "123456"}]);
        redact_value(&mut value);
        assert_eq!(value[0]["secret_key"], "<REDACTED>");
        assert_eq!(value[1]["secret_key"], "<REDACTED>");
    }

    #[test]
    fn redacted_copy_preserves_original() {
        let original = json!({"identity": "topsecret", "public": "hello"});
        let redacted = redacted_copy(&original);
        assert_eq!(redacted["identity"], "<REDACTED>");
        assert_eq!(original["identity"], "topsecret");
    }

    #[test]
    fn non_sensitive_values_unchanged() {
        let mut value = json!({"name": "kerosene", "version": "1.0.0"});
        redact_value(&mut value);
        assert_eq!(value["name"], "kerosene");
        assert_eq!(value["version"], "1.0.0");
    }

    #[test]
    fn header_is_redacted() {
        let header = "Bearer eyJhbGciOiJIUzI1NiJ9";
        let redacted = redact_header(header);
        assert!(redacted.contains("<REDACTED>"));
        assert!(redacted.starts_with("Bear"));
    }
}
