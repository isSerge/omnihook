//! Webhook HTTP client with optional HMAC signing.

use std::{collections::HashMap, sync::Arc, time::Duration};

use chrono::Utc;
use hmac::{Hmac, KeyInit, Mac};
use reqwest::{
    Method,
    header::{HeaderMap, HeaderName, HeaderValue},
};
use reqwest_middleware::ClientWithMiddleware;
use sha2::Sha256;
use url::Url;

use crate::error::OmnihookError;

type HmacSha256 = Hmac<Sha256>;

/// Configuration for a webhook request.
#[derive(Clone)]
pub struct WebhookConfig {
    /// The webhook URL to send requests to.
    pub url: Url,
    /// Optional URL query parameters to include in the request.
    pub url_params: Option<HashMap<String, String>>,
    /// The HTTP method to use (default: POST).
    pub method: Option<String>,
    /// Optional secret for HMAC signing of the payload.
    pub secret: Option<String>,
    /// Optional custom headers to include in the request.
    pub headers: Option<HashMap<String, String>>,
    /// Optional timeout for the HTTP request. If not set, the default timeout of the HTTP client will be used.
    pub timeout: Option<Duration>,
}

/// HTTP client for sending webhook notifications with optional HMAC signing.
#[derive(Debug)]
pub struct WebhookClient {
    pub url: Url,
    pub url_params: Option<HashMap<String, String>>,
    pub client: Arc<ClientWithMiddleware>,
    pub method: String,
    pub secret: Option<String>,
    pub headers: Option<HashMap<String, String>>,
    pub timeout: Option<Duration>,
}

impl WebhookClient {
    /// Creates a new `WebhookClient` from the given config and HTTP client.
    pub fn new(
        config: WebhookConfig,
        http_client: Arc<ClientWithMiddleware>,
    ) -> Result<Self, OmnihookError> {
        let mut headers = config.headers.unwrap_or_default();
        if !headers.contains_key("Content-Type") {
            headers.insert("Content-Type".to_string(), "application/json".to_string());
        }

        Ok(Self {
            url: config.url,
            url_params: config.url_params,
            client: http_client,
            method: config.method.unwrap_or_else(|| "POST".to_string()),
            secret: config.secret,
            headers: Some(headers),
            timeout: config.timeout,
        })
    }

    /// Signs a JSON payload with HMAC-SHA256 and returns `(hex_signature,
    /// timestamp_ms)`.
    pub fn sign_payload(
        &self,
        secret: &str,
        payload: &serde_json::Value,
        timestamp: i64,
    ) -> Result<(String, String), OmnihookError> {
        if secret.is_empty() {
            return Err(OmnihookError::NotifyFailed(
                "Invalid secret: cannot be empty.".to_string(),
            ));
        }

        let mut mac = HmacSha256::new_from_slice(secret.as_bytes())
            .map_err(|e| OmnihookError::ConfigError(format!("Invalid secret: {e}")))?;

        let serialized_payload = serde_json::to_string(payload).map_err(|e| {
            OmnihookError::InternalError(format!("Failed to serialize payload: {e}"))
        })?;
        let message = format!("{serialized_payload}{timestamp}");
        mac.update(message.as_bytes());

        let signature = hex::encode(mac.finalize().into_bytes());
        Ok((signature, timestamp.to_string()))
    }

    /// Sends a JSON payload to the configured webhook URL.
    pub async fn notify_json(
        &self,
        payload: &serde_json::Value,
        idempotency_key: Option<&str>,
    ) -> Result<(), OmnihookError> {
        let mut url = self.url.clone();

        if let Some(params) = &self.url_params
            && !params.is_empty()
        {
            url.query_pairs_mut().extend_pairs(params);
        }

        let method = Method::from_bytes(self.method.as_bytes()).unwrap_or(Method::POST);

        let mut headers = HeaderMap::new();

        if let Some(secret) = &self.secret {
            let timestamp = Utc::now().timestamp_millis();
            let (signature, timestamp_str) = self.sign_payload(secret, payload, timestamp)?;

            headers.insert(
                HeaderName::from_static("x-signature"),
                HeaderValue::from_str(&signature).map_err(|e| {
                    OmnihookError::NotifyFailed(format!("Invalid signature value: {e}"))
                })?,
            );
            headers.insert(
                HeaderName::from_static("x-timestamp"),
                HeaderValue::from_str(&timestamp_str).map_err(|e| {
                    OmnihookError::NotifyFailed(format!("Invalid timestamp value: {e}"))
                })?,
            );
        }

        if let Some(headers_map) = &self.headers {
            for (key, value) in headers_map {
                let header_name = HeaderName::from_bytes(key.as_bytes()).map_err(|e| {
                    OmnihookError::NotifyFailed(format!("Invalid header name: {key}: {e}"))
                })?;
                let header_value = HeaderValue::from_str(value).map_err(|e| {
                    OmnihookError::NotifyFailed(format!(
                        "Invalid header value for {key}: {value}: {e}"
                    ))
                })?;
                headers.insert(header_name, header_value);
            }
        }

        if let Some(key) = idempotency_key {
            let header_val = HeaderValue::from_str(key).map_err(|e| {
                OmnihookError::NotifyFailed(format!("Invalid idempotency key value: {e}"))
            })?;
            headers.insert("Idempotency-Key", header_val);
        }

        let mut request = self.client.request(method, url.as_str()).headers(headers);

        if let Some(timeout) = self.timeout {
            request = request.timeout(timeout);
        }

        let response = request.json(payload).send().await?;

        let status = response.status();
        if !status.is_success() {
            return Err(OmnihookError::NotifyFailed(format!(
                "Webhook request failed with status: {status}"
            )));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::HashMap, sync::Arc};

    use mockito::{Matcher, Mock};
    use serde_json::json;

    use super::*;
    use crate::{GenericWebhookPayloadBuilder, OmnihookError, WebhookPayloadBuilder};

    fn create_test_http_client() -> Arc<ClientWithMiddleware> {
        Arc::new(reqwest_middleware::ClientBuilder::new(reqwest::Client::new()).build())
    }

    fn create_test_action(
        url: &str,
        secret: Option<&str>,
        headers: Option<HashMap<String, String>>,
    ) -> WebhookClient {
        let http_client = create_test_http_client();
        let config = WebhookConfig {
            url: Url::parse(url).unwrap(),
            url_params: None,
            method: Some("POST".to_string()),
            secret: secret.map(|s| s.to_string()),
            headers,
            timeout: None,
        };
        WebhookClient::new(config, http_client).unwrap()
    }

    fn create_test_payload() -> serde_json::Value {
        GenericWebhookPayloadBuilder.build_payload("Test Alert", "Test message with value ${value}")
    }

    #[test]
    fn test_sign_request() {
        let action = create_test_action("https://webhook.example.com", Some("test-secret"), None);
        let payload = json!({ "title": "Test Title", "body": "Test message" });
        let timestamp = 123456789;
        let (signature, timestamp_str) = action
            .sign_payload("test-secret", &payload, timestamp)
            .unwrap();
        assert!(!signature.is_empty());
        assert_eq!(timestamp_str, "123456789");
    }

    #[test]
    fn test_sign_request_fails_empty_secret() {
        let action = create_test_action("https://webhook.example.com", None, None);
        let payload = json!({ "title": "Test Title", "body": "Test message" });
        let error = action.sign_payload("", &payload, 123).unwrap_err();
        assert!(matches!(error, OmnihookError::NotifyFailed(_)));
    }

    #[tokio::test]
    async fn test_notify_failure() {
        let action = create_test_action("https://webhook.example.com", None, None);
        let payload = create_test_payload();
        let result = action.notify_json(&payload, None).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_notify_includes_signature_and_timestamp() {
        let mut server = mockito::Server::new_async().await;
        let mock: Mock = server
            .mock("POST", "/")
            .match_header("X-Signature", Matcher::Regex("^[0-9a-f]{64}$".to_string()))
            .match_header("X-Timestamp", Matcher::Regex("^[0-9]+$".to_string()))
            .match_header("Content-Type", "application/json")
            .with_status(200)
            .create_async()
            .await;

        let action = create_test_action(
            server.url().as_str(),
            Some("top-secret"),
            Some(HashMap::from([(
                "Content-Type".to_string(),
                "application/json".to_string(),
            )])),
        );
        let result = action.notify_json(&create_test_payload(), None).await;
        assert!(result.is_ok());
        mock.assert();
    }

    #[tokio::test]
    async fn test_notify_with_invalid_header_name() {
        let server = mockito::Server::new_async().await;
        let invalid_headers =
            HashMap::from([("Invalid Header!@#".to_string(), "value".to_string())]);
        let action = create_test_action(server.url().as_str(), None, Some(invalid_headers));
        let err = action
            .notify_json(&create_test_payload(), None)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("Invalid header name"));
    }

    #[tokio::test]
    async fn test_notify_with_invalid_header_value() {
        let server = mockito::Server::new_async().await;
        let invalid_headers =
            HashMap::from([("X-Custom-Header".to_string(), "Invalid\nValue".to_string())]);
        let action = create_test_action(server.url().as_str(), None, Some(invalid_headers));
        let err = action
            .notify_json(&create_test_payload(), None)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("Invalid header value"));
    }

    #[tokio::test]
    async fn test_notify_with_valid_headers() {
        let mut server = mockito::Server::new_async().await;
        let valid_headers = HashMap::from([
            ("X-Custom-Header".to_string(), "valid-value".to_string()),
            ("Accept".to_string(), "application/json".to_string()),
        ]);
        let mock = server
            .mock("POST", "/")
            .match_header("X-Custom-Header", "valid-value")
            .match_header("Accept", "application/json")
            .with_status(200)
            .create_async()
            .await;
        let action = create_test_action(server.url().as_str(), None, Some(valid_headers));
        assert!(
            action
                .notify_json(&create_test_payload(), None)
                .await
                .is_ok()
        );
        mock.assert();
    }

    #[tokio::test]
    async fn test_notify_signature_header_cases() {
        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock("POST", "/")
            .match_header("X-Signature", Matcher::Any)
            .match_header("X-Timestamp", Matcher::Any)
            .with_status(200)
            .create_async()
            .await;
        let action = create_test_action(server.url().as_str(), Some("test-secret"), None);
        assert!(
            action
                .notify_json(&create_test_payload(), None)
                .await
                .is_ok()
        );
        mock.assert();
    }
    #[test]
    fn test_sign_request_validation() {
        let action = create_test_action("https://webhook.example.com", Some("test-secret"), None);
        let timestamp = 123456789;
        let (signature, timestamp_str) = action
            .sign_payload("test-secret", &create_test_payload(), timestamp)
            .unwrap();
        assert!(
            hex::decode(&signature).is_ok(),
            "Signature should be valid hex"
        );
        assert_eq!(timestamp_str, "123456789");
    }
}
