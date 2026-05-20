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
#[derive(Clone, Debug)]
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

impl WebhookConfig {
    /// Creates a new `WebhookConfig` with the given URL and default values.
    pub fn new(url: Url) -> Self {
        Self {
            url,
            url_params: None,
            method: None,
            secret: None,
            headers: None,
            timeout: None,
        }
    }

    /// Sets the HTTP method for the webhook request.
    pub fn with_method(mut self, method: impl Into<String>) -> Self {
        self.method = Some(method.into());
        self
    }

    /// Sets the secret for HMAC signing.
    pub fn with_secret(mut self, secret: impl Into<String>) -> Self {
        self.secret = Some(secret.into());
        self
    }

    /// Sets the timeout for the webhook request.
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }

    /// Adds custom headers to the webhook request.
    pub fn with_headers(mut self, headers: HashMap<String, String>) -> Self {
        self.headers = Some(headers);
        self
    }

    /// Adds URL query parameters to the webhook request.
    pub fn with_url_params(mut self, params: HashMap<String, String>) -> Self {
        self.url_params = Some(params);
        self
    }
}

/// HTTP client for sending webhook notifications with optional HMAC signing.
#[derive(Debug)]
pub struct WebhookClient {
    url: Url,
    url_params: Option<HashMap<String, String>>,
    client: Arc<ClientWithMiddleware>,
    method: Method,
    secret: Option<String>,
    headers: HashMap<String, String>,
    timeout: Option<Duration>,
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

        let method = if let Some(m) = config.method {
            Method::from_bytes(m.as_bytes())
                .map_err(|e| OmnihookError::ConfigError(format!("Invalid HTTP method: {e}")))?
        } else {
            Method::POST
        };

        if let Some(params) = &config.url_params
            && params.is_empty() {
                return Err(OmnihookError::ConfigError(
                    "url_params cannot be empty if provided".to_string(),
                ));
            }

        Ok(Self {
            url: config.url,
            url_params: config.url_params,
            client: http_client,
            method,
            headers,
            secret: config.secret,
            timeout: config.timeout,
        })
    }

    /// Signs a JSON payload with HMAC-SHA256 and returns `(hex_signature,
    /// timestamp_ms)`.
    pub fn sign_payload(
        secret: &str,
        payload: &serde_json::Value,
        timestamp: i64,
    ) -> Result<(String, String), OmnihookError> {
        if secret.is_empty() {
            return Err(OmnihookError::SigningError(
                "Invalid secret: cannot be empty.".to_string(),
            ));
        }

        let mut mac = HmacSha256::new_from_slice(secret.as_bytes())
            .map_err(|e| OmnihookError::SigningError(format!("Invalid secret: {e}")))?;

        let serialized_payload = serde_json::to_string(payload).map_err(|e| {
            OmnihookError::SerializationError(format!("Failed to serialize payload: {e}"))
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
        // Sign the payload if a secret is configured
        let (signature, timestamp_str) = if let Some(secret) = &self.secret {
            let timestamp = Utc::now().timestamp_millis();
            let result = Self::sign_payload(secret, payload, timestamp)?;
            (Some(result.0), Some(result.1))
        } else {
            (None, None)
        };

        let mut url = self.url.clone();

        if let Some(params) = &self.url_params {
            url.query_pairs_mut().extend_pairs(params);
        }

        let mut headers = HeaderMap::new();

        if let Some(sig) = signature {
            headers.insert(
                HeaderName::from_static("x-signature"),
                HeaderValue::from_str(&sig).map_err(|e| {
                    OmnihookError::NotifyFailed(format!("Invalid signature value: {e}"))
                })?,
            );
        }

        if let Some(ts) = timestamp_str {
            headers.insert(
                HeaderName::from_static("x-timestamp"),
                HeaderValue::from_str(&ts).map_err(|e| {
                    OmnihookError::NotifyFailed(format!("Invalid timestamp value: {e}"))
                })?,
            );
        }

        for (key, value) in &self.headers {
            let header_name = HeaderName::from_bytes(key.as_bytes()).map_err(|e| {
                OmnihookError::NotifyFailed(format!("Invalid header name: {key}: {e}"))
            })?;
            let header_value = HeaderValue::from_str(value).map_err(|e| {
                OmnihookError::NotifyFailed(format!("Invalid header value for {key}: {value}: {e}"))
            })?;
            headers.insert(header_name, header_value);
        }

        if let Some(key) = idempotency_key {
            let header_val = HeaderValue::from_str(key).map_err(|e| {
                OmnihookError::NotifyFailed(format!("Invalid idempotency key value: {e}"))
            })?;
            headers.insert("Idempotency-Key", header_val);
        }

        let mut request = self
            .client
            .request(self.method.clone(), url)
            .headers(headers);

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
        let mut config = WebhookConfig::new(Url::parse(url).unwrap());

        if let Some(s) = secret {
            config = config.with_secret(s);
        }

        if let Some(h) = headers {
            config = config.with_headers(h);
        }

        WebhookClient::new(config, http_client).unwrap()
    }

    fn create_test_payload() -> serde_json::Value {
        GenericWebhookPayloadBuilder.build_payload("Test Alert", "Test message with value ${value}")
    }

    #[test]
    fn test_sign_request() {
        let payload = json!({ "title": "Test Title", "body": "Test message" });
        let timestamp = 123456789;
        let (signature, timestamp_str) =
            WebhookClient::sign_payload("test-secret", &payload, timestamp).unwrap();
        assert!(!signature.is_empty());
        assert_eq!(timestamp_str, "123456789");
    }

    #[test]
    fn test_webhook_config_builder() {
        let url = Url::parse("https://example.com").unwrap();
        let config = WebhookConfig::new(url.clone())
            .with_method("PUT")
            .with_secret("secret")
            .with_timeout(Duration::from_secs(5))
            .with_headers(HashMap::from([("X-Test".to_string(), "Value".to_string())]))
            .with_url_params(HashMap::from([("param".to_string(), "val".to_string())]));

        assert_eq!(config.url, url);
        assert_eq!(config.method, Some("PUT".to_string()));
        assert_eq!(config.secret, Some("secret".to_string()));
        assert_eq!(config.timeout, Some(Duration::from_secs(5)));
        assert_eq!(config.headers.unwrap().get("X-Test").unwrap(), "Value");
        assert_eq!(config.url_params.unwrap().get("param").unwrap(), "val");
    }

    #[test]
    fn test_invalid_http_method() {
        let http_client = create_test_http_client();
        let config = WebhookConfig::new(Url::parse("https://example.com").unwrap())
            .with_method("INVALID METHOD");

        let result = WebhookClient::new(config, http_client);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("Invalid HTTP method")
        );
    }

    #[tokio::test]
    async fn test_url_params_inclusion() {
        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock("POST", "/")
            .match_query(mockito::Matcher::UrlEncoded("foo".into(), "bar".into()))
            .with_status(200)
            .create_async()
            .await;

        let http_client = create_test_http_client();
        let config = WebhookConfig::new(Url::parse(&server.url()).unwrap())
            .with_url_params(HashMap::from([("foo".to_string(), "bar".to_string())]));

        let client = WebhookClient::new(config, http_client).unwrap();
        let result = client.notify_json(&json!({"test": "data"}), None).await;

        assert!(result.is_ok());
        mock.assert();
    }

    #[test]
    fn test_sign_request_validation() {
        let payload = json!({ "title": "Test Title", "body": "Test message" });
        let error = WebhookClient::sign_payload("", &payload, 123).unwrap_err();
        assert!(matches!(error, OmnihookError::SigningError(_)));
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
    fn test_sign_payload_validation() {
        let timestamp = 123456789;
        let (signature, timestamp_str) =
            WebhookClient::sign_payload("test-secret", &create_test_payload(), timestamp).unwrap();
        assert!(
            hex::decode(&signature).is_ok(),
            "Signature should be valid hex"
        );
        assert_eq!(timestamp_str, "123456789");
    }
}
