//! Webhook HTTP client with optional HMAC signing.

use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use hmac::{Hmac, KeyInit, Mac};
use reqwest::{
    Client, Method,
    header::{HeaderMap, HeaderName, HeaderValue},
};
use reqwest_middleware::{ClientBuilder, ClientWithMiddleware};
use sha2::Sha256;
use url::Url;

use crate::{error::OmnihookError, payload_builder::WebhookPayloadBuilder};

type HmacSha256 = Hmac<Sha256>;

/// Configuration for a webhook request.
#[derive(Clone, Debug)]
pub struct WebhookConfig {
    /// The webhook URL to send requests to.
    url: Url,
    /// Optional URL query parameters to include in the request.
    url_params: Option<HashMap<String, String>>,
    /// The HTTP method to use (default: POST).
    method: Method,
    /// Optional secret for HMAC signing of the payload.
    secret: Option<String>,
    /// Optional custom headers to include in the request.
    headers: Option<HashMap<String, String>>,
    /// Optional timeout for the HTTP request. If not set, the default timeout of the HTTP client will be used.
    timeout: Option<Duration>,
}

impl WebhookConfig {
    /// Creates a new `WebhookConfig` with the given URL and default values.
    pub fn new(url: Url) -> Self {
        Self {
            url,
            url_params: None,
            method: Method::POST,
            secret: None,
            headers: None,
            timeout: None,
        }
    }

    /// Sets the HTTP method for the webhook request.
    pub fn with_method(mut self, method: Method) -> Self {
        self.method = method;
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

    /// Adds multiple custom headers to the webhook request, merging with existing ones.
    pub fn with_headers(mut self, headers: HashMap<String, String>) -> Self {
        let current = self.headers.get_or_insert_with(HashMap::new);
        current.extend(headers);
        self
    }

    /// Adds a single custom header to the webhook request.
    pub fn with_header(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        let headers = self.headers.get_or_insert_with(HashMap::new);
        headers.insert(key.into(), value.into());
        self
    }

    /// Adds multiple URL query parameters to the webhook request, merging with existing ones.
    pub fn with_url_params(mut self, params: HashMap<String, String>) -> Self {
        let current = self.url_params.get_or_insert_with(HashMap::new);
        current.extend(params);
        self
    }

    /// Adds a single URL query parameter to the webhook request.
    pub fn with_url_param(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        let params = self.url_params.get_or_insert_with(HashMap::new);
        params.insert(key.into(), value.into());
        self
    }

    /// Builds a `WebhookClient` using a default HTTP client.
    pub fn build(self) -> Result<WebhookClient, OmnihookError> {
        WebhookClient::try_from(self)
    }
}

impl TryFrom<WebhookConfig> for WebhookClient {
    type Error = OmnihookError;

    /// Creates a `WebhookClient` from a `WebhookConfig` using a default reqwest client.
    fn try_from(config: WebhookConfig) -> Result<Self, Self::Error> {
        let http_client = Arc::new(ClientBuilder::new(Client::new()).build());
        Self::new(config, http_client)
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

        if let Some(params) = &config.url_params
            && params.is_empty()
        {
            return Err(OmnihookError::ConfigError(
                "url_params cannot be empty if provided".to_string(),
            ));
        }

        Ok(Self {
            url: config.url,
            url_params: config.url_params,
            client: http_client,
            method: config.method,
            headers,
            secret: config.secret,
            timeout: config.timeout,
        })
    }

    /// Computes an HMAC-SHA256 signature and returns `(hex_signature,
    /// timestamp_ms)`.
    ///
    /// The HMAC message is the raw `payload_bytes` followed immediately by the
    /// decimal string representation of `timestamp`, with no delimiter between
    /// them. In other words, the signed message is:
    ///
    /// `payload_bytes || timestamp.to_string().as_bytes()`
    ///
    /// The returned `timestamp_ms` value is that decimal timestamp string.
    pub fn sign_payload(
        secret: &str,
        payload_bytes: &[u8],
        timestamp: i64,
    ) -> Result<(String, String), OmnihookError> {
        if secret.is_empty() {
            return Err(OmnihookError::SigningError(
                "Invalid secret: cannot be empty.".to_string(),
            ));
        }

        let mut mac = HmacSha256::new_from_slice(secret.as_bytes())
            .map_err(|e| OmnihookError::SigningError(format!("Invalid secret: {e}")))?;

        let timestamp_str = timestamp.to_string();

        // The signature is computed over the payload bytes followed by the timestamp string.
        mac.update(payload_bytes);
        mac.update(timestamp_str.as_bytes());

        let signature = hex::encode(mac.finalize().into_bytes());
        Ok((signature, timestamp_str))
    }

    /// Builds a payload using the given builder and sends it.
    pub async fn notify(
        &self,
        title: &str,
        body: &str,
        builder: &dyn WebhookPayloadBuilder,
    ) -> Result<(), OmnihookError> {
        let payload = builder.build_payload(title, body);
        self.notify_json(&payload, None).await
    }

    /// Sends a JSON payload to the configured webhook URL.
    pub async fn notify_json(
        &self,
        payload: &serde_json::Value,
        idempotency_key: Option<&str>,
    ) -> Result<(), OmnihookError> {
        // Serialize the payload to JSON bytes ONCE to ensure the same content is used for both the request body and signing.
        let body_bytes = serde_json::to_vec(payload).map_err(|e| {
            OmnihookError::SerializationError(format!("Failed to serialize payload: {e}"))
        })?;

        // Sign the payload if a secret is configured
        let (signature, timestamp_str) = if let Some(secret) = &self.secret {
            let timestamp = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|_| OmnihookError::SigningError("Time went backwards".to_string()))?
                .as_millis();

            let timestamp_i64 = i64::try_from(timestamp)
                .map_err(|_| OmnihookError::SigningError("Timestamp overflow".to_string()))?;

            let result = Self::sign_payload(secret, &body_bytes, timestamp_i64)?;
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
            .headers(headers)
            .body(body_bytes);

        if let Some(timeout) = self.timeout {
            request = request.timeout(timeout);
        }

        let response = request.send().await?;

        let status = response.status();
        if !status.is_success() {
            // Get error context from the response body if possible
            let error_body = response
                .text()
                .await
                .unwrap_or_else(|_| "Unknown error".to_string());
            return Err(OmnihookError::NotifyFailed(format!(
                "Webhook request failed with status: {status}. Body: {error_body}"
            )));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::HashMap, sync::Arc};

    use mockito::{Matcher, Mock};

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
    fn test_sign_payload_basic() {
        let payload_bytes = serde_json::to_vec(&create_test_payload()).unwrap();
        let timestamp = 123456789;
        let (signature, timestamp_str) =
            WebhookClient::sign_payload("test-secret", &payload_bytes, timestamp).unwrap();
        assert!(!signature.is_empty());
        assert_eq!(timestamp_str, "123456789");
    }

    #[test]
    fn test_webhook_config_builder() {
        let url = Url::parse("https://example.com").unwrap();
        let config = WebhookConfig::new(url.clone())
            .with_method(Method::PUT)
            .with_secret("secret")
            .with_timeout(Duration::from_secs(5))
            .with_header("X-Test", "Value")
            .with_url_param("param", "val");

        assert_eq!(config.url, url);
        assert_eq!(config.method, Method::PUT);
        assert_eq!(config.secret, Some("secret".to_string()));
        assert_eq!(config.timeout, Some(Duration::from_secs(5)));
        assert_eq!(
            config.headers.as_ref().unwrap().get("X-Test").unwrap(),
            "Value"
        );
        assert_eq!(
            config.url_params.as_ref().unwrap().get("param").unwrap(),
            "val"
        );
    }

    #[test]
    fn test_webhook_config_builder_append() {
        let url = Url::parse("https://example.com").unwrap();
        let config = WebhookConfig::new(url)
            .with_header("X-1", "V1")
            .with_headers(HashMap::from([("X-2".to_string(), "V2".to_string())]))
            .with_url_param("p1", "v1")
            .with_url_params(HashMap::from([("p2".to_string(), "v2".to_string())]));

        let headers = config.headers.unwrap();
        assert_eq!(headers.get("X-1").unwrap(), "V1");
        assert_eq!(headers.get("X-2").unwrap(), "V2");

        let params = config.url_params.unwrap();
        assert_eq!(params.get("p1").unwrap(), "v1");
        assert_eq!(params.get("p2").unwrap(), "v2");
    }

    #[test]
    fn test_webhook_client_default_build() {
        let url = Url::parse("https://example.com").unwrap();
        let config = WebhookConfig::new(url);
        let client = config.build().unwrap();
        assert_eq!(client.url.as_str(), "https://example.com/");
    }

    #[tokio::test]
    async fn test_notify_success_with_url_params() {
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
        let result = client.notify_json(&create_test_payload(), None).await;

        assert!(result.is_ok());
        mock.assert();
    }

    #[test]
    fn test_sign_payload_error_on_empty_secret() {
        let payload_bytes = serde_json::to_vec(&create_test_payload()).unwrap();
        let error = WebhookClient::sign_payload("", &payload_bytes, 123).unwrap_err();
        assert!(matches!(error, OmnihookError::SigningError(_)));
    }

    #[tokio::test]
    async fn test_notify_error_network() {
        let action = create_test_action("https://webhook.example.com", None, None);
        let payload = create_test_payload();
        let result = action.notify_json(&payload, None).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_notify_success_with_signing_headers() {
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
    async fn test_notify_error_invalid_header_name() {
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
    async fn test_notify_error_invalid_header_value() {
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
    async fn test_notify_error_includes_original_error_body() {
        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock("POST", "/")
            .with_status(400)
            .with_body("Invalid payload format")
            .create_async()
            .await;

        let action = create_test_action(server.url().as_str(), None, None);
        let err = action
            .notify_json(&create_test_payload(), None)
            .await
            .unwrap_err();

        assert!(err.to_string().contains("400 Bad Request"));
        assert!(err.to_string().contains("Invalid payload format"));
        mock.assert();
    }

    #[tokio::test]
    async fn test_notify_success_with_custom_headers() {
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
    #[test]
    fn test_sign_payload_format() {
        let timestamp = 123456789;
        let payload_bytes = serde_json::to_vec(&create_test_payload()).unwrap();
        let (signature, timestamp_str) =
            WebhookClient::sign_payload("test-secret", &payload_bytes, timestamp).unwrap();
        assert!(
            hex::decode(&signature).is_ok(),
            "Signature should be valid hex"
        );
        assert_eq!(timestamp_str, "123456789");
    }
}
