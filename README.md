[![Crates.io](https://img.shields.io/crates/v/omnihook.svg)](https://crates.io/crates/omnihook)
[![Docs.rs](https://docs.rs/omnihook/badge.svg)](https://docs.rs/omnihook)
[![License](https://img.shields.io/crates/l/omnihook.svg)](https://crates.io/crates/omnihook)
[![Build Status](https://img.shields.io/github/actions/workflow/status/isSerge/omnihook/ci.yml?branch=main)](https://github.com/isSerge/omnihook/actions)

# Omnihook

`omnihook` is a flexible, type-safe Rust library for sending webhook notifications to various platforms. It provides platform-specific payload builders for Slack, Discord, Telegram, and generic endpoints, with built-in support for HMAC-SHA256 signing.

## Features

- **Multi-Platform Support**: Built-in builders for:
  - **Slack**: Blocks-based messages with mrkdwn.
  - **Discord**: Content-based messages with markdown.
  - **Telegram**: MarkdownV2 formatted messages with chat ID support.
  - **Generic**: Custom JSON payloads with template variables.
- **HMAC Signing**: Secure your webhooks with HMAC-SHA256 signatures and timestamps.
- **Middleware Support**: Built on top of `reqwest-middleware` for extensible HTTP client behavior.
- **Async/Await**: Native async support for high-performance notification delivery.

## Installation

Add this to your `Cargo.toml`:

```toml
[dependencies]
omnihook = "0.1.0"
```

## Quick Start

### Basic Webhook Notification

```rust,no_run
use omnihook::{WebhookClient, WebhookConfig, SlackPayloadBuilder, WebhookPayloadBuilder};
use reqwest_middleware::ClientBuilder;
use std::sync::Arc;
use url::Url;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. Setup HTTP client with middleware support.
    // You can easily add retries, logging, or caching here using reqwest-middleware.
    let http_client = Arc::new(
        ClientBuilder::new(reqwest::Client::new())
            .build()
    );

    // 2. Configure the webhook using the builder API
    let config = WebhookConfig::new(Url::parse("https://hooks.slack.com/services/T123/B123/X123")?)
        .with_method("POST")
        .with_timeout(std::time::Duration::from_secs(10));

    let client = WebhookClient::new(config, http_client)?;

    // 3. Build platform-specific payload
    let builder = SlackPayloadBuilder::default();
    let payload = builder.build_payload("Critical Error", "The database is unreachable.");

    // 4. Send notification
    client.notify_json(&payload, None).await?;

    Ok(())
}
```

## Middleware & Customization

Since `omnihook` uses `reqwest-middleware`, you have full control over the HTTP client's behavior. This makes it simple to add features like **exponential backoff retries** without any library-specific configuration:

```rust,ignore
// Example: Adding retries with reqwest-retry
let retry_policy = ExponentialBackoff::builder().build_with_max_retries(3);
let http_client = Arc::new(
    ClientBuilder::new(reqwest::Client::new())
        .with(RetryTransientMiddleware::new_with_policy(retry_policy))
        .build()
);
```

## Payload Builders

The library uses the `WebhookPayloadBuilder` trait to allow for easy extensibility:

### Slack
Uses Slack's [Block Kit](https://api.slack.com/block-kit) for structured messages.
```rust,no_run
use omnihook::{SlackPayloadBuilder, WebhookPayloadBuilder};
let builder = SlackPayloadBuilder::default();
let payload = builder.build_payload("Alert", "Something happened");
// Returns: { "blocks": [ { "type": "section", "text": { "type": "mrkdwn", "text": "*Alert*\n\nSomething happened" } } ] }
```

### Discord
Simple markdown-enabled content messages.
```rust,no_run
use omnihook::{DiscordPayloadBuilder, WebhookPayloadBuilder};
let builder = DiscordPayloadBuilder::default();
let payload = builder.build_payload("Alert", "Something happened");
// Returns: { "content": "*Alert*\n\nSomething happened" }
```

### Telegram
Handles required `chat_id` and MarkdownV2 escaping.
```rust,no_run
use omnihook::{TelegramPayloadBuilder, WebhookPayloadBuilder};
let builder = TelegramPayloadBuilder {
    chat_id: "123456789".to_string(),
    disable_web_preview: true,
};
let payload = builder.build_payload("Alert", "Something happened");
// Returns: { "chat_id": "123456789", "text": "*Alert* \n\nSomething happened", "parse_mode": "MarkdownV2", ... }
```

### Generic
Producing a standard high-level JSON object.
```rust,no_run
use omnihook::{GenericWebhookPayloadBuilder, WebhookPayloadBuilder};
let builder = GenericWebhookPayloadBuilder::default();
let payload = builder.build_payload("Alert", "Something happened");
// Returns: { "title": "Alert", "body": "Something happened" }
```

## HMAC Signing

If a `secret` is provided in the `WebhookConfig`, `omnihook` can sign payloads:

```rust,ignore
let (signature, timestamp) = client.sign_payload("secret-key", &payload)?;
```

This generates an HMAC-SHA256 signature calculated from the JSON payload and a timestamp, which can be sent as headers to verify the authenticity of the webhook on the receiving end.

## License

* MIT license (http://opensource.org/licenses/MIT)
