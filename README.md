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

## Usage

### Basic Example

```rust,no_run
use omnihook::{WebhookClient, WebhookConfig, SlackPayloadBuilder};
use url::Url;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let url = Url::parse("https://hooks.slack.com/services/T000/B000/XXXX")?;
    
    // 1. Configure the webhook
    let config = WebhookConfig::new(url);

    // 2. Build client using default HTTP settings
    let client = config.build()?;

    // 3. Send notification
    let builder = SlackPayloadBuilder::default();
    client.notify("System Alert", "Database is down!", &builder, Some("idempotency_key")).await?;

    Ok(())
}
```

### Customizing HTTP Client (Middleware)

Since `omnihook` uses `reqwest-middleware`, you can add retries, logging, or caching. To do this, provide your own `Arc<ClientWithMiddleware>` to `WebhookClient::new`:

```rust,ignore
use std::sync::Arc;
use reqwest_middleware::ClientBuilder;
use reqwest_retry::{RetryTransientMiddleware, policies::ExponentialBackoff};
use omnihook::{WebhookClient, WebhookConfig};
use url::Url;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. Setup retry policy
    let retry_policy = ExponentialBackoff::builder().build_with_max_retries(3);
    let http_client = ClientBuilder::new(reqwest::Client::new())
        .with(RetryTransientMiddleware::new_with_policy(retry_policy))
        .build();

    // 2. Wrap in Arc and pass to client
    let config = WebhookConfig::new(Url::parse("https://...")?);
    let client = WebhookClient::new(config, Arc::new(http_client))?;

    Ok(())
}
```

## HMAC Signing & Security

`omnihook` supports automatic payload signing using HMAC-SHA256. When a `secret` is provided in the configuration, every request will include `x-signature` and `x-timestamp` headers.

```rust,no_run
use omnihook::{WebhookClient, WebhookConfig, GenericWebhookPayloadBuilder};
use url::Url;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = WebhookConfig::new(Url::parse("https://your-api.com/webhook")?)
        .with_secret("top-secret-key"); // Enables automatic signing

    let client = config.build()?;
    
    // This call will now automatically sign the payload
    client.notify("Alert", "Something happened", &GenericWebhookPayloadBuilder::default(), Some("idempotency_key")).await?;

    Ok(())
}
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

## License

* MIT license (http://opensource.org/licenses/MIT)
