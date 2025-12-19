//! X/Twitter API integration
//!
//! Handles posting via the X API v2 using OAuth 1.0a.

use crate::config::load_x_creds;
use crate::posts::{find_post, load_posts};
use anyhow::Result;
use base64::Engine;
use hmac::{Hmac, Mac};
use reqwest::header::{HeaderMap, HeaderValue, AUTHORIZATION, CONTENT_TYPE};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const API_URL: &str = "https://api.twitter.com/2/tweets";

type HmacSha256 = Hmac<Sha256>;

/// Tweet request body
#[derive(Debug, Serialize)]
struct TweetRequest {
    text: String,
}

/// Tweet response
#[derive(Debug, Deserialize)]
struct TweetResponse {
    data: TweetData,
}

#[derive(Debug, Deserialize)]
struct TweetData {
    id: String,
}

/// Generate OAuth 1.0a signature and authorization header
fn oauth_header(
    consumer_key: &str,
    consumer_secret: &str,
    access_token: &str,
    access_token_secret: &str,
    method: &str,
    url: &str,
) -> String {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards")
        .as_secs()
        .to_string();

    let mut nonce = String::with_capacity(32);
    for _ in 0..32 {
        let _ = write!(nonce, "{:x}", rand::random::<u8>() % 16);
    }

    let mut params = BTreeMap::new();
    params.insert("oauth_consumer_key", consumer_key);
    params.insert("oauth_nonce", &nonce);
    params.insert("oauth_signature_method", "HMAC-SHA256");
    params.insert("oauth_timestamp", &timestamp);
    params.insert("oauth_token", access_token);
    params.insert("oauth_version", "1.0");

    let param_string: String = params
        .iter()
        .map(|(k, v)| format!("{}={}", percent_encode(k), percent_encode(v)))
        .collect::<Vec<_>>()
        .join("&");

    let base_string = format!(
        "{}&{}&{}",
        method,
        percent_encode(url),
        percent_encode(&param_string)
    );

    let signing_key = format!(
        "{}&{}",
        percent_encode(consumer_secret),
        percent_encode(access_token_secret)
    );

    let mut mac =
        HmacSha256::new_from_slice(signing_key.as_bytes()).expect("HMAC can take key of any size");
    mac.update(base_string.as_bytes());
    let signature = base64::engine::general_purpose::STANDARD.encode(mac.finalize().into_bytes());

    format!(
        r#"OAuth oauth_consumer_key="{}", oauth_nonce="{}", oauth_signature="{}", oauth_signature_method="HMAC-SHA256", oauth_timestamp="{}", oauth_token="{}", oauth_version="1.0""#,
        percent_encode(consumer_key),
        percent_encode(&nonce),
        percent_encode(&signature),
        percent_encode(&timestamp),
        percent_encode(access_token),
    )
}

/// Percent encode a string for OAuth
fn percent_encode(s: &str) -> String {
    let mut result = String::new();
    for byte in s.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                result.push(byte as char);
            }
            _ => {
                let _ = write!(result, "%{byte:02X}");
            }
        }
    }
    result
}

/// Post content to X
///
/// # Errors
/// Returns error if posting fails
pub async fn post(id: &str, dry_run: bool) -> Result<()> {
    let post_data = find_post(id)?;
    let content = post_data.x.trim();

    println!("Posting: {}", post_data.title);

    if content.len() > 280 {
        println!(
            "Warning: Content is {} chars (limit 280 for free tier)",
            content.len()
        );
    }

    if dry_run {
        println!("\n[DRY RUN] Would post to X:");
        println!("{}", "-".repeat(50));
        println!("{content}");
        println!("{}", "-".repeat(50));
        println!("Character count: {}/280", content.len());
        return Ok(());
    }

    let creds = load_x_creds()?;

    if creds.consumer_key.is_empty() {
        anyhow::bail!("X API credentials not found in pass royalbit/x");
    }

    let auth_header = oauth_header(
        &creds.consumer_key,
        &creds.consumer_secret,
        &creds.access_token,
        &creds.access_token_secret,
        "POST",
        API_URL,
    );

    let mut headers = HeaderMap::new();
    headers.insert(AUTHORIZATION, HeaderValue::from_str(&auth_header)?);
    headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));

    let request = TweetRequest {
        text: content.to_string(),
    };

    let client = reqwest::Client::new();
    let response = client
        .post(API_URL)
        .headers(headers)
        .json(&request)
        .send()
        .await?;

    if response.status().is_success() {
        let tweet: TweetResponse = response.json().await?;
        println!("Posted successfully!");
        println!("Tweet ID: {}", tweet.data.id);
        println!("URL: https://x.com/i/status/{}", tweet.data.id);
    } else {
        let status = response.status();
        let body = response.text().await?;
        anyhow::bail!("Failed to post: {status} - {body}");
    }

    Ok(())
}

/// Post all content with delay between posts
///
/// # Errors
/// Returns error if any post fails
pub async fn post_all(delay: u64, dry_run: bool) -> Result<()> {
    let posts = load_posts()?;

    println!(
        "Posting {} items with {delay}s delay between posts...",
        posts.len(),
    );

    if dry_run {
        println!("[DRY RUN MODE]");
    }

    for (i, p) in posts.iter().enumerate() {
        println!("\n[{}/{}] {}", i + 1, posts.len(), p.title);

        post(&p.id, dry_run).await?;

        if !dry_run && i < posts.len() - 1 {
            println!("Waiting {delay}s before next post...");
            tokio::time::sleep(Duration::from_secs(delay)).await;
        }
    }

    println!("\nDone!");
    Ok(())
}
