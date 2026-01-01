//! X/Twitter API integration
//!
//! Handles posting via the X API v2 using OAuth 1.0a.

use crate::config::{load_x_creds, posts_path};
use crate::posts::{
    filter_unposted, find_post_with_path, load_posts_with_path, update_posted_timestamp, Platform,
};
use anyhow::{Context, Result};
use base64::Engine;
use hmac::{Hmac, Mac};
use reqwest::header::{HeaderMap, HeaderValue, AUTHORIZATION, CONTENT_TYPE};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const API_URL: &str = "https://api.twitter.com/2/tweets";
const MEDIA_UPLOAD_URL: &str = "https://upload.twitter.com/1.1/media/upload.json";

type HmacSha256 = Hmac<Sha256>;

/// Tweet request body
#[derive(Debug, Serialize, Clone, PartialEq, Eq)]
pub struct TweetRequest {
    pub text: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub media: Option<TweetMedia>,
}

/// Media IDs for a tweet
#[derive(Debug, Serialize, Clone, PartialEq, Eq)]
pub struct TweetMedia {
    pub media_ids: Vec<String>,
}

/// Response from media upload
#[derive(Debug, Deserialize)]
struct MediaUploadResponse {
    media_id_string: String,
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

/// Percent encode a string for OAuth (RFC 3986)
#[must_use]
pub fn percent_encode(s: &str) -> String {
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

/// Generate a random nonce for OAuth
#[must_use]
pub fn generate_nonce() -> String {
    let mut nonce = String::with_capacity(32);
    for _ in 0..32 {
        let _ = write!(nonce, "{:x}", rand::random::<u8>() % 16);
    }
    nonce
}

/// Build OAuth parameter string from components
#[must_use]
pub fn build_oauth_params(
    consumer_key: &str,
    access_token: &str,
    timestamp: &str,
    nonce: &str,
) -> BTreeMap<String, String> {
    let mut params = BTreeMap::new();
    params.insert("oauth_consumer_key".to_string(), consumer_key.to_string());
    params.insert("oauth_nonce".to_string(), nonce.to_string());
    params.insert(
        "oauth_signature_method".to_string(),
        "HMAC-SHA256".to_string(),
    );
    params.insert("oauth_timestamp".to_string(), timestamp.to_string());
    params.insert("oauth_token".to_string(), access_token.to_string());
    params.insert("oauth_version".to_string(), "1.0".to_string());
    params
}

/// Generate OAuth signature base string
#[must_use]
pub fn build_signature_base_string(
    method: &str,
    url: &str,
    params: &BTreeMap<String, String>,
) -> String {
    let param_string: String = params
        .iter()
        .map(|(k, v)| format!("{}={}", percent_encode(k), percent_encode(v)))
        .collect::<Vec<_>>()
        .join("&");

    format!(
        "{}&{}&{}",
        method,
        percent_encode(url),
        percent_encode(&param_string)
    )
}

/// Generate HMAC-SHA256 signature
#[must_use]
pub fn generate_signature(base_string: &str, consumer_secret: &str, token_secret: &str) -> String {
    let signing_key = format!(
        "{}&{}",
        percent_encode(consumer_secret),
        percent_encode(token_secret)
    );

    let mut mac =
        HmacSha256::new_from_slice(signing_key.as_bytes()).expect("HMAC can take key of any size");
    mac.update(base_string.as_bytes());
    base64::engine::general_purpose::STANDARD.encode(mac.finalize().into_bytes())
}

/// Build OAuth authorization header value
#[must_use]
pub fn build_auth_header(
    consumer_key: &str,
    access_token: &str,
    signature: &str,
    timestamp: &str,
    nonce: &str,
) -> String {
    format!(
        r#"OAuth oauth_consumer_key="{}", oauth_nonce="{}", oauth_signature="{}", oauth_signature_method="HMAC-SHA256", oauth_timestamp="{}", oauth_token="{}", oauth_version="1.0""#,
        percent_encode(consumer_key),
        percent_encode(nonce),
        percent_encode(signature),
        percent_encode(timestamp),
        percent_encode(access_token),
    )
}

/// Generate OAuth 1.0a authorization header
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

    let nonce = generate_nonce();
    let params = build_oauth_params(consumer_key, access_token, &timestamp, &nonce);
    let base_string = build_signature_base_string(method, url, &params);
    let signature = generate_signature(&base_string, consumer_secret, access_token_secret);

    build_auth_header(consumer_key, access_token, &signature, &timestamp, &nonce)
}

/// Upload an image to X and return its media ID
///
/// # Errors
/// Returns error if upload fails
async fn upload_image(image_path: &Path, creds: &crate::config::XConfig) -> Result<String> {
    // Read and base64 encode the image
    let image_data = std::fs::read(image_path)
        .with_context(|| format!("Failed to read image: {}", image_path.display()))?;
    let media_data =
        base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &image_data);

    let auth_header = oauth_header(
        &creds.consumer_key,
        &creds.consumer_secret,
        &creds.access_token,
        &creds.access_token_secret,
        "POST",
        MEDIA_UPLOAD_URL,
    );

    let mut headers = HeaderMap::new();
    headers.insert(AUTHORIZATION, HeaderValue::from_str(&auth_header)?);
    headers.insert(
        CONTENT_TYPE,
        HeaderValue::from_static("application/x-www-form-urlencoded"),
    );

    let client = reqwest::Client::new();
    let response = client
        .post(MEDIA_UPLOAD_URL)
        .headers(headers)
        .form(&[("media_data", media_data)])
        .send()
        .await?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await?;
        anyhow::bail!("Failed to upload image: {status} - {body}");
    }

    let upload_response: MediaUploadResponse = response.json().await?;
    Ok(upload_response.media_id_string)
}

/// Post content to X
///
/// # Errors
/// Returns error if posting fails
pub async fn post(id: &str, dry_run: bool, custom_posts_path: Option<&Path>) -> Result<()> {
    let post_data = find_post_with_path(id, custom_posts_path)?;
    let content = post_data.x.trim();

    // Resolve image path relative to posts.yaml if present
    let image_path = if let Some(ref img) = post_data.image {
        let path = Path::new(img);
        if path.is_absolute() {
            Some(path.to_path_buf())
        } else {
            // Resolve relative to posts.yaml directory
            let posts_file = posts_path(custom_posts_path)?;
            posts_file.parent().map(|p| p.join(path))
        }
    } else {
        None
    };

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
        if let Some(ref img_path) = image_path {
            println!("Image: {}", img_path.display());
        }
        return Ok(());
    }

    let creds = load_x_creds()?;

    if creds.consumer_key.is_empty() {
        anyhow::bail!("X API credentials not found in pass royalbit/x");
    }

    // Upload image if present
    let media = if let Some(ref img_path) = image_path {
        println!("Uploading image: {}", img_path.display());
        let media_id = upload_image(img_path, &creds).await?;
        println!("Image uploaded: {media_id}");
        Some(TweetMedia {
            media_ids: vec![media_id],
        })
    } else {
        None
    };

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
        media,
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

        // Update posted timestamp
        let path = posts_path(custom_posts_path)?;
        if let Err(e) = update_posted_timestamp(id, Platform::X, &path) {
            eprintln!("Warning: Failed to update posted timestamp: {e}");
        }
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
pub async fn post_all(delay: u64, dry_run: bool, custom_posts_path: Option<&Path>) -> Result<()> {
    let all_posts = load_posts_with_path(custom_posts_path)?;
    let posts = filter_unposted(&all_posts, Platform::X);
    let skipped = all_posts.len() - posts.len();

    if skipped > 0 {
        println!("Skipping {skipped} already-posted item(s)");
    }

    if posts.is_empty() {
        println!("No unposted content for X.");
        return Ok(());
    }

    println!(
        "Posting {} item(s) with {delay}s delay between posts...",
        posts.len(),
    );

    if dry_run {
        println!("[DRY RUN MODE]");
    }

    for (i, p) in posts.iter().enumerate() {
        println!("\n[{}/{}] {}", i + 1, posts.len(), p.title);

        post(&p.id, dry_run, custom_posts_path).await?;

        if !dry_run && i < posts.len() - 1 {
            println!("Waiting {delay}s before next post...");
            tokio::time::sleep(Duration::from_secs(delay)).await;
        }
    }

    println!("\nDone!");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_percent_encode_unreserved() {
        // Unreserved characters should not be encoded
        assert_eq!(percent_encode("abc"), "abc");
        assert_eq!(percent_encode("ABC"), "ABC");
        assert_eq!(percent_encode("123"), "123");
        assert_eq!(percent_encode("-._~"), "-._~");
    }

    #[test]
    fn test_percent_encode_reserved() {
        assert_eq!(percent_encode(" "), "%20");
        assert_eq!(percent_encode("!"), "%21");
        assert_eq!(percent_encode("@"), "%40");
        assert_eq!(percent_encode("/"), "%2F");
        assert_eq!(percent_encode("="), "%3D");
        assert_eq!(percent_encode("&"), "%26");
    }

    #[test]
    fn test_percent_encode_mixed() {
        assert_eq!(percent_encode("hello world"), "hello%20world");
        assert_eq!(
            percent_encode("https://example.com"),
            "https%3A%2F%2Fexample.com"
        );
    }

    #[test]
    fn test_percent_encode_empty() {
        assert_eq!(percent_encode(""), "");
    }

    #[test]
    fn test_generate_nonce_length() {
        let nonce = generate_nonce();
        assert_eq!(nonce.len(), 32);
    }

    #[test]
    fn test_generate_nonce_hex() {
        let nonce = generate_nonce();
        assert!(nonce.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_generate_nonce_unique() {
        let nonce1 = generate_nonce();
        let nonce2 = generate_nonce();
        // Very unlikely to be equal
        assert_ne!(nonce1, nonce2);
    }

    #[test]
    fn test_build_oauth_params() {
        let params = build_oauth_params("consumer", "token", "1234567890", "nonce123");

        assert_eq!(
            params.get("oauth_consumer_key"),
            Some(&"consumer".to_string())
        );
        assert_eq!(params.get("oauth_token"), Some(&"token".to_string()));
        assert_eq!(
            params.get("oauth_timestamp"),
            Some(&"1234567890".to_string())
        );
        assert_eq!(params.get("oauth_nonce"), Some(&"nonce123".to_string()));
        assert_eq!(
            params.get("oauth_signature_method"),
            Some(&"HMAC-SHA256".to_string())
        );
        assert_eq!(params.get("oauth_version"), Some(&"1.0".to_string()));
    }

    #[test]
    fn test_build_signature_base_string() {
        let params = build_oauth_params("key", "token", "123", "nonce");
        let base = build_signature_base_string("POST", "https://api.example.com/endpoint", &params);

        assert!(base.starts_with("POST&"));
        assert!(base.contains("https%3A%2F%2Fapi.example.com%2Fendpoint"));
    }

    #[test]
    fn test_generate_signature() {
        // Test that signature is base64 encoded
        let signature = generate_signature("test base string", "consumer_secret", "token_secret");

        // Base64 should only contain alphanumeric, +, /, =
        assert!(signature
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '='));
    }

    #[test]
    fn test_generate_signature_deterministic() {
        // Same inputs should produce same signature
        let sig1 = generate_signature("base", "secret", "token");
        let sig2 = generate_signature("base", "secret", "token");
        assert_eq!(sig1, sig2);
    }

    #[test]
    fn test_generate_signature_different_inputs() {
        let sig1 = generate_signature("base1", "secret", "token");
        let sig2 = generate_signature("base2", "secret", "token");
        assert_ne!(sig1, sig2);
    }

    #[test]
    fn test_build_auth_header_format() {
        let header = build_auth_header("consumer_key", "access_token", "sig", "123", "nonce");

        assert!(header.starts_with("OAuth "));
        assert!(header.contains("oauth_consumer_key=\"consumer_key\""));
        assert!(header.contains("oauth_token=\"access_token\""));
        assert!(header.contains("oauth_signature=\"sig\""));
        assert!(header.contains("oauth_timestamp=\"123\""));
        assert!(header.contains("oauth_nonce=\"nonce\""));
        assert!(header.contains("oauth_signature_method=\"HMAC-SHA256\""));
        assert!(header.contains("oauth_version=\"1.0\""));
    }

    #[test]
    fn test_build_auth_header_encodes_special_chars() {
        let header = build_auth_header("key+value", "tok/en", "sig=nal", "123", "non ce");

        // Special characters should be percent-encoded
        assert!(header.contains("key%2Bvalue"));
        assert!(header.contains("tok%2Fen"));
        assert!(header.contains("sig%3Dnal"));
        assert!(header.contains("non%20ce"));
    }

    #[test]
    fn test_tweet_request_serialization() {
        let request = TweetRequest {
            text: "Hello, world!".to_string(),
            media: None,
        };

        let json = serde_json::to_string(&request).unwrap();
        assert_eq!(json, r#"{"text":"Hello, world!"}"#);
    }

    #[test]
    fn test_tweet_request_equality() {
        let req1 = TweetRequest {
            text: "test".to_string(),
            media: None,
        };
        let req2 = req1.clone();
        assert_eq!(req1, req2);
    }

    #[test]
    fn test_tweet_media_serialization() {
        let media = TweetMedia {
            media_ids: vec!["12345".to_string(), "67890".to_string()],
        };

        let json = serde_json::to_string(&media).unwrap();
        assert_eq!(json, r#"{"media_ids":["12345","67890"]}"#);
    }

    #[test]
    fn test_tweet_request_with_media() {
        let request = TweetRequest {
            text: "Check out this photo!".to_string(),
            media: Some(TweetMedia {
                media_ids: vec!["123456789".to_string()],
            }),
        };

        let json = serde_json::to_string(&request).unwrap();
        assert!(json.contains("\"text\":\"Check out this photo!\""));
        assert!(json.contains("\"media\":{\"media_ids\":[\"123456789\"]}"));
    }

    #[test]
    fn test_tweet_request_media_omitted_when_none() {
        let request = TweetRequest {
            text: "No media here".to_string(),
            media: None,
        };

        let json = serde_json::to_string(&request).unwrap();
        assert!(!json.contains("\"media\""));
        assert_eq!(json, r#"{"text":"No media here"}"#);
    }

    #[test]
    fn test_media_upload_response_deserialization() {
        let json = r#"{"media_id_string":"1234567890123456789"}"#;
        let response: MediaUploadResponse = serde_json::from_str(json).unwrap();
        assert_eq!(response.media_id_string, "1234567890123456789");
    }
}
