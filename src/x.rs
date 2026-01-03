//! X/Twitter API integration
//!
//! Handles posting via the X API v2 using OAuth 2.0 with PKCE.

use crate::config::{load_x_oauth2_creds, load_x_token, posts_path, save_x_token, XToken};
use crate::posts::{
    filter_unposted, find_post_with_path, load_posts_with_path, update_posted_timestamp, Platform,
};
use anyhow::{Context, Result};
use base64::Engine;
use rand::Rng;
use reqwest::header::{HeaderMap, HeaderValue, AUTHORIZATION, CONTENT_TYPE};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;
use std::path::Path;
use std::time::Duration;
use url::Url;

const AUTH_URL: &str = "https://x.com/i/oauth2/authorize";
const TOKEN_URL: &str = "https://api.x.com/2/oauth2/token";
const API_URL: &str = "https://api.x.com/2/tweets";
const USERS_ME_URL: &str = "https://api.x.com/2/users/me";
const MEDIA_UPLOAD_URL: &str = "https://upload.twitter.com/1.1/media/upload.json";
const REDIRECT_URI: &str = "http://localhost:8686/callback";
const SCOPES: &str = "tweet.read tweet.write users.read offline.access";

/// User timeline endpoint (requires user_id)
fn user_tweets_url(user_id: &str) -> String {
    format!("https://api.x.com/2/users/{user_id}/tweets")
}

/// Delete tweet endpoint (requires tweet_id)
fn delete_tweet_url(tweet_id: &str) -> String {
    format!("https://api.x.com/2/tweets/{tweet_id}")
}

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

/// Token response from OAuth 2.0
#[derive(Debug, Deserialize)]
struct TokenResponse {
    access_token: String,
    refresh_token: String,
    #[allow(dead_code)]
    expires_in: u64,
}

/// User info response
#[derive(Debug, Deserialize)]
struct UserResponse {
    data: UserData,
}

#[derive(Debug, Deserialize)]
struct UserData {
    id: String,
    username: String,
}

/// Timeline response from GET /users/{id}/tweets
#[derive(Debug, Deserialize)]
struct TimelineResponse {
    #[serde(default)]
    data: Vec<TimelineTweet>,
    meta: Option<TimelineMeta>,
}

#[derive(Debug, Deserialize)]
struct TimelineTweet {
    id: String,
    text: String,
    created_at: Option<String>,
}

#[derive(Debug, Deserialize)]
struct TimelineMeta {
    next_token: Option<String>,
    #[allow(dead_code)]
    result_count: u32,
}

/// Delete response from DELETE /tweets/{id}
#[derive(Debug, Deserialize)]
struct DeleteResponse {
    data: DeleteData,
}

#[derive(Debug, Deserialize)]
struct DeleteData {
    deleted: bool,
}

/// Generate a random code verifier for PKCE (43-128 chars)
fn generate_code_verifier() -> String {
    let mut rng = rand::rng();
    let bytes: Vec<u8> = (0..32).map(|_| rng.random::<u8>()).collect();
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&bytes)
}

/// Generate code challenge from verifier (S256 method)
fn generate_code_challenge(verifier: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(verifier.as_bytes());
    let hash = hasher.finalize();
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(hash)
}

/// Run OAuth 2.0 authentication flow with PKCE
///
/// # Errors
/// Returns error if authentication fails at any step
pub async fn authenticate() -> Result<()> {
    let creds = load_x_oauth2_creds()?;

    let code_verifier = generate_code_verifier();
    let code_challenge = generate_code_challenge(&code_verifier);

    // Generate random state for CSRF protection
    let mut state = String::with_capacity(16);
    for _ in 0..16 {
        use std::fmt::Write;
        let _ = write!(state, "{:x}", rand::random::<u8>() % 16);
    }

    let auth_url = format!(
        "{AUTH_URL}?response_type=code&client_id={}&redirect_uri={}&scope={}&state={state}&code_challenge={code_challenge}&code_challenge_method=S256",
        creds.client_id,
        urlencoding::encode(REDIRECT_URI),
        urlencoding::encode(SCOPES),
    );

    println!("Opening browser for X authorization...");
    println!("If browser doesn't open, visit:\n{auth_url}\n");

    let _: Result<(), _> = open::that(&auth_url);

    let listener = TcpListener::bind("127.0.0.1:8686").context("Failed to bind to port 8686")?;

    println!("Waiting for authorization callback...");

    let (mut stream, _) = listener.accept()?;
    let mut reader = BufReader::new(&stream);
    let mut request_line = String::new();
    reader.read_line(&mut request_line)?;

    let (code, returned_state) =
        extract_code_and_state(&request_line).context("Failed to extract authorization code")?;

    // Verify state matches
    if returned_state != state {
        anyhow::bail!("State mismatch - possible CSRF attack");
    }

    let response = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n\
        <html><body style='font-family:sans-serif;text-align:center;padding:50px'>\
        <h1>Authorization Successful!</h1>\
        <p>You can close this window and return to the terminal.</p>\
        </body></html>";
    stream.write_all(response.as_bytes())?;

    println!("Authorization code received. Exchanging for token...");

    let client = reqwest::Client::new();

    // Build token request - use Basic auth for confidential clients
    let mut request = client.post(TOKEN_URL).form(&[
        ("grant_type", "authorization_code"),
        ("code", &code),
        ("redirect_uri", REDIRECT_URI),
        ("code_verifier", &code_verifier),
    ]);

    // Add client credentials
    if let Some(ref secret) = creds.client_secret {
        // Confidential client: use Basic auth
        request = request.basic_auth(&creds.client_id, Some(secret));
    } else {
        // Public client: include client_id in body
        request = request.form(&[("client_id", &creds.client_id)]);
    }

    let token_response = request.send().await?;

    if !token_response.status().is_success() {
        let status = token_response.status();
        let body = token_response.text().await?;
        anyhow::bail!("Token exchange failed: {status} - {body}");
    }

    let token_data: TokenResponse = token_response
        .json()
        .await
        .context("Failed to parse token response")?;

    println!("Token obtained. Fetching profile...");

    // Get user info
    let user_response = client
        .get(USERS_ME_URL)
        .bearer_auth(&token_data.access_token)
        .send()
        .await?;

    if !user_response.status().is_success() {
        let status = user_response.status();
        let body = user_response.text().await?;
        anyhow::bail!("Failed to fetch profile: {status} - {body}");
    }

    let user_data: UserResponse = user_response
        .json()
        .await
        .context("Failed to parse user response")?;

    println!("Authenticated as: @{}", user_data.data.username);

    let token = XToken {
        access_token: token_data.access_token,
        refresh_token: token_data.refresh_token,
        user_id: user_data.data.id,
        username: user_data.data.username,
        saved_at: chrono::Utc::now().to_rfc3339(),
    };

    save_x_token(&token)?;

    println!("\nAuthentication complete! You can now post to X.");

    Ok(())
}

/// Extract authorization code and state from callback URL
fn extract_code_and_state(request_line: &str) -> Option<(String, String)> {
    let path = request_line.split_whitespace().nth(1)?;
    let url = Url::parse(&format!("http://localhost{path}")).ok()?;

    let code = url
        .query_pairs()
        .find(|(k, _)| k == "code")
        .map(|(_, v)| v.to_string())?;

    let state = url
        .query_pairs()
        .find(|(k, _)| k == "state")
        .map(|(_, v)| v.to_string())?;

    Some((code, state))
}

/// Refresh the access token using refresh token
///
/// # Errors
/// Returns error if refresh fails
async fn refresh_token(token: &XToken) -> Result<XToken> {
    let creds = load_x_oauth2_creds()?;
    let client = reqwest::Client::new();

    // Build refresh request - use Basic auth for confidential clients
    let mut request = client.post(TOKEN_URL).form(&[
        ("grant_type", "refresh_token"),
        ("refresh_token", &token.refresh_token),
    ]);

    // Add client credentials
    if let Some(ref secret) = creds.client_secret {
        request = request.basic_auth(&creds.client_id, Some(secret));
    } else {
        request = request.form(&[("client_id", &creds.client_id)]);
    }

    let response = request.send().await?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await?;
        anyhow::bail!(
            "Token refresh failed: {status} - {body}\n\nRun 'poster x auth' to re-authenticate."
        );
    }

    let token_data: TokenResponse = response.json().await?;

    let new_token = XToken {
        access_token: token_data.access_token,
        refresh_token: token_data.refresh_token,
        user_id: token.user_id.clone(),
        username: token.username.clone(),
        saved_at: chrono::Utc::now().to_rfc3339(),
    };

    save_x_token(&new_token)?;
    println!("Token refreshed.");

    Ok(new_token)
}

/// Get a valid access token, refreshing if needed
async fn get_valid_token() -> Result<XToken> {
    let token = load_x_token()?;

    // Try a simple API call to check if token is valid
    let client = reqwest::Client::new();
    let response = client
        .get(USERS_ME_URL)
        .bearer_auth(&token.access_token)
        .send()
        .await?;

    if response.status().is_success() {
        return Ok(token);
    }

    // Token expired, try to refresh
    if response.status() == 401 {
        println!("Access token expired, refreshing...");
        return refresh_token(&token).await;
    }

    let status = response.status();
    let body = response.text().await?;
    anyhow::bail!("API error: {status} - {body}");
}

/// Upload an image to X and return its media ID
///
/// Note: Media upload still uses v1.1 API which requires app-level auth
/// For now, we'll skip media upload with OAuth 2.0 user tokens
///
/// # Errors
/// Returns error if upload fails
async fn upload_image(image_path: &Path, token: &XToken) -> Result<String> {
    // Read and base64 encode the image
    let image_data = std::fs::read(image_path)
        .with_context(|| format!("Failed to read image: {}", image_path.display()))?;
    let media_data =
        base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &image_data);

    // v1.1 media upload with OAuth 2.0 Bearer token
    let mut headers = HeaderMap::new();
    headers.insert(
        AUTHORIZATION,
        HeaderValue::from_str(&format!("Bearer {}", token.access_token))?,
    );
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
        println!("\n--- DRY RUN ---");
        println!("Content ({} chars):\n{content}", content.len());
        if let Some(ref path) = image_path {
            println!("Image: {}", path.display());
        }
        println!("--- END DRY RUN ---");
        return Ok(());
    }

    let token = get_valid_token().await?;

    // Upload image if present
    let media_id = if let Some(ref path) = image_path {
        println!("Uploading image: {}", path.display());
        match upload_image(path, &token).await {
            Ok(id) => Some(id),
            Err(e) => {
                // Media upload may fail with OAuth 2.0 - warn but continue
                println!("Warning: Image upload failed (may require OAuth 1.0a): {e}");
                println!("Posting without image...");
                None
            }
        }
    } else {
        None
    };

    let request = TweetRequest {
        text: content.to_string(),
        media: media_id.map(|id| TweetMedia {
            media_ids: vec![id],
        }),
    };

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()?;

    let response = client
        .post(API_URL)
        .bearer_auth(&token.access_token)
        .json(&request)
        .send()
        .await?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await?;
        anyhow::bail!("Failed to post: {status} - {body}");
    }

    let tweet: TweetResponse = response.json().await?;
    println!("Posted successfully!");
    println!("https://x.com/{}/status/{}", token.username, tweet.data.id);

    // Update posted timestamp
    let path = posts_path(custom_posts_path)?;
    if let Err(e) = update_posted_timestamp(id, Platform::X, &path) {
        eprintln!("Warning: Failed to update posted timestamp: {e}");
    }

    Ok(())
}

/// Post all unposted content with delay
///
/// # Errors
/// Returns error if posting fails
pub async fn post_all(
    delay_secs: u64,
    dry_run: bool,
    custom_posts_path: Option<&Path>,
) -> Result<()> {
    let all_posts = load_posts_with_path(custom_posts_path)?;
    let posts = filter_unposted(&all_posts, Platform::X);

    if posts.is_empty() {
        let skipped = all_posts.len();
        if skipped > 0 {
            println!("All {skipped} posts already posted to X. Nothing to do.");
        } else {
            println!("No posts found.");
        }
        return Ok(());
    }

    let skipped = all_posts.len() - posts.len();
    if skipped > 0 {
        println!("Skipping {skipped} already-posted entries.");
    }

    println!("Posting {} items to X...\n", posts.len());

    for (i, post_data) in posts.iter().enumerate() {
        if i > 0 {
            println!("\nWaiting {delay_secs}s before next post...\n");
            tokio::time::sleep(Duration::from_secs(delay_secs)).await;
        }
        post(&post_data.id, dry_run, custom_posts_path).await?;
    }

    Ok(())
}

/// List recent tweets for the authenticated user
///
/// # Errors
/// Returns error if API call fails
pub async fn list_tweets(limit: u32) -> Result<()> {
    let token = get_valid_token().await?;
    let client = reqwest::Client::new();

    let mut all_tweets: Vec<TimelineTweet> = Vec::new();
    let mut pagination_token: Option<String> = None;
    let per_page = std::cmp::min(limit, 100); // API max is 100 per request

    println!("Fetching tweets for @{}...\n", token.username);

    loop {
        let mut url = format!(
            "{}?max_results={}&tweet.fields=created_at",
            user_tweets_url(&token.user_id),
            per_page
        );

        if let Some(ref next_token) = pagination_token {
            use std::fmt::Write;
            let _ = write!(url, "&pagination_token={next_token}");
        }

        let response = client
            .get(&url)
            .bearer_auth(&token.access_token)
            .send()
            .await?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await?;
            anyhow::bail!("Failed to fetch tweets: {status} - {body}");
        }

        let timeline: TimelineResponse = response.json().await?;

        all_tweets.extend(timeline.data);

        // Check if we have enough or no more pages
        #[allow(clippy::cast_possible_truncation)]
        let fetched = all_tweets.len() as u32; // Safe: limit is u32, we truncate at limit
        if fetched >= limit {
            all_tweets.truncate(limit as usize);
            break;
        }

        match timeline.meta.and_then(|m| m.next_token) {
            Some(next) => pagination_token = Some(next),
            None => break,
        }
    }

    if all_tweets.is_empty() {
        println!("No tweets found.");
        return Ok(());
    }

    println!("Found {} tweets:\n", all_tweets.len());
    for tweet in &all_tweets {
        let date = tweet.created_at.as_deref().unwrap_or("unknown");
        let text_preview: String = tweet.text.chars().take(60).collect();
        let ellipsis = if tweet.text.len() > 60 { "..." } else { "" };
        println!("{} | {} | {}{}", tweet.id, date, text_preview, ellipsis);
    }

    Ok(())
}

/// Delete a single tweet by ID
///
/// # Errors
/// Returns error if deletion fails
pub async fn delete_tweet(tweet_id: &str) -> Result<()> {
    let token = get_valid_token().await?;
    let client = reqwest::Client::new();

    println!("Deleting tweet {tweet_id}...");

    let response = client
        .delete(delete_tweet_url(tweet_id))
        .bearer_auth(&token.access_token)
        .send()
        .await?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await?;
        anyhow::bail!("Failed to delete tweet: {status} - {body}");
    }

    let result: DeleteResponse = response.json().await?;

    if result.data.deleted {
        println!("Tweet {tweet_id} deleted successfully.");
    } else {
        println!("Tweet {tweet_id} was not deleted (may already be gone).");
    }

    Ok(())
}

/// Delete all tweets for the authenticated user
///
/// # Errors
/// Returns error if deletion fails
#[allow(clippy::too_many_lines)]
pub async fn delete_all_tweets(dry_run: bool, skip_confirm: bool, delay_ms: u64) -> Result<()> {
    let token = get_valid_token().await?;
    let client = reqwest::Client::new();

    // First, fetch all tweets
    println!("Fetching all tweets for @{}...", token.username);

    let mut all_tweets: Vec<TimelineTweet> = Vec::new();
    let mut pagination_token: Option<String> = None;

    loop {
        let mut url = format!(
            "{}?max_results=100&tweet.fields=created_at",
            user_tweets_url(&token.user_id)
        );

        if let Some(ref next_token) = pagination_token {
            use std::fmt::Write;
            let _ = write!(url, "&pagination_token={next_token}");
        }

        let response = client
            .get(&url)
            .bearer_auth(&token.access_token)
            .send()
            .await?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await?;
            anyhow::bail!("Failed to fetch tweets: {status} - {body}");
        }

        let timeline: TimelineResponse = response.json().await?;
        let count = timeline.data.len();
        all_tweets.extend(timeline.data);

        println!(
            "  Fetched {} tweets (total: {})...",
            count,
            all_tweets.len()
        );

        match timeline.meta.and_then(|m| m.next_token) {
            Some(next) => pagination_token = Some(next),
            None => break,
        }
    }

    if all_tweets.is_empty() {
        println!("\nNo tweets found. Nothing to delete.");
        return Ok(());
    }

    println!("\nFound {} tweets to delete.", all_tweets.len());

    if dry_run {
        println!("\n--- DRY RUN ---");
        println!("Would delete {} tweets:", all_tweets.len());
        for (i, tweet) in all_tweets.iter().enumerate().take(10) {
            let text_preview: String = tweet.text.chars().take(50).collect();
            println!("  {}. {} - {}...", i + 1, tweet.id, text_preview);
        }
        if all_tweets.len() > 10 {
            println!("  ... and {} more", all_tweets.len() - 10);
        }
        println!("--- END DRY RUN ---");
        return Ok(());
    }

    // Confirm unless --yes flag
    if !skip_confirm {
        println!(
            "\nThis will permanently delete {} tweets. This cannot be undone!",
            all_tweets.len()
        );
        print!("Type 'DELETE' to confirm: ");
        std::io::Write::flush(&mut std::io::stdout())?;

        let mut input = String::new();
        std::io::stdin().read_line(&mut input)?;

        if input.trim() != "DELETE" {
            println!("Aborted.");
            return Ok(());
        }
    }

    println!("\nDeleting {} tweets...", all_tweets.len());

    let mut deleted = 0;
    let mut failed = 0;

    for (i, tweet) in all_tweets.iter().enumerate() {
        if i > 0 && delay_ms > 0 {
            tokio::time::sleep(Duration::from_millis(delay_ms)).await;
        }

        let response = client
            .delete(delete_tweet_url(&tweet.id))
            .bearer_auth(&token.access_token)
            .send()
            .await;

        match response {
            Ok(resp) if resp.status().is_success() => {
                deleted += 1;
                if deleted % 10 == 0 || deleted == all_tweets.len() {
                    println!("  Deleted {}/{}", deleted, all_tweets.len());
                }
            }
            Ok(resp) => {
                let status = resp.status();
                // Rate limit handling
                if status == 429 {
                    println!("  Rate limited, waiting 60s...");
                    tokio::time::sleep(Duration::from_secs(60)).await;
                    // Retry this one
                    let retry = client
                        .delete(delete_tweet_url(&tweet.id))
                        .bearer_auth(&token.access_token)
                        .send()
                        .await;
                    if retry.is_ok_and(|r| r.status().is_success()) {
                        deleted += 1;
                    } else {
                        failed += 1;
                    }
                } else {
                    eprintln!("  Failed to delete {}: {}", tweet.id, status);
                    failed += 1;
                }
            }
            Err(e) => {
                eprintln!("  Error deleting {}: {}", tweet.id, e);
                failed += 1;
            }
        }
    }

    println!("\nDone! Deleted: {deleted}, Failed: {failed}");

    if failed > 0 {
        println!("Note: Some deletions failed. Run again to retry.");
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_code_verifier_length() {
        let verifier = generate_code_verifier();
        // 32 bytes base64 encoded = 43 chars
        assert!(verifier.len() >= 43);
    }

    #[test]
    fn test_generate_code_challenge() {
        let verifier = "test_verifier_string";
        let challenge = generate_code_challenge(verifier);
        // Should be base64url encoded SHA256 hash
        assert!(!challenge.is_empty());
        assert!(!challenge.contains('=')); // URL-safe no padding
    }

    #[test]
    fn test_extract_code_and_state() {
        let request = "GET /callback?code=abc123&state=xyz789 HTTP/1.1";
        let result = extract_code_and_state(request);
        assert!(result.is_some());
        let (code, state) = result.unwrap();
        assert_eq!(code, "abc123");
        assert_eq!(state, "xyz789");
    }

    #[test]
    fn test_extract_code_and_state_missing_code() {
        let request = "GET /callback?state=xyz789 HTTP/1.1";
        let result = extract_code_and_state(request);
        assert!(result.is_none());
    }

    #[test]
    fn test_extract_code_and_state_missing_state() {
        let request = "GET /callback?code=abc123 HTTP/1.1";
        let result = extract_code_and_state(request);
        assert!(result.is_none());
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

    #[test]
    fn test_user_tweets_url() {
        let url = user_tweets_url("12345");
        assert_eq!(url, "https://api.x.com/2/users/12345/tweets");
    }

    #[test]
    fn test_delete_tweet_url() {
        let url = delete_tweet_url("98765");
        assert_eq!(url, "https://api.x.com/2/tweets/98765");
    }

    #[test]
    fn test_timeline_response_deserialization() {
        let json = r#"{
            "data": [
                {"id": "123", "text": "Hello world"},
                {"id": "456", "text": "Another tweet", "created_at": "2024-01-15T10:30:00Z"}
            ],
            "meta": {"next_token": "abc123", "result_count": 2}
        }"#;
        let response: TimelineResponse = serde_json::from_str(json).unwrap();
        assert_eq!(response.data.len(), 2);
        assert_eq!(response.data[0].id, "123");
        assert_eq!(response.data[0].text, "Hello world");
        assert!(response.data[0].created_at.is_none());
        assert_eq!(
            response.data[1].created_at.as_deref(),
            Some("2024-01-15T10:30:00Z")
        );
        assert_eq!(
            response.meta.as_ref().unwrap().next_token.as_deref(),
            Some("abc123")
        );
        assert_eq!(response.meta.as_ref().unwrap().result_count, 2);
    }

    #[test]
    fn test_timeline_response_empty() {
        let json = r#"{"meta": {"result_count": 0}}"#;
        let response: TimelineResponse = serde_json::from_str(json).unwrap();
        assert!(response.data.is_empty());
    }

    #[test]
    fn test_delete_response_deserialization() {
        let json = r#"{"data": {"deleted": true}}"#;
        let response: DeleteResponse = serde_json::from_str(json).unwrap();
        assert!(response.data.deleted);

        let json = r#"{"data": {"deleted": false}}"#;
        let response: DeleteResponse = serde_json::from_str(json).unwrap();
        assert!(!response.data.deleted);
    }
}
