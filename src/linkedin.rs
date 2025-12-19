//! LinkedIn API integration
//!
//! Handles OAuth 2.0 authentication and posting via the Marketing API.

#![allow(clippy::doc_markdown)] // LinkedIn is a brand name, not code

use crate::config::{load_linkedin_creds, load_linkedin_token, save_linkedin_token, LinkedinToken};
use crate::posts::{find_post, load_posts};
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;
use std::time::Duration;
use url::Url;

const AUTH_URL: &str = "https://www.linkedin.com/oauth/v2/authorization";
const TOKEN_URL: &str = "https://www.linkedin.com/oauth/v2/accessToken";
const API_BASE: &str = "https://api.linkedin.com";
const REDIRECT_URI: &str = "http://localhost:8585/callback";
const SCOPES: &str = "openid profile w_member_social";

/// LinkedIn user profile response
#[derive(Debug, Deserialize)]
struct UserInfo {
    sub: String,
    name: Option<String>,
}

/// LinkedIn token response
#[derive(Debug, Deserialize)]
struct TokenResponse {
    access_token: String,
    #[allow(dead_code)]
    expires_in: u64,
}

/// LinkedIn post request
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct PostRequest {
    author: String,
    commentary: String,
    visibility: String,
    distribution: Distribution,
    lifecycle_state: String,
    is_reshare_disabled_by_author: bool,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
#[allow(clippy::struct_field_names)] // API field name
struct Distribution {
    feed_distribution: String,
    target_entities: Vec<String>,
    third_party_distribution_channels: Vec<String>,
}

/// Run OAuth 2.0 authentication flow
///
/// # Errors
/// Returns error if authentication fails at any step
pub async fn authenticate() -> Result<()> {
    let creds = load_linkedin_creds()?;

    let auth_url = format!(
        "{AUTH_URL}?response_type=code&client_id={}&redirect_uri={}&scope={}&state=daneel_poster",
        creds.client_id,
        urlencoding::encode(REDIRECT_URI),
        urlencoding::encode(SCOPES),
    );

    println!("Opening browser for LinkedIn authorization...");
    println!("If browser doesn't open, visit:\n{auth_url}\n");

    let _: Result<(), _> = open::that(&auth_url);

    let listener = TcpListener::bind("127.0.0.1:8585").context("Failed to bind to port 8585")?;

    println!("Waiting for authorization callback...");

    let (mut stream, _) = listener.accept()?;
    let mut reader = BufReader::new(&stream);
    let mut request_line = String::new();
    reader.read_line(&mut request_line)?;

    let code = extract_code(&request_line).context("Failed to extract authorization code")?;

    let response = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n\
        <html><body style='font-family:sans-serif;text-align:center;padding:50px'>\
        <h1>Authorization Successful!</h1>\
        <p>You can close this window and return to the terminal.</p>\
        </body></html>";
    stream.write_all(response.as_bytes())?;

    println!("Authorization code received. Exchanging for token...");

    let client = reqwest::Client::new();
    let token_response = client
        .post(TOKEN_URL)
        .form(&[
            ("grant_type", "authorization_code"),
            ("code", &code),
            ("redirect_uri", REDIRECT_URI),
            ("client_id", &creds.client_id),
            ("client_secret", &creds.client_secret),
        ])
        .send()
        .await?
        .json::<TokenResponse>()
        .await
        .context("Failed to exchange code for token")?;

    println!("Token obtained. Fetching profile...");

    let profile: UserInfo = client
        .get(format!("{API_BASE}/v2/userinfo"))
        .bearer_auth(&token_response.access_token)
        .send()
        .await?
        .json()
        .await
        .context("Failed to fetch profile")?;

    let person_urn = format!("urn:li:person:{}", profile.sub);

    println!(
        "Authenticated as: {}",
        profile.name.as_deref().unwrap_or("Unknown")
    );
    println!("Person URN: {person_urn}");

    let token = LinkedinToken {
        access_token: token_response.access_token,
        person_urn,
        saved_at: chrono::Utc::now().to_rfc3339(),
    };

    save_linkedin_token(&token)?;

    println!("\nAuthentication complete! You can now post to LinkedIn.");

    Ok(())
}

/// Extract authorization code from callback URL
fn extract_code(request_line: &str) -> Option<String> {
    let path = request_line.split_whitespace().nth(1)?;
    let url = Url::parse(&format!("http://localhost{path}")).ok()?;

    url.query_pairs()
        .find(|(k, _)| k == "code")
        .map(|(_, v)| v.to_string())
}

/// Post content to LinkedIn
///
/// # Errors
/// Returns error if posting fails
pub async fn post(id: &str, dry_run: bool) -> Result<()> {
    let post = find_post(id)?;
    let content = post.linkedin.trim();

    println!("Posting: {}", post.title);

    if dry_run {
        println!("\n[DRY RUN] Would post to LinkedIn:");
        println!("{}", "-".repeat(50));
        if content.len() > 500 {
            println!("{}...", &content[..500]);
        } else {
            println!("{content}");
        }
        println!("{}", "-".repeat(50));
        println!("Character count: {}", content.len());
        return Ok(());
    }

    let token = load_linkedin_token()?;

    let request = PostRequest {
        author: token.person_urn.clone(),
        commentary: content.to_string(),
        visibility: "PUBLIC".to_string(),
        distribution: Distribution {
            feed_distribution: "MAIN_FEED".to_string(),
            target_entities: vec![],
            third_party_distribution_channels: vec![],
        },
        lifecycle_state: "PUBLISHED".to_string(),
        is_reshare_disabled_by_author: false,
    };

    let client = reqwest::Client::new();
    let response = client
        .post(format!("{API_BASE}/rest/posts"))
        .bearer_auth(&token.access_token)
        .header("Content-Type", "application/json")
        .header("X-Restli-Protocol-Version", "2.0.0")
        .header("LinkedIn-Version", "202411")
        .json(&request)
        .send()
        .await?;

    if response.status().is_success() {
        let post_id = response
            .headers()
            .get("x-restli-id")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("unknown");

        println!("Posted successfully!");
        println!("Post ID: {post_id}");
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
