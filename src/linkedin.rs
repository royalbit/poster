//! LinkedIn API integration
//!
//! Handles OAuth 2.0 authentication and posting via the Marketing API.

#![allow(clippy::doc_markdown)] // LinkedIn is a brand name, not code

use crate::config::{
    load_linkedin_creds, load_linkedin_token, posts_path, save_linkedin_token, LinkedinToken,
};
use crate::posts::{
    filter_unposted, find_post_with_path, load_posts_with_path, update_posted_timestamp, Platform,
};
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;
use std::path::Path;
use std::time::Duration;
use url::Url;

const AUTH_URL: &str = "https://www.linkedin.com/oauth/v2/authorization";
const TOKEN_URL: &str = "https://www.linkedin.com/oauth/v2/accessToken";
const API_BASE: &str = "https://api.linkedin.com";
const REDIRECT_URI: &str = "http://localhost:8585/callback";
const SCOPES: &str = "openid profile w_member_social";

/// LinkedIn user profile response from /v2/userinfo
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
    /// ID token (JWT) returned when using OpenID Connect scopes
    id_token: Option<String>,
}

/// JWT claims from id_token
#[derive(Debug, Deserialize)]
struct IdTokenClaims {
    sub: String,
    name: Option<String>,
}

/// LinkedIn post request
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct PostRequest {
    author: String,
    commentary: String,
    visibility: String,
    distribution: Distribution,
    #[serde(skip_serializing_if = "Option::is_none")]
    content: Option<PostContent>,
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

/// Content with media for LinkedIn posts
#[derive(Debug, Serialize)]
struct PostContent {
    media: MediaContent,
}

/// Media content for LinkedIn posts
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct MediaContent {
    alt_text: String,
    id: String,
}

/// Response from image upload initialization
#[derive(Debug, Deserialize)]
struct InitializeUploadResponse {
    value: UploadValue,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct UploadValue {
    upload_url: String,
    image: String,
}

/// Run OAuth 2.0 authentication flow
///
/// # Errors
/// Returns error if authentication fails at any step
#[allow(clippy::too_many_lines)]
pub async fn authenticate() -> Result<()> {
    let creds = load_linkedin_creds()?;

    let auth_url = format!(
        "{AUTH_URL}?response_type=code&client_id={}&redirect_uri={}&scope={}&state=royalbit_poster",
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

    // Try to extract sub from id_token (JWT) first
    let (sub, _name) = if let Some(id_token) = &token_response.id_token {
        // JWT format: header.payload.signature - decode the payload
        let parts: Vec<&str> = id_token.split('.').collect();
        if parts.len() >= 2 {
            // Add padding if needed for base64 decoding
            let payload = parts[1];
            let padded = match payload.len() % 4 {
                2 => format!("{payload}=="),
                3 => format!("{payload}="),
                _ => payload.to_string(),
            };
            match base64::Engine::decode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, &padded)
                .or_else(|_| {
                    base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &padded)
                }) {
                Ok(decoded) => match serde_json::from_slice::<IdTokenClaims>(&decoded) {
                    Ok(claims) => {
                        println!(
                            "Authenticated as: {}",
                            claims.name.as_deref().unwrap_or("Unknown")
                        );
                        (claims.sub, claims.name)
                    }
                    Err(e) => anyhow::bail!("Failed to parse id_token claims: {e}"),
                },
                Err(e) => anyhow::bail!("Failed to decode id_token: {e}"),
            }
        } else {
            anyhow::bail!("Invalid id_token format");
        }
    } else {
        // Fallback to userinfo endpoint
        let profile_resp = client
            .get(format!("{API_BASE}/v2/userinfo"))
            .bearer_auth(&token_response.access_token)
            .send()
            .await
            .context("Failed to fetch profile")?;

        if !profile_resp.status().is_success() {
            let status = profile_resp.status();
            let body = profile_resp.text().await?;
            anyhow::bail!("Failed to fetch profile: {status} - {body}\n\nMake sure 'Sign In with LinkedIn using OpenID Connect' product is added to your app.");
        }

        let profile: UserInfo = profile_resp
            .json()
            .await
            .context("Failed to parse profile")?;
        println!(
            "Authenticated as: {}",
            profile.name.as_deref().unwrap_or("Unknown")
        );
        (profile.sub, profile.name)
    };

    let person_urn = format!("urn:li:person:{sub}");

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

/// Upload an image to LinkedIn and return its URN
///
/// # Errors
/// Returns error if upload fails
async fn upload_image(image_path: &Path, token: &LinkedinToken) -> Result<String> {
    let client = reqwest::Client::new();

    // Read image file
    let image_data = std::fs::read(image_path)
        .with_context(|| format!("Failed to read image: {}", image_path.display()))?;

    // Initialize upload
    let init_body = serde_json::json!({
        "initializeUploadRequest": {
            "owner": token.person_urn
        }
    });

    let init_response = client
        .post(format!("{API_BASE}/rest/images?action=initializeUpload"))
        .bearer_auth(&token.access_token)
        .header("Content-Type", "application/json")
        .header("X-Restli-Protocol-Version", "2.0.0")
        .header("LinkedIn-Version", "202411")
        .json(&init_body)
        .send()
        .await?;

    if !init_response.status().is_success() {
        let status = init_response.status();
        let body = init_response.text().await?;
        anyhow::bail!("Failed to initialize image upload: {status} - {body}");
    }

    let upload_info: InitializeUploadResponse = init_response.json().await?;

    // Upload the image binary
    let upload_response = client
        .put(&upload_info.value.upload_url)
        .header("Content-Type", "application/octet-stream")
        .body(image_data)
        .send()
        .await?;

    if !upload_response.status().is_success() {
        let status = upload_response.status();
        let body = upload_response.text().await?;
        anyhow::bail!("Failed to upload image: {status} - {body}");
    }

    Ok(upload_info.value.image)
}

/// Post content to LinkedIn
///
/// # Errors
/// Returns error if posting fails or content contains parentheses
pub async fn post(id: &str, dry_run: bool, custom_posts_path: Option<&Path>) -> Result<()> {
    let post_data = find_post_with_path(id, custom_posts_path)?;
    let content = post_data.linkedin.trim();

    // LinkedIn's "little text format" interprets "text (foo)" as a malformed link "[text](foo)"
    // which causes post truncation. Reject posts with parentheses.
    if content.contains('(') || content.contains(')') {
        anyhow::bail!(
            "LinkedIn post contains parentheses which cause truncation.\n\
             Rephrase using dashes instead: \"foo (bar)\" → \"foo - bar\""
        );
    }

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
        if let Some(ref img_path) = image_path {
            println!("Image: {}", img_path.display());
        }
        return Ok(());
    }

    let token = load_linkedin_token()?;

    // Upload image if present
    let media_content = if let Some(ref img_path) = image_path {
        println!("Uploading image: {}", img_path.display());
        let image_urn = upload_image(img_path, &token).await?;
        println!("Image uploaded: {image_urn}");
        Some(PostContent {
            media: MediaContent {
                alt_text: post_data.title.clone(),
                id: image_urn,
            },
        })
    } else {
        None
    };

    let request = PostRequest {
        author: token.person_urn.clone(),
        commentary: content.to_string(),
        visibility: "PUBLIC".to_string(),
        distribution: Distribution {
            feed_distribution: "MAIN_FEED".to_string(),
            target_entities: vec![],
            third_party_distribution_channels: vec![],
        },
        content: media_content,
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
        let rest_id = response
            .headers()
            .get("x-restli-id")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("unknown");

        println!("Posted successfully!");
        println!("Post ID: {rest_id}");

        // Update posted timestamp
        let path = posts_path(custom_posts_path)?;
        if let Err(e) = update_posted_timestamp(id, Platform::LinkedIn, &path) {
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
    let posts = filter_unposted(&all_posts, Platform::LinkedIn);
    let skipped = all_posts.len() - posts.len();

    if skipped > 0 {
        println!("Skipping {skipped} already-posted item(s)");
    }

    if posts.is_empty() {
        println!("No unposted content for LinkedIn.");
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

    /// Build authorization URL for LinkedIn OAuth (test helper)
    fn build_auth_url(client_id: &str) -> String {
        format!(
            "{AUTH_URL}?response_type=code&client_id={client_id}&redirect_uri={}&scope={}&state=royalbit_poster",
            urlencoding::encode(REDIRECT_URI),
            urlencoding::encode(SCOPES),
        )
    }

    /// Build person URN from subject ID (test helper)
    fn build_person_urn(sub: &str) -> String {
        format!("urn:li:person:{sub}")
    }

    #[test]
    fn test_extract_code_valid() {
        let request_line = "GET /callback?code=AQR1234567890&state=royalbit_poster HTTP/1.1";
        let code = extract_code(request_line);
        assert_eq!(code, Some("AQR1234567890".to_string()));
    }

    #[test]
    fn test_extract_code_with_other_params() {
        let request_line = "GET /callback?state=royalbit_poster&code=ABC123&other=value HTTP/1.1";
        let code = extract_code(request_line);
        assert_eq!(code, Some("ABC123".to_string()));
    }

    #[test]
    fn test_extract_code_no_code() {
        let request_line = "GET /callback?state=royalbit_poster HTTP/1.1";
        let code = extract_code(request_line);
        assert!(code.is_none());
    }

    #[test]
    fn test_extract_code_malformed_request() {
        let request_line = "malformed request";
        let code = extract_code(request_line);
        assert!(code.is_none());
    }

    #[test]
    fn test_extract_code_empty() {
        let code = extract_code("");
        assert!(code.is_none());
    }

    #[test]
    fn test_build_auth_url() {
        let url = build_auth_url("test-client-id");
        assert!(url.contains("client_id=test-client-id"));
        assert!(url.contains("response_type=code"));
        assert!(url.contains("redirect_uri="));
        assert!(url.contains("scope="));
        assert!(url.contains("state=royalbit_poster"));
    }

    #[test]
    fn test_build_person_urn() {
        let urn = build_person_urn("abc123");
        assert_eq!(urn, "urn:li:person:abc123");
    }

    #[test]
    fn test_post_request_serialization() {
        let request = PostRequest {
            author: "urn:li:person:123".to_string(),
            commentary: "Test post".to_string(),
            visibility: "PUBLIC".to_string(),
            distribution: Distribution {
                feed_distribution: "MAIN_FEED".to_string(),
                target_entities: vec![],
                third_party_distribution_channels: vec![],
            },
            lifecycle_state: "PUBLISHED".to_string(),
            is_reshare_disabled_by_author: false,
            content: None,
        };

        let json = serde_json::to_string(&request).unwrap();

        // Check camelCase conversion
        assert!(json.contains("\"author\""));
        assert!(json.contains("\"commentary\""));
        assert!(json.contains("\"visibility\""));
        assert!(json.contains("\"distribution\""));
        assert!(json.contains("\"lifecycleState\""));
        assert!(json.contains("\"isReshareDisabledByAuthor\""));
        assert!(json.contains("\"feedDistribution\""));
        assert!(json.contains("\"targetEntities\""));
        assert!(json.contains("\"thirdPartyDistributionChannels\""));
    }

    #[test]
    fn test_distribution_serialization() {
        let dist = Distribution {
            feed_distribution: "MAIN_FEED".to_string(),
            target_entities: vec!["entity1".to_string()],
            third_party_distribution_channels: vec![],
        };

        let json = serde_json::to_string(&dist).unwrap();
        assert!(json.contains("\"feedDistribution\":\"MAIN_FEED\""));
        assert!(json.contains("\"targetEntities\":[\"entity1\"]"));
        assert!(json.contains("\"thirdPartyDistributionChannels\":[]"));
    }

    #[test]
    fn test_user_info_deserialization() {
        let json = r#"{"sub":"abc123","name":"Test User"}"#;
        let info: UserInfo = serde_json::from_str(json).unwrap();
        assert_eq!(info.sub, "abc123");
        assert_eq!(info.name, Some("Test User".to_string()));
    }

    #[test]
    fn test_user_info_deserialization_no_name() {
        let json = r#"{"sub":"abc123"}"#;
        let info: UserInfo = serde_json::from_str(json).unwrap();
        assert_eq!(info.sub, "abc123");
        assert!(info.name.is_none());
    }

    #[test]
    fn test_token_response_deserialization() {
        let json = r#"{"access_token":"token123","expires_in":3600}"#;
        let response: TokenResponse = serde_json::from_str(json).unwrap();
        assert_eq!(response.access_token, "token123");
        assert_eq!(response.expires_in, 3600);
    }

    #[test]
    fn test_constants() {
        assert!(AUTH_URL.starts_with("https://"));
        assert!(TOKEN_URL.starts_with("https://"));
        assert!(API_BASE.starts_with("https://"));
        assert!(REDIRECT_URI.contains("localhost"));
        assert!(SCOPES.contains("profile"));
    }

    #[test]
    fn test_media_content_serialization() {
        let media = MediaContent {
            alt_text: "An example image".to_string(),
            id: "urn:li:image:12345".to_string(),
        };

        let json = serde_json::to_string(&media).unwrap();
        assert!(json.contains("\"altText\":\"An example image\""));
        assert!(json.contains("\"id\":\"urn:li:image:12345\""));
    }

    #[test]
    fn test_post_content_serialization() {
        let content = PostContent {
            media: MediaContent {
                alt_text: "Test alt".to_string(),
                id: "urn:li:image:999".to_string(),
            },
        };

        let json = serde_json::to_string(&content).unwrap();
        assert!(json.contains("\"media\":{"));
        assert!(json.contains("\"altText\":\"Test alt\""));
        assert!(json.contains("\"id\":\"urn:li:image:999\""));
    }

    #[test]
    fn test_post_request_with_content() {
        let request = PostRequest {
            author: "urn:li:person:123".to_string(),
            commentary: "Check out this image!".to_string(),
            visibility: "PUBLIC".to_string(),
            distribution: Distribution {
                feed_distribution: "MAIN_FEED".to_string(),
                target_entities: vec![],
                third_party_distribution_channels: vec![],
            },
            lifecycle_state: "PUBLISHED".to_string(),
            is_reshare_disabled_by_author: false,
            content: Some(PostContent {
                media: MediaContent {
                    alt_text: "My image".to_string(),
                    id: "urn:li:image:abc".to_string(),
                },
            }),
        };

        let json = serde_json::to_string(&request).unwrap();
        assert!(json.contains("\"content\":{"));
        assert!(json.contains("\"media\":{"));
        assert!(json.contains("\"altText\":\"My image\""));
    }

    #[test]
    fn test_post_request_content_omitted_when_none() {
        let request = PostRequest {
            author: "urn:li:person:123".to_string(),
            commentary: "No image".to_string(),
            visibility: "PUBLIC".to_string(),
            distribution: Distribution {
                feed_distribution: "MAIN_FEED".to_string(),
                target_entities: vec![],
                third_party_distribution_channels: vec![],
            },
            lifecycle_state: "PUBLISHED".to_string(),
            is_reshare_disabled_by_author: false,
            content: None,
        };

        let json = serde_json::to_string(&request).unwrap();
        assert!(!json.contains("\"content\""));
    }

    #[test]
    fn test_initialize_upload_response_deserialization() {
        let json =
            r#"{"value":{"uploadUrl":"https://example.com/upload","image":"urn:li:image:xyz"}}"#;
        let response: InitializeUploadResponse = serde_json::from_str(json).unwrap();
        assert_eq!(response.value.upload_url, "https://example.com/upload");
        assert_eq!(response.value.image, "urn:li:image:xyz");
    }
}
