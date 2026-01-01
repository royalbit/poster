//! Configuration management for poster
//!
//! Credentials are loaded from `pass` (password-store).

#![allow(clippy::doc_markdown)] // LinkedIn is a brand name, not code

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

/// LinkedIn credentials from pass
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinkedinConfig {
    pub client_id: String,
    pub client_secret: String,
}

/// X/Twitter OAuth 2.0 credentials from pass
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XOAuth2Config {
    pub client_id: String,
    /// Client secret (required for confidential clients like Web Apps)
    pub client_secret: Option<String>,
}

/// X OAuth 2.0 token storage
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct XToken {
    pub access_token: String,
    pub refresh_token: String,
    pub user_id: String,
    pub username: String,
    #[serde(default)]
    pub saved_at: String,
}

/// Parse pass output into key-value pairs
///
/// Each line should be in format "key: value"
#[must_use]
pub fn parse_pass_output(content: &str) -> HashMap<String, String> {
    let mut map = HashMap::new();
    for line in content.lines() {
        if let Some((key, value)) = line.split_once(':') {
            map.insert(key.trim().to_string(), value.trim().to_string());
        }
    }
    map
}

/// Extract LinkedIn config from parsed pass output
///
/// # Errors
/// Returns error if required fields are missing
pub fn extract_linkedin_config(creds: &HashMap<String, String>) -> Result<LinkedinConfig> {
    Ok(LinkedinConfig {
        client_id: creds
            .get("client_id")
            .context("Missing 'client_id' in royalbit/linkedin")?
            .clone(),
        client_secret: creds
            .get("client_secret")
            .context("Missing 'client_secret' in royalbit/linkedin")?
            .clone(),
    })
}

/// Extract X OAuth 2.0 config from parsed pass output
///
/// # Errors
/// Returns error if required fields are missing
pub fn extract_x_oauth2_config(creds: &HashMap<String, String>) -> Result<XOAuth2Config> {
    Ok(XOAuth2Config {
        client_id: creds
            .get("client_id")
            .context("Missing 'client_id' in royalbit/x")?
            .clone(),
        client_secret: creds.get("client_secret").cloned(),
    })
}

/// Read a pass entry and parse key: value pairs
fn read_pass(entry: &str) -> Result<HashMap<String, String>> {
    let output = Command::new("pass")
        .arg(entry)
        .output()
        .with_context(|| format!("Failed to run 'pass {entry}'"))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("pass {entry} failed: {stderr}");
    }

    let content = String::from_utf8(output.stdout).context("Invalid UTF-8 in pass output")?;

    Ok(parse_pass_output(&content))
}

/// Load LinkedIn credentials from pass
///
/// # Errors
/// Returns error if pass entry is missing or malformed
pub fn load_linkedin_creds() -> Result<LinkedinConfig> {
    let creds =
        read_pass("royalbit/linkedin").context("Failed to read royalbit/linkedin from pass")?;
    extract_linkedin_config(&creds)
}

/// Load X OAuth 2.0 credentials from pass
///
/// # Errors
/// Returns error if pass entry is missing or malformed
pub fn load_x_oauth2_creds() -> Result<XOAuth2Config> {
    let creds = read_pass("royalbit/x").context("Failed to read royalbit/x from pass")?;
    extract_x_oauth2_config(&creds)
}

/// LinkedIn OAuth token storage
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct LinkedinToken {
    pub access_token: String,
    pub person_urn: String,
    #[serde(default)]
    pub saved_at: String,
}

/// Get the config directory path
///
/// # Errors
/// Returns error if config directory cannot be determined or created
pub fn config_dir() -> Result<PathBuf> {
    let dir = dirs::config_dir()
        .context("Could not determine config directory")?
        .join("poster");

    if !dir.exists() {
        fs::create_dir_all(&dir)?;
    }

    Ok(dir)
}

/// Get the posts file path
///
/// Priority: custom_path > DANEEL_POSTS_PATH env > cwd > config dir
///
/// # Errors
/// Returns error if config directory cannot be determined
pub fn posts_path(custom_path: Option<&Path>) -> Result<PathBuf> {
    // 1. Custom path takes priority
    if let Some(path) = custom_path {
        return Ok(path.to_path_buf());
    }

    // 2. Environment variable
    if let Ok(env_path) = std::env::var("DANEEL_POSTS_PATH") {
        let path = PathBuf::from(env_path);
        if path.exists() {
            return Ok(path);
        }
    }

    // 3. Current working directory
    let local = PathBuf::from("posts.yaml");
    if local.exists() {
        return Ok(local);
    }

    // 4. Config directory (fallback)
    let config = config_dir()?.join("posts.yaml");
    Ok(config)
}

/// Get the LinkedIn token file path
///
/// # Errors
/// Returns error if config directory cannot be determined
pub fn token_path() -> Result<PathBuf> {
    Ok(config_dir()?.join("linkedin_token.json"))
}

/// Get the X token file path
///
/// # Errors
/// Returns error if config directory cannot be determined
pub fn x_token_path() -> Result<PathBuf> {
    Ok(config_dir()?.join("x_token.json"))
}

/// Load LinkedIn token from a specific path
///
/// # Errors
/// Returns error if token file is missing or malformed
pub fn load_token_from_path(path: &Path) -> Result<LinkedinToken> {
    if !path.exists() {
        anyhow::bail!("LinkedIn token not found.\nRun 'poster linkedin auth' first.");
    }

    let content = fs::read_to_string(path)?;
    let token: LinkedinToken = serde_json::from_str(&content)?;

    Ok(token)
}

/// Load LinkedIn token from default file
///
/// # Errors
/// Returns error if token file is missing or malformed
pub fn load_linkedin_token() -> Result<LinkedinToken> {
    let path = token_path()?;
    load_token_from_path(&path)
}

/// Save LinkedIn token to a specific path
///
/// # Errors
/// Returns error if token cannot be serialized or written
pub fn save_token_to_path(token: &LinkedinToken, path: &Path) -> Result<()> {
    let content = serde_json::to_string_pretty(token)?;
    fs::write(path, content)?;
    Ok(())
}

/// Save LinkedIn token to default file
///
/// # Errors
/// Returns error if token cannot be serialized or written
pub fn save_linkedin_token(token: &LinkedinToken) -> Result<()> {
    let path = token_path()?;
    save_token_to_path(token, &path)?;
    println!("Token saved to {}", path.display());
    Ok(())
}

/// Load X token from default file
///
/// # Errors
/// Returns error if token file is missing or malformed
pub fn load_x_token() -> Result<XToken> {
    let path = x_token_path()?;
    if !path.exists() {
        anyhow::bail!("X token not found.\nRun 'poster x auth' first.");
    }
    let content = fs::read_to_string(&path)?;
    let token: XToken = serde_json::from_str(&content)?;
    Ok(token)
}

/// Save X token to default file
///
/// # Errors
/// Returns error if token cannot be serialized or written
pub fn save_x_token(token: &XToken) -> Result<()> {
    let path = x_token_path()?;
    let content = serde_json::to_string_pretty(token)?;
    fs::write(&path, content)?;
    println!("Token saved to {}", path.display());
    Ok(())
}

/// Initialize posts file
///
/// # Errors
/// Returns error if config directory or posts file cannot be created
pub fn init_config() -> Result<()> {
    let posts_path = config_dir()?.join("posts.yaml");

    if posts_path.exists() {
        println!("Posts file already exists: {}", posts_path.display());
    } else {
        let example_posts = include_str!("../posts.example.yaml");
        fs::write(&posts_path, example_posts)?;
        println!("Created posts file: {}", posts_path.display());
    }

    println!("\nCredentials are loaded from pass:");
    println!("  pass royalbit/linkedin  (client_id, client_secret)");
    println!("  pass royalbit/x         (client_id)");
    println!("\nNext steps:");
    println!("1. Ensure pass entries exist with key: value format");
    println!("2. Run 'poster linkedin auth' to authenticate with LinkedIn");
    println!("3. Run 'poster x auth' to authenticate with X");
    println!("4. Run 'poster list' to see available posts");

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::{NamedTempFile, TempDir};

    #[test]
    fn test_parse_pass_output_valid() {
        let content = "client_id: my-client-id\nclient_secret: my-secret\n";
        let map = parse_pass_output(content);
        assert_eq!(map.get("client_id"), Some(&"my-client-id".to_string()));
        assert_eq!(map.get("client_secret"), Some(&"my-secret".to_string()));
    }

    #[test]
    fn test_parse_pass_output_with_spaces() {
        let content = "  key  :  value with spaces  \n";
        let map = parse_pass_output(content);
        assert_eq!(map.get("key"), Some(&"value with spaces".to_string()));
    }

    #[test]
    fn test_parse_pass_output_empty() {
        let map = parse_pass_output("");
        assert!(map.is_empty());
    }

    #[test]
    fn test_parse_pass_output_no_colon() {
        let content = "this line has no colon\nkey: value\n";
        let map = parse_pass_output(content);
        assert_eq!(map.len(), 1);
        assert_eq!(map.get("key"), Some(&"value".to_string()));
    }

    #[test]
    fn test_extract_linkedin_config_valid() {
        let mut creds = HashMap::new();
        creds.insert("client_id".to_string(), "test-id".to_string());
        creds.insert("client_secret".to_string(), "test-secret".to_string());

        let config = extract_linkedin_config(&creds).unwrap();
        assert_eq!(config.client_id, "test-id");
        assert_eq!(config.client_secret, "test-secret");
    }

    #[test]
    fn test_extract_linkedin_config_missing_id() {
        let mut creds = HashMap::new();
        creds.insert("client_secret".to_string(), "test-secret".to_string());

        let result = extract_linkedin_config(&creds);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("client_id"));
    }

    #[test]
    fn test_extract_linkedin_config_missing_secret() {
        let mut creds = HashMap::new();
        creds.insert("client_id".to_string(), "test-id".to_string());

        let result = extract_linkedin_config(&creds);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("client_secret"));
    }

    #[test]
    fn test_extract_x_oauth2_config_valid() {
        let mut creds = HashMap::new();
        creds.insert("client_id".to_string(), "test-client-id".to_string());

        let config = extract_x_oauth2_config(&creds).unwrap();
        assert_eq!(config.client_id, "test-client-id");
        assert!(config.client_secret.is_none());
    }

    #[test]
    fn test_extract_x_oauth2_config_with_secret() {
        let mut creds = HashMap::new();
        creds.insert("client_id".to_string(), "test-client-id".to_string());
        creds.insert("client_secret".to_string(), "test-secret".to_string());

        let config = extract_x_oauth2_config(&creds).unwrap();
        assert_eq!(config.client_id, "test-client-id");
        assert_eq!(config.client_secret, Some("test-secret".to_string()));
    }

    #[test]
    fn test_extract_x_oauth2_config_missing_field() {
        let creds = HashMap::new();
        // Missing client_id

        let result = extract_x_oauth2_config(&creds);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("client_id"));
    }

    #[test]
    fn test_linkedin_token_serialization() {
        let token = LinkedinToken {
            access_token: "test-token".to_string(),
            person_urn: "urn:li:person:123".to_string(),
            saved_at: "2025-01-01T00:00:00Z".to_string(),
        };

        let json = serde_json::to_string(&token).unwrap();
        let parsed: LinkedinToken = serde_json::from_str(&json).unwrap();

        assert_eq!(token, parsed);
    }

    #[test]
    fn test_linkedin_token_default_saved_at() {
        let json = r#"{"access_token":"tok","person_urn":"urn"}"#;
        let token: LinkedinToken = serde_json::from_str(json).unwrap();
        assert_eq!(token.saved_at, "");
    }

    #[test]
    fn test_save_and_load_token() {
        let token = LinkedinToken {
            access_token: "test-token".to_string(),
            person_urn: "urn:li:person:456".to_string(),
            saved_at: "2025-01-01T00:00:00Z".to_string(),
        };

        let dir = TempDir::new().unwrap();
        let path = dir.path().join("token.json");

        save_token_to_path(&token, &path).unwrap();
        let loaded = load_token_from_path(&path).unwrap();

        assert_eq!(token, loaded);
    }

    #[test]
    fn test_load_token_not_found() {
        let result = load_token_from_path(Path::new("/nonexistent/token.json"));
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("not found"));
    }

    #[test]
    fn test_load_token_invalid_json() {
        let mut file = NamedTempFile::new().unwrap();
        file.write_all(b"not valid json").unwrap();

        let result = load_token_from_path(file.path());
        assert!(result.is_err());
    }

    #[test]
    fn test_linkedin_config_equality() {
        let config1 = LinkedinConfig {
            client_id: "id".to_string(),
            client_secret: "secret".to_string(),
        };
        let config2 = config1.clone();
        assert_eq!(config1, config2);
    }

    #[test]
    fn test_x_oauth2_config_equality() {
        let config1 = XOAuth2Config {
            client_id: "client-id".to_string(),
            client_secret: Some("secret".to_string()),
        };
        let config2 = config1.clone();
        assert_eq!(config1, config2);
    }

    #[test]
    fn test_x_token_serialization() {
        let token = XToken {
            access_token: "test-access".to_string(),
            refresh_token: "test-refresh".to_string(),
            user_id: "12345".to_string(),
            username: "testuser".to_string(),
            saved_at: "2026-01-01T00:00:00Z".to_string(),
        };

        let json = serde_json::to_string(&token).unwrap();
        let parsed: XToken = serde_json::from_str(&json).unwrap();

        assert_eq!(token, parsed);
    }
}
