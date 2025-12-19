//! Configuration management for daneel-poster
//!
//! Credentials are loaded from `pass` (password-store).

#![allow(clippy::doc_markdown)] // LinkedIn is a brand name, not code

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::process::Command;

/// LinkedIn credentials from pass
#[derive(Debug)]
pub struct LinkedinConfig {
    pub client_id: String,
    pub client_secret: String,
}

/// X/Twitter credentials from pass
#[derive(Debug)]
pub struct XConfig {
    pub consumer_key: String,
    pub consumer_secret: String,
    pub access_token: String,
    pub access_token_secret: String,
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

    let mut map = HashMap::new();
    for line in content.lines() {
        if let Some((key, value)) = line.split_once(':') {
            map.insert(key.trim().to_string(), value.trim().to_string());
        }
    }

    Ok(map)
}

/// Load LinkedIn credentials from pass
///
/// # Errors
/// Returns error if pass entry is missing or malformed
pub fn load_linkedin_creds() -> Result<LinkedinConfig> {
    let creds =
        read_pass("royalbit/linkedin").context("Failed to read royalbit/linkedin from pass")?;

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

/// Load X credentials from pass
///
/// # Errors
/// Returns error if pass entry is missing or malformed
pub fn load_x_creds() -> Result<XConfig> {
    let creds = read_pass("royalbit/x").context("Failed to read royalbit/x from pass")?;

    Ok(XConfig {
        consumer_key: creds
            .get("consumer_key")
            .context("Missing 'consumer_key' in royalbit/x")?
            .clone(),
        consumer_secret: creds
            .get("consumer_secret")
            .context("Missing 'consumer_secret' in royalbit/x")?
            .clone(),
        access_token: creds
            .get("access_token")
            .context("Missing 'access_token' in royalbit/x")?
            .clone(),
        access_token_secret: creds
            .get("access_token_secret")
            .context("Missing 'access_token_secret' in royalbit/x")?
            .clone(),
    })
}

/// LinkedIn OAuth token storage
#[derive(Debug, Serialize, Deserialize)]
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
        .join("daneel-poster");

    if !dir.exists() {
        fs::create_dir_all(&dir)?;
    }

    Ok(dir)
}

/// Get the posts file path (looks in current dir first, then config dir)
///
/// # Errors
/// Returns error if config directory cannot be determined
pub fn posts_path() -> Result<PathBuf> {
    let local = PathBuf::from("posts.yaml");
    if local.exists() {
        return Ok(local);
    }

    let config = config_dir()?.join("posts.yaml");
    if config.exists() {
        return Ok(config);
    }

    Ok(config)
}

/// Get the LinkedIn token file path
///
/// # Errors
/// Returns error if config directory cannot be determined
pub fn token_path() -> Result<PathBuf> {
    Ok(config_dir()?.join("linkedin_token.json"))
}

/// Load LinkedIn token from file
///
/// # Errors
/// Returns error if token file is missing or malformed
pub fn load_linkedin_token() -> Result<LinkedinToken> {
    let path = token_path()?;

    if !path.exists() {
        anyhow::bail!("LinkedIn token not found.\nRun 'daneel-poster linkedin auth' first.");
    }

    let content = fs::read_to_string(&path)?;
    let token: LinkedinToken = serde_json::from_str(&content)?;

    Ok(token)
}

/// Save LinkedIn token to file
///
/// # Errors
/// Returns error if token cannot be serialized or written
pub fn save_linkedin_token(token: &LinkedinToken) -> Result<()> {
    let path = token_path()?;
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
    println!("  pass royalbit/x         (consumer_key, consumer_secret, access_token, access_token_secret)");
    println!("\nNext steps:");
    println!("1. Ensure pass entries exist with key: value format");
    println!("2. Run 'daneel-poster linkedin auth' to authenticate");
    println!("3. Run 'daneel-poster list' to see available posts");

    Ok(())
}
