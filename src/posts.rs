//! Post data loading and management

use crate::config::posts_path;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fs;

/// A single social media post
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Post {
    pub id: String,
    pub title: String,
    pub url: String,
    pub x: String,
    pub linkedin: String,
}

/// Posts file structure
#[derive(Debug, Serialize, Deserialize)]
pub struct PostsFile {
    pub posts: Vec<Post>,
}

/// Load posts from YAML file
///
/// # Errors
/// Returns error if posts file is missing or malformed
pub fn load_posts() -> Result<Vec<Post>> {
    let path = posts_path()?;

    if !path.exists() {
        anyhow::bail!(
            "Posts file not found at {}\nRun 'daneel-poster init' to create it.",
            path.display()
        );
    }

    let content = fs::read_to_string(&path)
        .with_context(|| format!("Failed to read posts from {}", path.display()))?;

    let posts_file: PostsFile =
        serde_yaml::from_str(&content).context("Failed to parse posts.yaml")?;

    Ok(posts_file.posts)
}

/// Find a post by ID
///
/// # Errors
/// Returns error if post is not found or posts file cannot be read
pub fn find_post(id: &str) -> Result<Post> {
    let posts = load_posts()?;

    posts.into_iter().find(|p| p.id == id).with_context(|| {
        format!("Post '{id}' not found. Run 'daneel-poster list' to see available posts.")
    })
}

/// List all available posts
///
/// # Errors
/// Returns error if posts file cannot be read
pub fn list_posts() -> Result<()> {
    let posts = load_posts()?;

    println!("\nAvailable posts ({} total):\n", posts.len());

    for post in posts {
        let x_len = post.x.trim().len();
        let x_status = if x_len <= 280 {
            format!("OK ({x_len}/280)")
        } else {
            format!("OVER ({x_len}/280)")
        };

        let li_len = post.linkedin.trim().len();

        println!("  {}", post.id);
        println!("    Title: {}", post.title);
        println!("    URL: {}", post.url);
        println!("    X: {x_len} chars [{x_status}]");
        println!("    LinkedIn: {li_len} chars");
        println!();
    }

    Ok(())
}
