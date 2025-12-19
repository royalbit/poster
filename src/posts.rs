//! Post data loading and management

use crate::config::posts_path;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

/// A single social media post
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
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

/// Load posts from a specific path
///
/// # Errors
/// Returns error if posts file is missing or malformed
pub fn load_posts_from_path(path: &Path) -> Result<Vec<Post>> {
    if !path.exists() {
        anyhow::bail!(
            "Posts file not found at {}\nRun 'daneel-poster init' to create it.",
            path.display()
        );
    }

    let content = fs::read_to_string(path)
        .with_context(|| format!("Failed to read posts from {}", path.display()))?;

    parse_posts_yaml(&content)
}

/// Parse posts from YAML content
///
/// # Errors
/// Returns error if YAML is malformed
pub fn parse_posts_yaml(content: &str) -> Result<Vec<Post>> {
    let posts_file: PostsFile =
        serde_yaml::from_str(content).context("Failed to parse posts.yaml")?;
    Ok(posts_file.posts)
}

/// Load posts from default YAML file location
///
/// # Errors
/// Returns error if posts file is missing or malformed
pub fn load_posts() -> Result<Vec<Post>> {
    let path = posts_path()?;
    load_posts_from_path(&path)
}

/// Find a post by ID from a list
#[must_use]
pub fn find_post_in_list(posts: &[Post], id: &str) -> Option<Post> {
    posts.iter().find(|p| p.id == id).cloned()
}

/// Find a post by ID from default file
///
/// # Errors
/// Returns error if post is not found or posts file cannot be read
pub fn find_post(id: &str) -> Result<Post> {
    let posts = load_posts()?;

    find_post_in_list(&posts, id).with_context(|| {
        format!("Post '{id}' not found. Run 'daneel-poster list' to see available posts.")
    })
}

/// Format post info for display
#[must_use]
pub fn format_post_info(post: &Post) -> String {
    let x_len = post.x.trim().len();
    let x_status = if x_len <= 280 {
        format!("OK ({x_len}/280)")
    } else {
        format!("OVER ({x_len}/280)")
    };

    let li_len = post.linkedin.trim().len();

    format!(
        "  {}\n    Title: {}\n    URL: {}\n    X: {x_len} chars [{x_status}]\n    LinkedIn: {li_len} chars\n",
        post.id, post.title, post.url
    )
}

/// List all available posts
///
/// # Errors
/// Returns error if posts file cannot be read
pub fn list_posts() -> Result<()> {
    let posts = load_posts()?;

    println!("\nAvailable posts ({} total):\n", posts.len());

    for post in posts {
        print!("{}", format_post_info(&post));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    const VALID_YAML: &str = r"
posts:
  - id: test-post-1
    title: Test Post One
    url: https://example.com/1
    x: Short tweet content
    linkedin: |
      Longer LinkedIn content
      with multiple lines
  - id: test-post-2
    title: Test Post Two
    url: https://example.com/2
    x: Another tweet that is exactly at the limit of 280 characters. This is a test to see if we can properly handle tweets that are at the maximum length allowed by the platform. Let's add more text here to reach the limit.
    linkedin: Second LinkedIn post
";

    const INVALID_YAML: &str = r"
posts:
  - id: missing-fields
    title: Only Title
";

    #[test]
    fn test_parse_posts_yaml_valid() {
        let posts = parse_posts_yaml(VALID_YAML).unwrap();
        assert_eq!(posts.len(), 2);
        assert_eq!(posts[0].id, "test-post-1");
        assert_eq!(posts[0].title, "Test Post One");
        assert_eq!(posts[1].id, "test-post-2");
    }

    #[test]
    fn test_parse_posts_yaml_invalid() {
        let result = parse_posts_yaml(INVALID_YAML);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_posts_yaml_empty() {
        let result = parse_posts_yaml("posts: []");
        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 0);
    }

    #[test]
    fn test_load_posts_from_path_valid() {
        let mut file = NamedTempFile::new().unwrap();
        file.write_all(VALID_YAML.as_bytes()).unwrap();

        let posts = load_posts_from_path(file.path()).unwrap();
        assert_eq!(posts.len(), 2);
    }

    #[test]
    fn test_load_posts_from_path_not_found() {
        let result = load_posts_from_path(Path::new("/nonexistent/path/posts.yaml"));
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("not found"));
    }

    #[test]
    fn test_find_post_in_list_found() {
        let posts = parse_posts_yaml(VALID_YAML).unwrap();
        let found = find_post_in_list(&posts, "test-post-1");
        assert!(found.is_some());
        assert_eq!(found.unwrap().title, "Test Post One");
    }

    #[test]
    fn test_find_post_in_list_not_found() {
        let posts = parse_posts_yaml(VALID_YAML).unwrap();
        let found = find_post_in_list(&posts, "nonexistent");
        assert!(found.is_none());
    }

    #[test]
    fn test_format_post_info_short_tweet() {
        let post = Post {
            id: "test".to_string(),
            title: "Test Title".to_string(),
            url: "https://example.com".to_string(),
            x: "Short tweet".to_string(),
            linkedin: "LinkedIn content".to_string(),
        };

        let info = format_post_info(&post);
        assert!(info.contains("test"));
        assert!(info.contains("Test Title"));
        assert!(info.contains("OK ("));
        assert!(info.contains("/280)"));
    }

    #[test]
    fn test_format_post_info_long_tweet() {
        let long_tweet = "x".repeat(300);
        let post = Post {
            id: "test".to_string(),
            title: "Test Title".to_string(),
            url: "https://example.com".to_string(),
            x: long_tweet,
            linkedin: "LinkedIn content".to_string(),
        };

        let info = format_post_info(&post);
        assert!(info.contains("OVER (300/280)"));
    }

    #[test]
    fn test_post_equality() {
        let post1 = Post {
            id: "test".to_string(),
            title: "Title".to_string(),
            url: "https://example.com".to_string(),
            x: "Tweet".to_string(),
            linkedin: "LinkedIn".to_string(),
        };
        let post2 = post1.clone();
        assert_eq!(post1, post2);
    }
}
