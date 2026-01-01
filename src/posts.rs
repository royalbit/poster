//! Post data loading and management

use crate::config::posts_path;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;
use url::Url;

/// Posted status tracking for each platform
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, Default)]
pub struct PostedStatus {
    /// ISO timestamp when posted to X, or null if not posted
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub x: Option<String>,
    /// ISO timestamp when posted to LinkedIn, or null if not posted
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub linkedin: Option<String>,
}

/// A single social media post
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct Post {
    pub id: String,
    pub title: String,
    pub url: String,
    pub x: String,
    pub linkedin: String,
    /// Tracking of when this post was published to each platform
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub posted: Option<PostedStatus>,
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
            "Posts file not found at {}\nRun 'poster init' to create it.",
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

/// Validation error for a post
#[derive(Debug)]
pub struct ValidationError {
    pub post_id: String,
    pub message: String,
    pub is_warning: bool,
}

/// Validate posts and return any errors/warnings
///
/// Checks:
/// - X posts must be <= 280 chars
/// - URL format must be valid
/// - Warns on missing posted timestamps
#[must_use]
pub fn validate_posts(posts: &[Post]) -> Vec<ValidationError> {
    let mut errors = Vec::new();

    for post in posts {
        // Check X content length
        let x_len = post.x.trim().len();
        if x_len > 280 {
            errors.push(ValidationError {
                post_id: post.id.clone(),
                message: format!("X content exceeds 280 chars ({x_len}/280)"),
                is_warning: false,
            });
        }

        // Validate URL format
        if Url::parse(&post.url).is_err() {
            errors.push(ValidationError {
                post_id: post.id.clone(),
                message: format!("Invalid URL: {}", post.url),
                is_warning: false,
            });
        }

        // Warn on missing posted timestamps
        if post.posted.is_none() {
            errors.push(ValidationError {
                post_id: post.id.clone(),
                message: "Missing posted timestamps".to_string(),
                is_warning: true,
            });
        }
    }

    errors
}

/// Print validation errors/warnings to stderr
pub fn print_validation_errors(errors: &[ValidationError]) {
    for error in errors {
        if error.is_warning {
            eprintln!("Warning [{}]: {}", error.post_id, error.message);
        } else {
            eprintln!("Error [{}]: {}", error.post_id, error.message);
        }
    }
}

/// Load posts with optional custom path
///
/// # Errors
/// Returns error if posts file is missing or malformed
pub fn load_posts_with_path(custom_path: Option<&Path>) -> Result<Vec<Post>> {
    let path = posts_path(custom_path)?;
    load_posts_from_path(&path)
}

/// Platform identifier for posted timestamps
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Platform {
    X,
    LinkedIn,
}

/// Check if a post has already been posted to a platform
#[must_use]
pub fn is_posted(post: &Post, platform: Platform) -> bool {
    post.posted.as_ref().is_some_and(|status| match platform {
        Platform::X => status.x.is_some(),
        Platform::LinkedIn => status.linkedin.is_some(),
    })
}

/// Filter posts to only those not yet posted to a platform
#[must_use]
pub fn filter_unposted(posts: &[Post], platform: Platform) -> Vec<Post> {
    posts
        .iter()
        .filter(|p| !is_posted(p, platform))
        .cloned()
        .collect()
}

/// Update the posted timestamp for a specific post and platform
///
/// # Errors
/// Returns error if posts file cannot be read or written
pub fn update_posted_timestamp(post_id: &str, platform: Platform, posts_path: &Path) -> Result<()> {
    let content = fs::read_to_string(posts_path)
        .with_context(|| format!("Failed to read posts from {}", posts_path.display()))?;

    let mut posts_file: PostsFile =
        serde_yaml::from_str(&content).context("Failed to parse posts.yaml")?;

    let timestamp = chrono::Utc::now().to_rfc3339();

    let post = posts_file
        .posts
        .iter_mut()
        .find(|p| p.id == post_id)
        .with_context(|| format!("Post '{post_id}' not found"))?;

    let posted = post.posted.get_or_insert(PostedStatus::default());

    match platform {
        Platform::X => posted.x = Some(timestamp),
        Platform::LinkedIn => posted.linkedin = Some(timestamp),
    }

    let yaml = serde_yaml::to_string(&posts_file).context("Failed to serialize posts")?;
    fs::write(posts_path, yaml)
        .with_context(|| format!("Failed to write posts to {}", posts_path.display()))?;

    Ok(())
}

/// Find a post by ID from a list
#[must_use]
pub fn find_post_in_list(posts: &[Post], id: &str) -> Option<Post> {
    posts.iter().find(|p| p.id == id).cloned()
}

/// Find a post by ID with optional custom path
///
/// # Errors
/// Returns error if post is not found or posts file cannot be read
pub fn find_post_with_path(id: &str, custom_path: Option<&Path>) -> Result<Post> {
    let posts = load_posts_with_path(custom_path)?;

    find_post_in_list(&posts, id).with_context(|| {
        format!("Post '{id}' not found. Run 'poster list' to see available posts.")
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

    // Show posted status
    let posted_status = match &post.posted {
        Some(status) => {
            let x_posted = status.x.as_ref().map_or("not posted", |_| "posted");
            let li_posted = status.linkedin.as_ref().map_or("not posted", |_| "posted");
            format!("X: {x_posted}, LinkedIn: {li_posted}")
        }
        None => "not tracked".to_string(),
    };

    format!(
        "  {}\n    Title: {}\n    URL: {}\n    X: {x_len} chars [{x_status}]\n    LinkedIn: {li_len} chars\n    Posted: {posted_status}\n",
        post.id, post.title, post.url
    )
}

/// List all available posts with optional custom path
///
/// # Errors
/// Returns error if posts file cannot be read
pub fn list_posts_with_path(custom_path: Option<&Path>) -> Result<()> {
    let path = posts_path(custom_path)?;
    let posts = load_posts_from_path(&path)?;

    // Validate and print warnings
    let errors = validate_posts(&posts);
    let has_errors = errors.iter().any(|e| !e.is_warning);
    if !errors.is_empty() {
        print_validation_errors(&errors);
        if has_errors {
            println!();
        }
    }

    println!("\nAvailable posts ({} total):\n", posts.len());

    for post in &posts {
        print!("{}", format_post_info(post));
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
            posted: None,
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
            posted: None,
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
            posted: None,
        };
        let post2 = post1.clone();
        assert_eq!(post1, post2);
    }

    #[test]
    fn test_posted_status_serialization() {
        let status = PostedStatus {
            x: Some("2025-01-01T00:00:00Z".to_string()),
            linkedin: None,
        };

        let post = Post {
            id: "test".to_string(),
            title: "Title".to_string(),
            url: "https://example.com".to_string(),
            x: "Tweet".to_string(),
            linkedin: "LinkedIn".to_string(),
            posted: Some(status),
        };

        let yaml = serde_yaml::to_string(&PostsFile { posts: vec![post] }).unwrap();
        assert!(yaml.contains("posted:"));
        assert!(yaml.contains("2025-01-01T00:00:00Z"));
    }

    #[test]
    fn test_validate_posts_valid() {
        let posts = vec![Post {
            id: "test".to_string(),
            title: "Title".to_string(),
            url: "https://example.com".to_string(),
            x: "Short tweet".to_string(),
            linkedin: "LinkedIn".to_string(),
            posted: Some(PostedStatus::default()),
        }];

        let errors = validate_posts(&posts);
        assert!(errors.is_empty());
    }

    #[test]
    fn test_validate_posts_x_too_long() {
        let posts = vec![Post {
            id: "test".to_string(),
            title: "Title".to_string(),
            url: "https://example.com".to_string(),
            x: "x".repeat(300),
            linkedin: "LinkedIn".to_string(),
            posted: Some(PostedStatus::default()),
        }];

        let errors = validate_posts(&posts);
        assert_eq!(errors.len(), 1);
        assert!(!errors[0].is_warning);
        assert!(errors[0].message.contains("280"));
    }

    #[test]
    fn test_validate_posts_invalid_url() {
        let posts = vec![Post {
            id: "test".to_string(),
            title: "Title".to_string(),
            url: "not-a-valid-url".to_string(),
            x: "Tweet".to_string(),
            linkedin: "LinkedIn".to_string(),
            posted: Some(PostedStatus::default()),
        }];

        let errors = validate_posts(&posts);
        assert_eq!(errors.len(), 1);
        assert!(!errors[0].is_warning);
        assert!(errors[0].message.contains("Invalid URL"));
    }

    #[test]
    fn test_validate_posts_missing_posted() {
        let posts = vec![Post {
            id: "test".to_string(),
            title: "Title".to_string(),
            url: "https://example.com".to_string(),
            x: "Tweet".to_string(),
            linkedin: "LinkedIn".to_string(),
            posted: None,
        }];

        let errors = validate_posts(&posts);
        assert_eq!(errors.len(), 1);
        assert!(errors[0].is_warning);
        assert!(errors[0].message.contains("Missing posted"));
    }

    #[test]
    fn test_update_posted_timestamp() {
        use tempfile::TempDir;

        let dir = TempDir::new().unwrap();
        let path = dir.path().join("posts.yaml");

        let initial = r"
posts:
  - id: test-post
    title: Test Post
    url: https://example.com
    x: Tweet content
    linkedin: LinkedIn content
";
        std::fs::write(&path, initial).unwrap();

        update_posted_timestamp("test-post", Platform::X, &path).unwrap();

        let content = std::fs::read_to_string(&path).unwrap();
        let posts_file: PostsFile = serde_yaml::from_str(&content).unwrap();

        assert!(posts_file.posts[0].posted.is_some());
        assert!(posts_file.posts[0].posted.as_ref().unwrap().x.is_some());
    }

    #[test]
    fn test_is_posted_none() {
        let post = Post {
            id: "test".to_string(),
            title: "Title".to_string(),
            url: "https://example.com".to_string(),
            x: "Tweet".to_string(),
            linkedin: "LinkedIn".to_string(),
            posted: None,
        };
        assert!(!is_posted(&post, Platform::X));
        assert!(!is_posted(&post, Platform::LinkedIn));
    }

    #[test]
    fn test_is_posted_x_only() {
        let post = Post {
            id: "test".to_string(),
            title: "Title".to_string(),
            url: "https://example.com".to_string(),
            x: "Tweet".to_string(),
            linkedin: "LinkedIn".to_string(),
            posted: Some(PostedStatus {
                x: Some("2026-01-01T00:00:00Z".to_string()),
                linkedin: None,
            }),
        };
        assert!(is_posted(&post, Platform::X));
        assert!(!is_posted(&post, Platform::LinkedIn));
    }

    #[test]
    fn test_is_posted_linkedin_only() {
        let post = Post {
            id: "test".to_string(),
            title: "Title".to_string(),
            url: "https://example.com".to_string(),
            x: "Tweet".to_string(),
            linkedin: "LinkedIn".to_string(),
            posted: Some(PostedStatus {
                x: None,
                linkedin: Some("2026-01-01T00:00:00Z".to_string()),
            }),
        };
        assert!(!is_posted(&post, Platform::X));
        assert!(is_posted(&post, Platform::LinkedIn));
    }

    #[test]
    fn test_is_posted_both() {
        let post = Post {
            id: "test".to_string(),
            title: "Title".to_string(),
            url: "https://example.com".to_string(),
            x: "Tweet".to_string(),
            linkedin: "LinkedIn".to_string(),
            posted: Some(PostedStatus {
                x: Some("2026-01-01T00:00:00Z".to_string()),
                linkedin: Some("2026-01-01T00:00:00Z".to_string()),
            }),
        };
        assert!(is_posted(&post, Platform::X));
        assert!(is_posted(&post, Platform::LinkedIn));
    }

    #[test]
    fn test_filter_unposted_all_new() {
        let posts = vec![
            Post {
                id: "post1".to_string(),
                title: "Title 1".to_string(),
                url: "https://example.com/1".to_string(),
                x: "Tweet 1".to_string(),
                linkedin: "LinkedIn 1".to_string(),
                posted: None,
            },
            Post {
                id: "post2".to_string(),
                title: "Title 2".to_string(),
                url: "https://example.com/2".to_string(),
                x: "Tweet 2".to_string(),
                linkedin: "LinkedIn 2".to_string(),
                posted: None,
            },
        ];
        let filtered = filter_unposted(&posts, Platform::X);
        assert_eq!(filtered.len(), 2);
    }

    #[test]
    fn test_filter_unposted_some_posted() {
        let posts = vec![
            Post {
                id: "post1".to_string(),
                title: "Title 1".to_string(),
                url: "https://example.com/1".to_string(),
                x: "Tweet 1".to_string(),
                linkedin: "LinkedIn 1".to_string(),
                posted: Some(PostedStatus {
                    x: Some("2026-01-01T00:00:00Z".to_string()),
                    linkedin: None,
                }),
            },
            Post {
                id: "post2".to_string(),
                title: "Title 2".to_string(),
                url: "https://example.com/2".to_string(),
                x: "Tweet 2".to_string(),
                linkedin: "LinkedIn 2".to_string(),
                posted: None,
            },
        ];
        let filtered_x = filter_unposted(&posts, Platform::X);
        assert_eq!(filtered_x.len(), 1);
        assert_eq!(filtered_x[0].id, "post2");

        let filtered_li = filter_unposted(&posts, Platform::LinkedIn);
        assert_eq!(filtered_li.len(), 2);
    }

    #[test]
    fn test_filter_unposted_all_posted() {
        let posts = vec![Post {
            id: "post1".to_string(),
            title: "Title 1".to_string(),
            url: "https://example.com/1".to_string(),
            x: "Tweet 1".to_string(),
            linkedin: "LinkedIn 1".to_string(),
            posted: Some(PostedStatus {
                x: Some("2026-01-01T00:00:00Z".to_string()),
                linkedin: Some("2026-01-01T00:00:00Z".to_string()),
            }),
        }];
        let filtered_x = filter_unposted(&posts, Platform::X);
        assert!(filtered_x.is_empty());

        let filtered_li = filter_unposted(&posts, Platform::LinkedIn);
        assert!(filtered_li.is_empty());
    }

    // Schema validation tests
    mod schema {
        use jsonschema::Validator;
        use serde_json::Value;

        fn load_schema() -> Value {
            let schema_str = include_str!("../posts.schema.json");
            serde_json::from_str(schema_str).expect("Schema should be valid JSON")
        }

        fn validate_yaml(yaml: &str) -> Result<(), Vec<String>> {
            let schema = load_schema();
            let validator = Validator::new(&schema).expect("Schema should compile");

            let yaml_value: serde_yaml::Value =
                serde_yaml::from_str(yaml).expect("YAML should parse");
            let json_value: Value =
                serde_json::to_value(yaml_value).expect("YAML should convert to JSON");

            let errors: Vec<String> = validator
                .iter_errors(&json_value)
                .map(|e| e.to_string())
                .collect();

            if errors.is_empty() {
                Ok(())
            } else {
                Err(errors)
            }
        }

        #[test]
        fn test_schema_is_valid_json() {
            let schema = load_schema();
            assert!(schema.is_object());
            assert_eq!(schema["$schema"], "http://json-schema.org/draft-07/schema#");
        }

        #[test]
        fn test_schema_validates_minimal_post() {
            let yaml = r"
posts:
  - id: test-post
    title: Test Post
    url: https://example.com
    x: Tweet content
    linkedin: LinkedIn content
";
            assert!(validate_yaml(yaml).is_ok());
        }

        #[test]
        fn test_schema_validates_post_with_posted() {
            let yaml = r#"
posts:
  - id: test-post
    title: Test Post
    url: https://example.com
    x: Tweet content
    linkedin: LinkedIn content
    posted:
      x: "2026-01-01T00:00:00Z"
      linkedin: "2026-01-01T00:00:00Z"
"#;
            assert!(validate_yaml(yaml).is_ok());
        }

        #[test]
        fn test_schema_validates_empty_posts() {
            let yaml = "posts: []";
            assert!(validate_yaml(yaml).is_ok());
        }

        #[test]
        fn test_schema_rejects_missing_posts_key() {
            let yaml = "other: value";
            let result = validate_yaml(yaml);
            assert!(result.is_err());
            assert!(result.unwrap_err().iter().any(|e| e.contains("posts")));
        }

        #[test]
        fn test_schema_rejects_missing_required_field() {
            let yaml = r"
posts:
  - id: test-post
    title: Test Post
    url: https://example.com
    x: Tweet content
";
            let result = validate_yaml(yaml);
            assert!(result.is_err());
            assert!(result.unwrap_err().iter().any(|e| e.contains("linkedin")));
        }

        #[test]
        fn test_schema_rejects_invalid_id_format() {
            let yaml = r#"
posts:
  - id: "Invalid ID With Spaces"
    title: Test Post
    url: https://example.com
    x: Tweet content
    linkedin: LinkedIn content
"#;
            let result = validate_yaml(yaml);
            assert!(result.is_err());
        }

        #[test]
        fn test_schema_rejects_x_over_280_chars() {
            let long_tweet = "x".repeat(300);
            let yaml = format!(
                r#"
posts:
  - id: test-post
    title: Test Post
    url: https://example.com
    x: "{long_tweet}"
    linkedin: LinkedIn content
"#
            );
            let result = validate_yaml(&yaml);
            assert!(result.is_err());
            assert!(result.unwrap_err().iter().any(|e| e.contains("280")));
        }

        #[test]
        fn test_schema_rejects_extra_properties() {
            let yaml = r"
posts:
  - id: test-post
    title: Test Post
    url: https://example.com
    x: Tweet content
    linkedin: LinkedIn content
    extra_field: not allowed
";
            let result = validate_yaml(yaml);
            assert!(result.is_err());
        }
    }
}
