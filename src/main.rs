//! RoyalBit Poster
//!
//! Social media automation CLI for LinkedIn and X/Twitter.

#![allow(clippy::doc_markdown)] // LinkedIn is a brand name, not code

mod config;
mod linkedin;
mod posts;
mod update;
mod x;

use anyhow::Result;
use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "poster")]
#[command(about = "RoyalBit Poster - Social media automation CLI")]
#[command(version)]
struct Cli {
    /// Path to posts.yaml file (overrides DANEEL_POSTS_PATH env and default locations)
    #[arg(long, global = true, env = "DANEEL_POSTS_PATH")]
    posts_path: Option<PathBuf>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// LinkedIn operations
    Linkedin {
        #[command(subcommand)]
        action: LinkedinAction,
    },

    /// X/Twitter operations
    X {
        #[command(subcommand)]
        action: XAction,
    },

    /// List available posts
    List,

    /// Initialize configuration files
    Init,

    /// Update poster to the latest version
    Update {
        /// Only check for updates, don't install
        #[arg(long)]
        check: bool,
    },
}

#[derive(Subcommand)]
enum LinkedinAction {
    /// Authenticate with LinkedIn (opens browser)
    Auth,

    /// Post content to LinkedIn
    Post {
        /// Post ID to publish
        #[arg(long)]
        id: String,

        /// Print without actually posting
        #[arg(long, default_value = "false")]
        dry_run: bool,
    },

    /// Post all content with delay
    PostAll {
        /// Delay between posts in seconds
        #[arg(long, default_value = "3600")]
        delay: u64,

        /// Print without actually posting
        #[arg(long, default_value = "false")]
        dry_run: bool,
    },
}

#[derive(Subcommand)]
enum XAction {
    /// Authenticate with X (opens browser)
    Auth,

    /// Post content to X
    Post {
        /// Post ID to publish
        #[arg(long)]
        id: String,

        /// Print without actually posting
        #[arg(long, default_value = "false")]
        dry_run: bool,
    },

    /// Post all content with delay
    PostAll {
        /// Delay between posts in seconds
        #[arg(long, default_value = "3600")]
        delay: u64,

        /// Print without actually posting
        #[arg(long, default_value = "false")]
        dry_run: bool,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let posts_path = cli.posts_path.as_deref();

    match cli.command {
        Commands::Init => {
            config::init_config()?;
        }

        Commands::Update { check } => {
            use update::{run_update, UpdateResult};
            match run_update(check) {
                UpdateResult::AlreadyLatest { current, latest } => {
                    println!("Already at latest version {current} (latest: {latest})");
                }
                UpdateResult::UpdateAvailable { current, latest } => {
                    println!("Update available: {current} -> {latest}");
                    println!("Run `poster update` to install");
                }
                UpdateResult::Updated { from, to } => {
                    println!("Updated successfully: {from} -> {to}");
                }
                UpdateResult::UpdateFailed {
                    current,
                    latest,
                    error,
                    download_url,
                } => {
                    eprintln!("Update failed: {error}");
                    eprintln!("Current: {current}, Latest: {latest}");
                    eprintln!("Manual download: {download_url}");
                    std::process::exit(1);
                }
                UpdateResult::NoBinaryAvailable { current, latest } => {
                    eprintln!("No binary available for this platform");
                    eprintln!("Current: {current}, Latest: {latest}");
                    eprintln!("Install from source: cargo install royalbit-poster");
                    std::process::exit(1);
                }
                UpdateResult::CheckFailed { error } => {
                    eprintln!("Failed to check for updates: {error}");
                    std::process::exit(1);
                }
            }
        }

        Commands::List => {
            posts::list_posts_with_path(posts_path)?;
        }

        Commands::Linkedin { action } => match action {
            LinkedinAction::Auth => {
                linkedin::authenticate().await?;
            }
            LinkedinAction::Post { id, dry_run } => {
                linkedin::post(&id, dry_run, posts_path).await?;
            }
            LinkedinAction::PostAll { delay, dry_run } => {
                linkedin::post_all(delay, dry_run, posts_path).await?;
            }
        },

        Commands::X { action } => match action {
            XAction::Auth => {
                x::authenticate().await?;
            }
            XAction::Post { id, dry_run } => {
                x::post(&id, dry_run, posts_path).await?;
            }
            XAction::PostAll { delay, dry_run } => {
                x::post_all(delay, dry_run, posts_path).await?;
            }
        },
    }

    Ok(())
}
