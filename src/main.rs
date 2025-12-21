//! DANEEL Social Media Poster
//!
//! Automated posting to LinkedIn and X/Twitter for DANEEL blog content.

#![allow(clippy::doc_markdown)] // LinkedIn is a brand name, not code

mod config;
mod linkedin;
mod posts;
mod x;

use anyhow::Result;
use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "daneel-poster")]
#[command(about = "Automated social media poster for DANEEL blog content")]
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
