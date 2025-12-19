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

#[derive(Parser)]
#[command(name = "daneel-poster")]
#[command(about = "Automated social media poster for DANEEL blog content")]
#[command(version)]
struct Cli {
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

    match cli.command {
        Commands::Init => {
            config::init_config()?;
        }

        Commands::List => {
            posts::list_posts()?;
        }

        Commands::Linkedin { action } => match action {
            LinkedinAction::Auth => {
                linkedin::authenticate().await?;
            }
            LinkedinAction::Post { id, dry_run } => {
                linkedin::post(&id, dry_run).await?;
            }
            LinkedinAction::PostAll { delay, dry_run } => {
                linkedin::post_all(delay, dry_run).await?;
            }
        },

        Commands::X { action } => match action {
            XAction::Post { id, dry_run } => {
                x::post(&id, dry_run).await?;
            }
            XAction::PostAll { delay, dry_run } => {
                x::post_all(delay, dry_run).await?;
            }
        },
    }

    Ok(())
}
