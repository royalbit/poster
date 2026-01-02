//! Self-update functionality for RoyalBit Poster
//!
//! Checks GitHub Releases for new versions and updates the binary in-place.

use std::env;
use std::fs;
use std::path::Path;

/// GitHub releases page URL (redirects to latest)
const GITHUB_RELEASES_URL: &str = "https://github.com/royalbit/poster/releases/latest";

/// GitHub releases download base URL
const GITHUB_DOWNLOAD_BASE: &str = "https://github.com/royalbit/poster/releases/download";

/// Current version from Cargo.toml
pub const CURRENT_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Result of version check
#[derive(Debug, Clone)]
pub struct VersionCheck {
    pub current: String,
    pub latest: String,
    pub update_available: bool,
    pub download_url: Option<String>,
    pub checksums_url: Option<String>,
}

/// Get the appropriate asset name for the current platform
#[allow(clippy::unnecessary_wraps)]
pub fn get_platform_asset() -> Option<&'static str> {
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    return Some("poster-x86_64-unknown-linux-musl.tar.gz");

    #[cfg(all(target_os = "linux", target_arch = "aarch64"))]
    return Some("poster-aarch64-unknown-linux-musl.tar.gz");

    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    return Some("poster-aarch64-apple-darwin.tar.gz");

    #[cfg(all(target_os = "macos", target_arch = "x86_64"))]
    return Some("poster-x86_64-apple-darwin.tar.gz");

    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    return Some("poster-x86_64-pc-windows-msvc.zip");

    #[cfg(not(any(
        all(target_os = "linux", target_arch = "x86_64"),
        all(target_os = "linux", target_arch = "aarch64"),
        all(target_os = "macos", target_arch = "aarch64"),
        all(target_os = "macos", target_arch = "x86_64"),
        all(target_os = "windows", target_arch = "x86_64")
    )))]
    return None;
}

/// Get latest version by following GitHub releases redirect
fn get_latest_version_from_redirect(url: &str) -> Result<String, String> {
    let output = std::process::Command::new("curl")
        .args(["-sI", "-o", "/dev/null", "-w", "%{redirect_url}", url])
        .output()
        .map_err(|e| format!("Failed to fetch: {e}"))?;

    if !output.status.success() {
        return Err("Failed to fetch from URL".to_string());
    }

    let redirect_url = String::from_utf8_lossy(&output.stdout).into_owned();

    // Extract version from URL like: https://github.com/royalbit/poster/releases/tag/v0.8.0
    redirect_url
        .rsplit('/')
        .next()
        .map(|v| v.trim_start_matches('v').to_string())
        .filter(|v| !v.is_empty())
        .ok_or_else(|| "Could not parse version from redirect URL".to_string())
}

/// Check for updates by following GitHub releases redirect (no API, no rate limits)
pub fn check_for_update() -> Result<VersionCheck, String> {
    check_for_update_from_url(GITHUB_RELEASES_URL)
}

/// Check for updates from a custom URL (for testing)
pub fn check_for_update_from_url(url: &str) -> Result<VersionCheck, String> {
    let latest_version = get_latest_version_from_redirect(url)?;
    let update_available = is_newer_version(&latest_version, CURRENT_VERSION);

    // Build download URLs directly (no API needed)
    let download_url = if update_available {
        get_platform_asset()
            .map(|asset| format!("{GITHUB_DOWNLOAD_BASE}/v{latest_version}/{asset}"))
    } else {
        None
    };

    let checksums_url = if update_available {
        Some(format!(
            "{GITHUB_DOWNLOAD_BASE}/v{latest_version}/checksums.txt"
        ))
    } else {
        None
    };

    Ok(VersionCheck {
        current: CURRENT_VERSION.to_string(),
        latest: latest_version,
        update_available,
        download_url,
        checksums_url,
    })
}

/// Compare semantic versions (returns true if latest > current)
pub fn is_newer_version(latest: &str, current: &str) -> bool {
    let parse_version =
        |v: &str| -> Vec<u32> { v.split('.').filter_map(|s| s.parse().ok()).collect() };

    let latest_parts = parse_version(latest);
    let current_parts = parse_version(current);

    for i in 0..3 {
        let l = latest_parts.get(i).copied().unwrap_or(0);
        let c = current_parts.get(i).copied().unwrap_or(0);
        if l > c {
            return true;
        }
        if l < c {
            return false;
        }
    }
    false
}

/// Parse checksums file and find the expected checksum for an asset
pub fn parse_checksums(checksums_content: &str, asset_name: &str) -> Option<String> {
    checksums_content
        .lines()
        .find(|line| line.contains(asset_name))
        .and_then(|line| line.split_whitespace().next())
        .map(str::to_string)
}

/// Calculate SHA256 checksum of a file
pub fn calculate_checksum(file_path: &Path) -> Result<String, String> {
    #[cfg(not(target_os = "windows"))]
    {
        let output = std::process::Command::new("sha256sum")
            .arg(file_path)
            .output()
            .map_err(|e| format!("Failed to calculate checksum: {e}"))?;

        if !output.status.success() {
            return Err("Failed to calculate SHA256 checksum".to_string());
        }

        Ok(String::from_utf8_lossy(&output.stdout)
            .split_whitespace()
            .next()
            .unwrap_or("")
            .to_string())
    }

    #[cfg(target_os = "windows")]
    {
        let output = std::process::Command::new("certutil")
            .args(["-hashfile", file_path.to_str().unwrap(), "SHA256"])
            .output()
            .map_err(|e| format!("Failed to calculate checksum: {e}"))?;

        if !output.status.success() {
            return Err("Failed to calculate SHA256 checksum".to_string());
        }

        // certutil output has checksum on second line
        Ok(String::from_utf8_lossy(&output.stdout)
            .lines()
            .nth(1)
            .unwrap_or("")
            .trim()
            .replace(' ', "")
            .to_lowercase())
    }
}

/// Verify checksum matches expected
pub fn verify_checksum_match(expected: &str, actual: &str) -> Result<(), String> {
    if actual == expected {
        Ok(())
    } else {
        Err(format!(
            "Checksum mismatch!\n  Expected: {expected}\n  Actual:   {actual}"
        ))
    }
}

/// Verify SHA256 checksum of downloaded file
fn verify_checksum(
    file_path: &std::path::Path,
    checksums_url: &str,
    asset_name: &str,
) -> Result<(), String> {
    // Download checksums.txt
    let output = std::process::Command::new("curl")
        .args(["-sL", checksums_url])
        .output()
        .map_err(|e| format!("Failed to download checksums: {e}"))?;

    if !output.status.success() {
        return Err("Failed to download checksums.txt".to_string());
    }

    let checksums = String::from_utf8_lossy(&output.stdout);

    // Find the expected checksum for our asset
    let expected_checksum = parse_checksums(&checksums, asset_name)
        .ok_or_else(|| format!("Checksum not found for {asset_name}"))?;

    // Calculate actual checksum
    let actual_checksum = calculate_checksum(file_path)?;

    verify_checksum_match(&expected_checksum, &actual_checksum)
}

/// Download and install the update with checksum verification
pub fn perform_update(download_url: &str, checksums_url: Option<&str>) -> Result<(), String> {
    let current_exe = env::current_exe()
        .map_err(|e| format!("Could not determine current executable path: {e}"))?;

    println!("  Downloading update...");

    // Download to temp file
    let temp_dir = env::temp_dir();
    let temp_archive = temp_dir.join("poster_update.tar.gz");

    download_file(download_url, &temp_archive)?;

    // Verify checksum if available
    if let Some(checksums_url) = checksums_url {
        println!("  Verifying checksum...");
        if let Some(asset_name) = get_platform_asset() {
            verify_checksum(&temp_archive, checksums_url, asset_name)?;
        }
    }

    println!("  Extracting...");

    // Extract the binary
    let temp_binary = temp_dir.join("poster");
    extract_archive(&temp_archive, &temp_dir)?;

    // Verify extracted binary exists
    if !temp_binary.exists() {
        return Err(format!(
            "Extracted binary not found at {}",
            temp_binary.display()
        ));
    }

    println!("  Installing...");

    // Replace current executable
    replace_binary(&temp_binary, &current_exe)?;

    // Cleanup
    let _ = fs::remove_file(&temp_archive);
    let _ = fs::remove_file(&temp_binary);

    Ok(())
}

/// Download a file from URL to local path
pub fn download_file(url: &str, dest: &Path) -> Result<(), String> {
    let download_status = std::process::Command::new("curl")
        .args(["-L", "-o", dest.to_str().unwrap(), url])
        .status()
        .map_err(|e| format!("Failed to download: {e}"))?;

    if !download_status.success() {
        return Err("Download failed".to_string());
    }

    Ok(())
}

/// Extract archive to directory
pub fn extract_archive(archive: &Path, dest_dir: &Path) -> Result<(), String> {
    #[cfg(not(target_os = "windows"))]
    {
        let extract_status = std::process::Command::new("tar")
            .args([
                "-xzf",
                archive.to_str().unwrap(),
                "-C",
                dest_dir.to_str().unwrap(),
            ])
            .status()
            .map_err(|e| format!("Failed to extract: {e}"))?;

        if !extract_status.success() {
            return Err("Extraction failed".to_string());
        }
    }

    #[cfg(target_os = "windows")]
    {
        let archive_display = archive.display();
        let dest_display = dest_dir.display();
        let extract_status = std::process::Command::new("powershell")
            .args([
                "-Command",
                &format!(
                    "Expand-Archive -Path '{archive_display}' -DestinationPath '{dest_display}' -Force"
                ),
            ])
            .status()
            .map_err(|e| format!("Failed to extract: {e}"))?;

        if !extract_status.success() {
            return Err("Extraction failed".to_string());
        }
    }

    Ok(())
}

/// Replace the current binary with a new one
pub fn replace_binary(new_binary: &Path, current_exe: &Path) -> Result<(), String> {
    let backup_path = current_exe.with_extension("old");

    // Remove old backup if exists
    let _ = fs::remove_file(&backup_path);

    // Rename current to backup
    fs::rename(current_exe, &backup_path)
        .map_err(|e| format!("Failed to backup current binary: {e}"))?;

    // Copy new binary to current location
    fs::copy(new_binary, current_exe).map_err(|e| format!("Failed to install new binary: {e}"))?;

    // Set executable permissions on Unix
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(current_exe)
            .map_err(|e| format!("Failed to get permissions: {e}"))?
            .permissions();
        perms.set_mode(0o755);
        fs::set_permissions(current_exe, perms)
            .map_err(|e| format!("Failed to set permissions: {e}"))?;
    }

    // Remove backup
    let _ = fs::remove_file(&backup_path);

    Ok(())
}

/// Update result for CLI display
#[derive(Debug, Clone)]
pub enum UpdateResult {
    AlreadyLatest {
        current: String,
        latest: String,
    },
    UpdateAvailable {
        current: String,
        latest: String,
    },
    Updated {
        from: String,
        to: String,
    },
    UpdateFailed {
        current: String,
        latest: String,
        error: String,
        download_url: String,
    },
    NoBinaryAvailable {
        current: String,
        latest: String,
    },
    CheckFailed {
        error: String,
    },
}

/// Run the update check and optionally perform update
pub fn run_update(check_only: bool) -> UpdateResult {
    match check_for_update() {
        Ok(info) => {
            if info.update_available {
                if check_only {
                    return UpdateResult::UpdateAvailable {
                        current: info.current,
                        latest: info.latest,
                    };
                }
                if let Some(url) = info.download_url {
                    match perform_update(&url, info.checksums_url.as_deref()) {
                        Ok(()) => UpdateResult::Updated {
                            from: info.current,
                            to: info.latest,
                        },
                        Err(e) => UpdateResult::UpdateFailed {
                            current: info.current,
                            latest: info.latest,
                            error: e,
                            download_url: url,
                        },
                    }
                } else {
                    UpdateResult::NoBinaryAvailable {
                        current: info.current,
                        latest: info.latest,
                    }
                }
            } else {
                UpdateResult::AlreadyLatest {
                    current: info.current,
                    latest: info.latest,
                }
            }
        }
        Err(e) => UpdateResult::CheckFailed { error: e.clone() },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::TempDir;

    #[test]
    fn test_version_comparison() {
        assert!(is_newer_version("0.8.0", "0.7.0"));
        assert!(is_newer_version("1.0.0", "0.9.9"));
        assert!(is_newer_version("0.7.1", "0.7.0"));
        assert!(!is_newer_version("0.7.0", "0.7.0"));
        assert!(!is_newer_version("0.6.0", "0.7.0"));
        assert!(!is_newer_version("0.7.0", "0.8.0"));
    }

    #[test]
    fn test_current_version_set() {
        assert!(CURRENT_VERSION.contains('.'));
    }

    #[test]
    fn test_get_platform_asset() {
        let asset = get_platform_asset();
        #[cfg(any(
            all(target_os = "linux", target_arch = "x86_64"),
            all(target_os = "linux", target_arch = "aarch64"),
            all(target_os = "macos", target_arch = "aarch64"),
            all(target_os = "macos", target_arch = "x86_64"),
            all(target_os = "windows", target_arch = "x86_64")
        ))]
        {
            assert!(asset.is_some());
            let name = asset.unwrap();
            assert!(name.starts_with("poster-"));
        }
    }

    #[test]
    fn test_version_check_struct() {
        let check = VersionCheck {
            current: "0.7.0".to_string(),
            latest: "0.8.0".to_string(),
            update_available: true,
            download_url: Some("https://example.com/file.tar.gz".to_string()),
            checksums_url: Some("https://example.com/checksums.txt".to_string()),
        };
        assert!(check.update_available);
        assert!(check.download_url.is_some());
        assert!(check.checksums_url.is_some());
    }

    #[test]
    fn test_parse_checksums() {
        let input = r"abc123def456  poster-x86_64-unknown-linux-musl.tar.gz
789xyz000111  poster-aarch64-apple-darwin.tar.gz";

        let checksum = parse_checksums(input, "poster-x86_64-unknown-linux-musl.tar.gz");
        assert_eq!(checksum, Some("abc123def456".to_string()));

        let checksum_arm = parse_checksums(input, "poster-aarch64-apple-darwin.tar.gz");
        assert_eq!(checksum_arm, Some("789xyz000111".to_string()));

        let missing = parse_checksums(input, "nonexistent.tar.gz");
        assert!(missing.is_none());
    }

    #[test]
    fn test_verify_checksum_match_success() {
        let result = verify_checksum_match("abc123", "abc123");
        assert!(result.is_ok());
    }

    #[test]
    fn test_verify_checksum_match_failure() {
        let result = verify_checksum_match("abc123", "xyz789");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Checksum mismatch"));
    }

    #[test]
    fn test_calculate_checksum() {
        let temp_dir = TempDir::new().unwrap();
        let test_file = temp_dir.path().join("test.txt");
        let mut file = fs::File::create(&test_file).unwrap();
        file.write_all(b"test content").unwrap();

        let result = calculate_checksum(&test_file);
        assert!(result.is_ok());
        let checksum = result.unwrap();
        // SHA256 is always 64 hex characters
        assert_eq!(checksum.len(), 64);
    }

    #[test]
    fn test_calculate_checksum_missing_file() {
        let result = calculate_checksum(Path::new("/nonexistent/file.txt"));
        assert!(result.is_err());
    }

    #[test]
    fn test_replace_binary() {
        let temp_dir = TempDir::new().unwrap();

        // Create "new" binary
        let new_binary = temp_dir.path().join("new_binary");
        let mut f = fs::File::create(&new_binary).unwrap();
        f.write_all(b"new binary content").unwrap();

        // Create "current" binary
        let current_exe = temp_dir.path().join("current_binary");
        let mut f = fs::File::create(&current_exe).unwrap();
        f.write_all(b"old binary content").unwrap();

        let result = replace_binary(&new_binary, &current_exe);
        assert!(result.is_ok());

        // Verify the current exe now has new content
        let content = fs::read_to_string(&current_exe).unwrap();
        assert_eq!(content, "new binary content");
    }

    #[test]
    fn test_update_result_variants() {
        let _ = UpdateResult::AlreadyLatest {
            current: "0.7.0".to_string(),
            latest: "0.7.0".to_string(),
        };
        let _ = UpdateResult::UpdateAvailable {
            current: "0.7.0".to_string(),
            latest: "0.8.0".to_string(),
        };
        let _ = UpdateResult::Updated {
            from: "0.7.0".to_string(),
            to: "0.8.0".to_string(),
        };
        let _ = UpdateResult::UpdateFailed {
            current: "0.7.0".to_string(),
            latest: "0.8.0".to_string(),
            error: "err".to_string(),
            download_url: "url".to_string(),
        };
        let _ = UpdateResult::NoBinaryAvailable {
            current: "0.7.0".to_string(),
            latest: "0.8.0".to_string(),
        };
        let _ = UpdateResult::CheckFailed {
            error: "err".to_string(),
        };
    }

    #[test]
    fn test_run_update_check_only() {
        // This tests the check_only path - won't actually update
        // Note: This will make a network call to check for updates
        let result = run_update(true);
        // Result depends on network state and version comparison
        match result {
            UpdateResult::AlreadyLatest { .. }
            | UpdateResult::UpdateAvailable { .. }
            | UpdateResult::CheckFailed { .. } => {}
            _ => panic!("Unexpected result for check_only=true"),
        }
    }
}
