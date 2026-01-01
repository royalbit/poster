# RoyalBit Poster

Social media automation CLI for LinkedIn and X.

## Install

From releases:

```bash
# macOS (Apple Silicon)
curl -L https://github.com/royalbit/poster/releases/latest/download/poster-aarch64-apple-darwin.tar.gz | tar xz
sudo mv poster /usr/local/bin/

# macOS (Intel)
curl -L https://github.com/royalbit/poster/releases/latest/download/poster-x86_64-apple-darwin.tar.gz | tar xz
sudo mv poster /usr/local/bin/

# Linux (x64)
curl -L https://github.com/royalbit/poster/releases/latest/download/poster-x86_64-unknown-linux-musl.tar.gz | tar xz
sudo mv poster /usr/local/bin/

# Linux (ARM64)
curl -L https://github.com/royalbit/poster/releases/latest/download/poster-aarch64-unknown-linux-musl.tar.gz | tar xz
sudo mv poster /usr/local/bin/
```

From crates.io:

```bash
cargo install royalbit-poster
```

## Usage

```
poster <COMMAND>

Commands:
  init       Initialize configuration
  list       List posts from posts.yaml
  linkedin   LinkedIn commands (auth, post, post-all)
  x          X/Twitter commands (auth, post, post-all)
  post-all   Post to all platforms
```

## Setup

1. Create API credentials:
   - LinkedIn: [Developer Portal](https://developer.linkedin.com/)
   - X: [Developer Portal](https://developer.x.com/)

2. Store credentials in pass:
   ```bash
   pass insert royalbit/linkedin  # client_id, client_secret
   pass insert royalbit/x         # client_id, client_secret (optional)
   ```

3. Authenticate:
   ```bash
   poster linkedin auth
   poster x auth
   ```

4. Create posts.yaml and post:
   ```bash
   poster init
   poster list
   poster post-all --dry-run
   poster post-all
   ```

## License

[Elastic License 2.0](LICENSE) - RoyalBit Inc.
