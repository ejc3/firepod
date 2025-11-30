# Build Instructions for Firepod

## Building with Cargo (Recommended for Development)

```bash
# Build debug version
cargo build

# Build release version
cargo build --release

# Run tests
cargo test

# Build and install
cargo install --path ./fcvm
```

## Building with Buck2 (Production Builds)

Buck2 is configured for high-performance, reproducible builds.

### Prerequisites

1. Install Buck2:
```bash
# On Linux
curl -L https://github.com/facebook/buck2/releases/latest/download/buck2-x86_64-unknown-linux-gnu.zst | zstd -d > /usr/local/bin/buck2
chmod +x /usr/local/bin/buck2
```

2. Set up Buck2 prelude (if not already done):
```bash
git clone https://github.com/facebook/buck2-prelude.git prelude
```

### Build Commands

```bash
# Build the main binary
buck2 build //fcvm:fcvm

# Build in release mode
buck2 build //fcvm:fcvm --mode=release

# Run tests
buck2 test //fcvm:fcvm-test

# Clean build artifacts
buck2 clean
```

### Build Output

- Debug builds: `buck-out/v2/gen/fcvm/fcvm/__fcvm__/fcvm`
- Release builds: `buck-out/v2/gen/release/fcvm/fcvm/__fcvm__/fcvm`

## Cross-Compilation

Buck2 makes cross-compilation straightforward:

```bash
# Build for ARM64
buck2 build //fcvm:fcvm --target-platforms=//:arm64-linux

# Build for multiple platforms
buck2 build //fcvm:fcvm --target-platforms=//:x86_64-linux,//:arm64-linux
```

## CI/CD Integration

Buck2 is ideal for CI/CD pipelines due to its:
- Deterministic builds
- Fine-grained caching
- Parallel execution
- Remote execution support

Example CI configuration:
```yaml
- name: Build with Buck2
  run: |
    buck2 build //fcvm:fcvm --mode=release
    buck2 test //fcvm:...
```

## Development Workflow

For active development, use Cargo for faster iteration:
```bash
cargo watch -x 'check' -x 'test' -x 'run'
```

For production releases and CI, use Buck2 for reproducible builds:
```bash
buck2 build //fcvm:fcvm --mode=release
```
