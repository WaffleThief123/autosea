# AutoSea

> The Internet is like a giant body of water, everything connected in ways we might not always *sea*.

AutoSea is a reconnaissance tool designed for Trust & Safety teams and Abuse Researchers. It provides rapid analysis of suspicious domains, including URL deobfuscation, HTTP header inspection, DNS lookups, and VirusTotal reputation checks—all with YAML-formatted output for easy documentation.

## Features

- **URL Deobfuscation** — Automatically converts obfuscated URLs (`hxxp://`, `[.]`, etc.) to standard format
- **HTTP Header Analysis** — Fetches response headers and follows redirect chains
- **DNS Lookup** — Resolves domain records via the `host` command
- **VirusTotal Integration** — Queries VT API for domain reputation and detection counts
- **YAML Output** — Results formatted for easy pasting into case notes

## Installation

### Prerequisites

- Python 3.x with pip
- System utilities: `jq`, `curl`, `host`, `base64`, `sha256sum`, `sha512sum`, `sed`, `awk`
- A [VirusTotal API key](https://support.virustotal.com/hc/en-us/articles/115002100149-API)

### Setup

1. Clone the repository:
   ```bash
   git clone https://github.com/wafflethief123/autosea.git
   cd autosea
   ```

2. Configure your environment:
   ```bash
   cp ./data/.env.example ./data/.env
   # Edit ./data/.env and add your VirusTotal API key
   ```

3. Install dependencies:

   **Linux** (auto-detects dnf/yum/apt):
   ```bash
   ./core.sh --install-requirements
   ```

   **macOS** (requires Homebrew, Python3, and pip):
   ```bash
   python3 -m pip install -r ./data/python-requirements.txt --break-system-packages
   ```

### Docker

```bash
# Build and run with a target URL
TARGET_URL=https://example.com docker-compose up --build
```

## Usage

```bash
# Analyze a single domain
./core.sh https://example.com

# Analyze multiple domains
./core.sh https://example.com https://example.net https://example.org

# Configure a custom user agent
./core.sh --user-agent
```

## Exit Codes

| Code | Description |
|------|-------------|
| 1 | General error (accompanied by text explanation) |
| 2 | Invalid URL format (failed regex validation) |
| 3 | No URL provided |

## Contributing

Contributions are welcome. To add a new module:

1. Create your module in the working directory (it will be sourced on startup)
2. Add any new dependencies to `./data/bash-requirements.yml`
3. Ensure output follows YAML format:

   ```yaml
   commandName:
       response:
           key: value
           list:
           - item 1
           - item 2
   ```

4. Submit a pull request with your changes

## License

See [LICENSE](LICENSE) for details.