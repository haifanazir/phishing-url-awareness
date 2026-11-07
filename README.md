# Defensive Phishing URL Text Inspector

## Overview
Social engineering and phishing attacks frequently rely on confusing web links to deceive targets into providing sensitive information. This command-line utility evaluates the text structure of a provided URL against recognizable structural indicators of malicious links, entirely offline and without making HTTP requests.

## Key Detection Features
- Flags URL strings containing `@` symbols (credential/host obfuscation).
- Identifies lengthy URLs exceeding 100 total characters.
- Detects hostnames specified directly as numeric IPv4 addresses.
- Detects excessive subdomain levels (5 or more dot-delimited segments).
- Identifies internationalized domain names leveraging Punycode syntax (`xn--`).
- Identifies unencrypted plain HTTP transport schemes.
- **Improvement B (Review Banner)**: Integrates a dedicated summary banner alerting users to the exact quantity of flagged indicators found.
- **Improvement E (Numbered Output)**: Formats findings into an indexed, easy-to-read list for clearer interpretation.

## Environment Requirements
- Python 3.10 or higher.
- Requires no external pip libraries.

## How to Run
macOS / Linux:
```bash
python3 phishing_checker.py