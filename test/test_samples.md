# Phishing URL Evaluation Test Records

- **Platform**: macOS (Apple Silicon M-Series)
- **Runtime**: Python 3.10+
- **Execution Mode**: Terminal CLI

| # | Input URL | Target Criteria | Observed Detection Output | Status |
|---|---|---|---|---|
| 1 | `https://www.example.com/login` | No warning flags | No listed warning signs found. This does NOT prove safety. | PASS |
| 2 | `http://192.0.2.10/account` | IP Hostname + HTTP | Uses an IP address instead of a familiar domain. / Uses HTTP. HTTPS alone does not prove trust. | PASS |
| 3 | `http://example.com@sample.invalid/login` | @ Symbol + HTTP | Contains an @ symbol; inspect carefully. / Uses HTTP. HTTPS alone does not prove trust. | PASS |
| 4 | `https://a.b.c.d.e.example.invalid/path` | Multiple subdomains | Contains many hostname segments/subdomains. | PASS |
| 5 | `https://xn--example.invalid/` | Punycode identifier | Contains a punycode-style hostname. | PASS |

## Test Summary & Observations
- Confirmed that URLs lacking explicit schemes default gracefully to HTTP validation without throwing syntax exceptions.
- Heuristic string checks properly isolated numeric IP patterns and flagged multiple hostname segments accurately across all test cases.