# Security Policy

## Supported Versions
| Version | Supported |
| ------- | --------- |
| 0.x.x   | ✅        |

## Reporting a Vulnerability
Do NOT open a public GitHub issue for security vulnerabilities.

Email: cloudctlhq@gmail.com
Response time: Within 48 hours

## Security Measures
- All code scanned with Bandit + Semgrep on every commit
- Dependencies checked with pip-audit weekly
- Secrets scanning enabled on all branches via Gitleaks
- No static credentials ever stored
- All cloud access is read-only by default
- Human approval required before any write actions
