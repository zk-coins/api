# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in zkCoins, please report it responsibly:

1. **Do NOT open a public GitHub issue**
2. Email: security@zkcoins.app
3. Include: description, reproduction steps, impact assessment
4. We will acknowledge within 48 hours and provide a fix timeline

This repository **is** the standalone API process. Vulnerabilities in the live
REST surface are reported here (same email). Issues in the trustless
node kernel still go to [zk-coins/node](https://github.com/zk-coins/node)
(see Scope table).

## Scope

| Component                                  | In Scope |
| ------------------------------------------ | -------- |
| REST endpoints                             | Yes      |
| Capability gating / rate limiting          | Yes      |
| LNURL / alias / push-subscription database | Yes      |
| Node kernel (see [zk-coins/node](https://github.com/zk-coins/node)) | Report there |
| Documentation                              | No       |

## Supported Versions

Only the latest version on `develop` is supported with security updates.

## Responsible Disclosure

We follow a 90-day disclosure policy. After reporting, we will:

1. Confirm the vulnerability within 48 hours
2. Develop and test a fix
3. Release the fix
4. Credit the reporter (unless they prefer anonymity)
