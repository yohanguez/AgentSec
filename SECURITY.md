# Security Policy

## Overview

AgentSec is a security analysis tool designed to audit AI agent workflows. We take security seriously and appreciate responsible disclosure of any vulnerabilities found in this project.

## Good Practices

:warning: **You must never store credentials information into source code or config files in a GitHub repository**

- Block sensitive data being pushed to GitHub by git-secrets or similar tools as a git pre-commit hook
- Audit for slipped secrets with dedicated tools
- Use environment variables for secrets in CI/CD (e.g., GitHub Secrets) and secret managers in production
- Review code changes for accidentally committed credentials, API keys, or tokens

## Supported Versions

The following versions of AgentSec are currently supported with security updates:

| Version | Supported          |
| ------- | ------------------ |
| 1.0.x   | :white_check_mark: |
| < 1.0   | :x:                |

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues.**

If you discover a security vulnerability in AgentSec, please report it by emailing:

**security@imperva.com**

Please include the following information in your report:

- Type of vulnerability
- Full paths of source file(s) related to the vulnerability
- Location of the affected source code (tag/branch/commit or direct URL)
- Step-by-step instructions to reproduce the issue
- Proof-of-concept or exploit code (if available)
- Impact of the vulnerability, including how an attacker might exploit it

### What to Expect

- **Acknowledgment**: We will acknowledge receipt of your vulnerability report within 48 hours
- **Updates**: We will send you regular updates about our progress
- **Disclosure**: Once the vulnerability is fixed, we will notify you and may publicly disclose the issue
- **Credit**: We will give you credit for the discovery in our security advisory (unless you prefer to remain anonymous)

## Disclosure Policy

### Coordinated Disclosure

We follow a coordinated disclosure process:

1. **Report received**: Security team acknowledges the report within 48 hours
2. **Investigation**: We investigate and validate the vulnerability (1-5 business days)
3. **Fix development**: We develop and test a fix
4. **Release**: We release a patched version
5. **Public disclosure**: We publish a security advisory with credit to the reporter (after a fix is available)

### Timeline

- We aim to release a fix within **30 days** for critical vulnerabilities
- We aim to release a fix within **90 days** for medium/low severity issues
- We will coordinate the disclosure date with the reporter

## Security Update Policy

### How We Notify Users

- **GitHub Security Advisories**: Published for all security fixes
- **Release Notes**: Security fixes are clearly marked in release notes
- **Mailing List**: Critical vulnerabilities will be announced (when mailing list is established)

### Update Recommendations

- Subscribe to repository releases to receive notifications
- Regularly update to the latest version
- Review the CHANGELOG.md for security-related fixes

## Security-Related Configuration

### Best Practices for Deploying AgentSec

1. **Run with Least Privilege**
   - Do not run AgentSec with elevated privileges unless absolutely necessary
   - The `monitor` command requires root/sudo for network monitoring, but scan operations do not

2. **Protect Report Outputs**
   - HTML and JSON reports may contain sensitive information about your infrastructure
   - Store reports securely and limit access to authorized personnel
   - Consider encrypting reports at rest if they contain highly sensitive data

3. **Secure API Endpoints**
   - If using `agentsec serve`, ensure the dashboard is not exposed to the public internet
   - Use a reverse proxy with authentication if remote access is needed
   - Consider using HTTPS with valid certificates for production deployments

4. **Monitor Access to Analysis Targets**
   - AgentSec analyzes source code and may access sensitive workflow configurations
   - Ensure analysis is performed in secure environments
   - Review file access permissions before running analysis

5. **Dependency Management**
   - Regularly update dependencies to receive security patches
   - Use `pip audit` or similar tools to scan for known vulnerabilities
   - Review dependency licenses for compliance

## Known Security Gaps & Future Enhancements

### Current Limitations

1. **Static Analysis Only**
   - AgentSec performs static code analysis and does not sandbox or execute analyzed code
   - Runtime vulnerabilities may not be detected

2. **AST Parsing Coverage**
   - Custom tool detection relies on AST pattern matching
   - Obfuscated or dynamically generated code may not be fully analyzed

3. **Framework Support**
   - Only specific frameworks are supported (LangGraph, CrewAI, Autogen, OpenAI, n8n)
   - Custom agent implementations may not be fully covered

4. **Network Monitoring Privileges**
   - The `monitor` command requires elevated privileges (root/sudo)
   - This increases the attack surface if the tool is compromised

### Planned Improvements

- [ ] Add sandboxed dynamic analysis capabilities
- [ ] Implement cryptographic signing for reports
- [ ] Add SBOM (Software Bill of Materials) generation
- [ ] Implement rate limiting for web dashboard API
- [ ] Add authentication/authorization for multi-user deployments
- [ ] Provide unprivileged monitoring alternatives where possible

## Security Testing

AgentSec itself undergoes security analysis:

- **Static Analysis**: Linted with ruff, type-checked with mypy
- **Dependency Scanning**: Dependencies monitored for known vulnerabilities
- **Code Review**: All changes reviewed before merge
- **Automated Testing**: CI/CD pipeline runs security checks

## Contact

For security-related questions or concerns:

- **Security issues**: security@imperva.com
- **General questions**: Open a GitHub issue (non-security related only)

## Acknowledgments

We appreciate the security research community and thank all researchers who report vulnerabilities responsibly.

---

**Last Updated**: 2026-09-23
