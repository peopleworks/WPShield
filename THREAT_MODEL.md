# Threat model

## Protected assets

- WordPress application files and upload directories.
- Availability of IIS-hosted sites.
- Administrative sessions and request secrets.
- Integrity of WPShield configuration and rules.

## Initial threats

- Upload of executable PHP content through vulnerable endpoints.
- Mismatch between declared file type, file extension, and content.
- Automated probing and repeated abusive requests.
- Host-header confusion in a multi-site deployment.
- Sensitive data leakage through security logs.

## Trust boundaries

- Internet to WPShield gateway.
- WPShield gateway to IIS loopback destinations.
- Management interface to local administrators.
- Community rule packages to the inspection engine.

## Required safeguards

- Monitor mode is the default.
- Unknown hosts fail closed.
- Request bodies are bounded and inspected by streaming.
- Logs redact authorization, cookies, tokens, and submitted secrets.
- Rule packages are versioned and reviewed.
- Production deployments have a documented bypass and rollback procedure.
