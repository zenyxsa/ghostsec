# Security policy

## Supported versions

Security fixes are applied to the latest version on the default branch. Older
snapshots may not receive updates.

## Reporting a vulnerability

Please do not publish unpatched vulnerability details in a public issue.
Use GitHub's **Report a vulnerability** flow in the repository's Security tab
to send a private report. Include the affected commit or release, impact,
reproduction steps, and relevant logs with secrets and personal data removed.

The maintainers will assess the report and coordinate a fix and disclosure.
Do not include real credentials, leaked data, or third-party target data in a
report.

## Safe-use boundaries

GhostSec is designed for authorized defensive assessments. Its scanning tools
can generate traffic and affect services. Use only targets you own or have
explicit permission to assess. Do not use the project to execute exploits,
obtain credentials, evade monitoring, or access systems without authorization.
