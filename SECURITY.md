# Security policy

## Supported versions

The latest `0.x` release and the `main` branch receive security fixes. Older releases receive no fixes.

## Reporting a vulnerability

Open the repository’s **Security** tab and select **Report a vulnerability** to file a private report through GitHub. Do not open public issues, pull requests, or discussions for suspected vulnerabilities.

Never include real keys, auth keys, node keys, tailnet or device names, or logs containing any of them. Use placeholders such as `tail0001` and `100.64.0.1`.

This policy covers Swiftail code. Report issues with Tailscale’s control server or Go client to Tailscale. A limitation documented in the [README’s Security section](README.md#security) or [module contracts](docs/contracts/) is insufficient on its own to establish a vulnerability.

A single maintainer handles reports on a best-effort basis, with no promised response time. Security fixes ship in a patch release, with an advisory when warranted.
