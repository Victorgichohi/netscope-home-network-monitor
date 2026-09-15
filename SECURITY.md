# Security Policy

## Scope

NetScope captures network metadata and can optionally control a router. Treat every deployment as security-sensitive, even on a home network.

## Safe deployment

- Keep `.env` files, SQLite databases, packet-capture output, router credentials, and SSH keys out of source control.
- Bind to localhost unless remote access is required.
- Use HTTPS and a private VPN or trusted management network for remote access.
- Do not expose a root-run NetScope process directly to the LAN or internet.
- Give router adapters a dedicated least-privilege account that can run only the required status or reboot operation.
- Review captured metadata before sharing logs or screenshots because hostnames, IP addresses, and destinations can be sensitive.

## Reporting a vulnerability

Do not open a public issue containing credentials, private network data, or exploit details. Contact the repository owner privately through their GitHub profile with a concise description, affected version, reproduction steps, and expected impact.

Only test networks and devices you own or are explicitly authorized to administer.
