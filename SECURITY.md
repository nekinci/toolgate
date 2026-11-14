# Security policy

Toolgate holds credentials for other services, so security reports are
taken seriously.

## Reporting a vulnerability

Please **do not open a public issue**. Use GitHub's private vulnerability
reporting ("Security" tab → "Report a vulnerability") on this repository.
Include what you found, how to reproduce it, and the impact you expect. You
should get an answer within a week.

## Scope

In scope, for example:

- an agent (anything holding an `agw_` token) reading a secret value, an OAuth
  token, the master key or the admin token;
- an agent loosening a restriction or changing what a server runs or where it
  sends data without the user's approval (see "Security model" in the README);
- bypassing tool pinning, the localhost/`Host`/`Origin` checks, CSRF
  protection, pairing-code limits or token expiry;
- the API proxy sending a pooled key anywhere other than the pool's base URL,
  or leaking it to the client or the logs;
- a local user (other than root and the service user) reading the data
  directory of an isolated install.

Out of scope: attacks that need root or the service user's privileges, a
malicious upstream MCP server returning bad *results* (it is trusted with the
data you send it), and denial of service from a local process.

## Hardening tips

- Use the isolated install (`sudo toolgate install`).
- Give each agent its own token, a lifetime, and allow/deny patterns that fit
  what it does; keep `can_manage` for the agents that need it.
- Leave the audit argument mode at `keys` (default) or `none` unless you need
  full arguments.
