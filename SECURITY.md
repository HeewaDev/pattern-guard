# Security policy

Pattern-Guard sits in front of other people's applications, so a weakness in it can expose
everything behind it. Reports are very welcome.

## Reporting a vulnerability

**Please do not open a public issue.** Report privately through GitHub: open the
repository's **Security** tab and choose **Report a vulnerability**. If that is not
possible, open an issue that only asks for a private contact, without details.

Useful in a report:
- the component (gateway, WAF, behavioural engine, CLI) and the version or commit;
- what an attacker gains (a WAF bypass, a policy bypass, identity spoofing, a crash, memory or CPU exhaustion, …);
- a minimal reproduction: the request(s) and the relevant config.

You will get an acknowledgement, a fix or mitigation plan, and credit in the CHANGELOG
if you want it. Please allow time for a fix before publishing.

## Scope

In scope:
- The gateway (`crates/gateway`): bypassing a configured protection, spoofing the client
  identity, forging challenge clearance, abusing a protection against other users, crashes,
  unbounded resource use.
- The WAF (`crates/waf`): systematic detection bypasses with a root cause (a decoder gap, a
  parser differential), crashes, inputs with disproportionate CPU cost.
- The behavioural engine (`crates/engine`): unbounded memory, crashes, ways to make
  legitimate users look abusive.

Known and documented limits are not vulnerabilities by themselves. See
[docs/GATEWAY.md](docs/GATEWAY.md#limits-of-this-version) and
[docs/architecture/gateway.md](docs/architecture/gateway.md). Examples: the admin port has no
authentication (bind it to loopback or a private network), and with
`waf.flag_oversize = false` only the first `waf.inspect_body_bytes` of a body are inspected.
Individual payloads that score just
under the threshold are better filed as regular detection issues.

## Supported versions

Pattern-Guard is pre-1.0. Fixes go to the latest release and `main`.
