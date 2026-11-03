# Security policy

## Report a vulnerability

Do not report a vulnerability in a public issue.

Use GitHub private vulnerability reporting:
<https://github.com/willbara/locksmith/security/advisories/new>

Give this data in your report:

1. The Locksmith version and the operating system.
2. The steps that cause the problem. Attach a sample file if possible.
3. The effect. For example: data becomes visible, a key becomes known, or a file opens with changed
   contents.

You get a reply in 7 days or less. When a fix is available, the advisory becomes public. You get
credit in the advisory if you want it.

## Supported versions

Only the latest release gets security fixes.

## Scope

[docs/FORMAT.md](docs/FORMAT.md) section 19 and the limits in
[docs/SECURITY_MODEL.md](docs/SECURITY_MODEL.md) give the known limits. These are not vulnerabilities. A difference between the code and docs/FORMAT.md is a
vulnerability if it makes a file less secure.
