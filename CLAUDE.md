# CLAUDE.md

Agent guidance for **msp-security-console** (DTC Inc.).

## Credentials never live in code

No key, password, token, connection string, installer or enrollment token goes into this repo: not in code, tests, samples, comments, commit messages or PR descriptions. Credentials live in a vault (1Password, Azure Key Vault, Windmill secret variables, NinjaOne script variables or CI secrets) and code reads them at run time; a reference such as `op://vault/item/field` is fine to commit. A credential found in code is leaked: rotate it first, then remove it from the code, and record the location and type (never the value) on a Halo ticket. The standard: https://kb.dtctoday.com/books/developer-operations-devops/page/credentials-never-live-in-code-the-standard
