# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this project is

A WordPress plugin named JRTools OpenID Connect implementing OpenID Connect (OIDC) Authorization Code Flow with PKCE. Supports Keycloak, Microsoft Entra ID, Google, Okta, Auth0, and any OIDC-compliant provider.

## Commands

```sh
make install   # composer install
make test      # phpunit
make lint      # phpcs (WordPress Coding Standards)
make fix       # phpcbf (auto-fix style issues)
make ci        # install → lint → test (full pipeline)
make build     # create distribution ZIP via bin/build.sh
make clean     # remove build artifacts
```

Run a single test class:
```sh
vendor/bin/phpunit tests/Unit/JwtHelperTest.php
```

Run a specific test method:
```sh
vendor/bin/phpunit --filter test_method_name tests/Unit/JwtHelperTest.php
```

Static analysis:
```sh
vendor/bin/phpstan analyse
```

Mutation testing:
```sh
vendor/bin/infection
```

## Architecture

**Initialization** (`jrtools-openid-connect.php`):
1. Activation hook → `OIDC_Log::install()` (creates DB log table)
2. Requires all class files in dependency order
3. On `plugins_loaded` → instantiates: `OIDC_Log`, `OIDC_Logout`, `OIDC_Profile`, `OIDC_Admin`, `OIDC_Auth`, `OIDC_Login`

**Auth flow:**
```
OIDC_Login::handle_login_action()
  → OIDC_Auth::initiate_login()      # generates state/nonce/PKCE, redirects to provider
  → [provider redirects back]
  → OIDC_Auth::handle_callback()     # exchanges code for tokens
  → OIDC_JWT_Helper::verify_signature()
  → OIDC_Tokens::store_tokens()      # optional AES-256-CBC encryption
  → OIDC_Roles::apply_role_mapping()
  → OIDC_Profile (sync metadata)
  → wp_set_auth_cookie()
```

**Classes in `includes/`:**

| Class | Responsibility |
|---|---|
| `OIDC_JWT_Helper` | Static utility: JWT parsing, JWKS fetching, RS256 signature verification, JWK→PEM |
| `OIDC_Auth` | Authorization Code Flow + PKCE, callback handler, session validity, token refresh on `init` |
| `OIDC_Login` | Login button UI, error display, auto-login, optional WP login form hiding |
| `OIDC_Admin` | Settings page, Discovery URL auto-fetch (AJAX), cache clearing |
| `OIDC_Tokens` | Token storage/retrieval, optional AES-256-CBC encryption, access token refresh |
| `OIDC_Logout` | Frontchannel logout (redirect), backchannel logout (REST endpoint) |
| `OIDC_Roles` | Maps OIDC claims to WordPress roles |
| `OIDC_Profile` | Account linking UI, email/password field locking for OIDC users, avatar sync |
| `OIDC_Log` | DB-backed logging table + admin log page |

## Tests

Unit tests use **PHPUnit + Brain\Monkey** (WordPress hook/function mocking). Each test class extends `WpTestCase` which handles Brain\Monkey setup/teardown.

WordPress functions (e.g. `get_option`, `wp_remote_get`) are mocked via `Mockery` or `Brain\Monkey\Functions`. Global constants (`ABSPATH`, `OIDC_*`) are defined in `tests/bootstrap.php`.

Quality gates in CI:
- PHPStan level 5 (`phpstan.neon`)
- WordPress Coding Standards (`phpcs`)
- Mutation testing via Infection (min MSI 70%, covered MSI 80%)
- Coverage upload to Codecov

## WordPress Compatibility Policy

The plugin officially supports the **last 4 WordPress minor versions**. When a new minor version is released, the oldest one is dropped.

- `Requires at least` = oldest supported version (lowest in the CI matrix)
- `Tested up to` = newest supported version (highest in the CI matrix)
- CI matrix in `.github/workflows/ci.yml` always reflects exactly these 4 versions
- Run **Actions → "WordPress-Versionen aktualisieren"** to detect new releases and open an automated PR

When updating the matrix, these files must stay in sync:
- `.github/workflows/ci.yml` — matrix `wp:`
- `.github/workflows/release.yml` — `WP_TESTED_UP_TO`, `WP_REQUIRES_AT_LEAST`
- `readme.txt` — `Tested up to`, `Requires at least`
- `jrtools-openid-connect.php` — `Requires at least` in plugin header

## External services

- SonarCloud: https://sonarcloud.io/project/overview?id=JRTools_oidc-client
- Codecov: https://app.codecov.io/gh/JRTools/oidc-client
