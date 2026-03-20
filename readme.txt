=== OIDC Client ===
Contributors: johannesroesch
Tags: openid-connect, oauth2, sso, authentication, login
Requires at least: 5.9
Tested up to: 6.9
Requires PHP: 7.4
Stable tag: 1.0.0
License: GPL-2.0-or-later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

WordPress login via OpenID Connect – Authorization Code Flow with PKCE, token encryption, role mapping, and session management.

== Description ==

**OIDC Client** enables your WordPress site to authenticate users via any standard OpenID Connect provider. The login is handled through the secure Authorization Code Flow with PKCE (Proof Key for Code Exchange, RFC 7636).

Works out of the box with **Keycloak**, **Microsoft Entra ID (Azure AD)**, **Google**, **Okta**, **Auth0**, **easyVerein**, and any other standards-compliant provider.

= Key Features =

* **Authorization Code Flow + PKCE (S256)** – prevents authorization code interception attacks
* **Auto-Discovery** – automatically fills all endpoints from `/.well-known/openid-configuration`
* **JWT signature verification** – RS256 validation via JWKS endpoint with 1-hour cache and automatic key rotation
* **Token encryption** (AES-256-CBC) – optionally encrypts access, refresh, and ID tokens at rest
* **Session management** – ties WordPress sessions to token expiry; silently refreshes via refresh token; terminates session on failure
* **Frontchannel logout** and **Backchannel logout** (REST endpoint `POST /wp-json/oidc/v1/backchannel-logout`)
* **Account linking** – link and unlink existing WordPress accounts to an OIDC provider from the user profile
* **Role mapping** – map claim values to WordPress roles via simple line-based configuration (`claim-value=role`)
* **Lock email address** – prevents OIDC-linked users from changing their email in WordPress
* **Lock password** – prevents OIDC-linked users from changing their password in WordPress
* **Profile picture sync** – uses the `picture` claim as the WordPress avatar
* **Remember me** – configurable persistent or session-only auth cookie
* **Hide login form** – shows only the OIDC button; still reachable via `?showlogin=1`
* **Auto-login** – immediately redirects to the OIDC provider when the login page is visited
* **Login log** – logs all login attempts (success and failure) to a database table, viewable in wp-admin
* **Translations** – de_DE, en_US, fr_FR, es_ES, sv_SE

= Requirements =

* PHP 7.4 or higher with the `openssl` extension
* WordPress 5.9 or higher
* An OIDC provider that supports Authorization Code Flow

== Installation ==

= From the WordPress Plugin Directory =

1. Go to **Plugins → Add New** in your WordPress admin.
2. Search for **OIDC Client**.
3. Click **Install Now**, then **Activate**.

= Manual Installation =

1. Download the latest `oidc-client-x.y.z.zip` from the [releases page](https://github.com/johannesroesch/oidc-client/releases).
2. Go to **Plugins → Add New → Upload Plugin**.
3. Select the ZIP file and click **Install Now**.
4. Activate the plugin.

= Quick Start =

1. Go to **Settings → OIDC Client**.
2. Enter your provider's Discovery URL (e.g. `https://keycloak.example.com/realms/myrealm/.well-known/openid-configuration`) and click **Endpoints abrufen** – all endpoints are filled in automatically.
3. Enter your **Client ID** and **Client Secret** from your provider.
4. Save – the OIDC login button will appear on the WordPress login page immediately.

== Frequently Asked Questions ==

= Which providers are supported? =

Any provider that supports the OpenID Connect Authorization Code Flow. Tested with Keycloak, Microsoft Entra ID (Azure AD), Google, Okta, Auth0, and easyVerein.

= Does this replace the WordPress login? =

No. WordPress password login remains available as a fallback at all times. You can optionally hide the login form to show only the OIDC button, with `?showlogin=1` still giving access to the password form.

= Can existing WordPress accounts be linked? =

Yes. Users can link and unlink their account from the user profile page under **OpenID Connect**.

= Is the login secure? =

Yes. The plugin uses PKCE (S256) to prevent code interception attacks, validates JWT signatures via RS256/JWKS, and optionally encrypts tokens at rest using AES-256-CBC.

= Where are tokens stored? =

In WordPress user meta (`_oidc_access_token`, `_oidc_refresh_token`, `_oidc_id_token`). With token encryption enabled, they are stored with an `enc:` prefix in AES-256-CBC encrypted form.

= What happens when the access token expires? =

The plugin automatically attempts a silent token refresh using the refresh token. If the refresh fails (e.g. the session was revoked at the provider), the WordPress session is terminated and the user is redirected to the login page.

= How do I configure role mapping? =

In **Settings → OIDC Client → Rollen-Mapping**, set the claim name (e.g. `roles`) and add one mapping per line in the format `claim-value=wordpress-role` (e.g. `wordpress-editors=editor`).

= How do I set up backchannel logout? =

Register `https://your-site.com/wp-json/oidc/v1/backchannel-logout` as the backchannel logout URI at your provider.

== Screenshots ==

1. Settings page – Provider configuration with Auto-Discovery
2. Settings page – User management and role mapping
3. Login page with OIDC button
4. User profile – Account linking section
5. Login log in wp-admin

== Changelog ==

= 1.0.0 – 2026-03-20 =
* Initial release
* Authorization Code Flow with PKCE (S256)
* Auto-Discovery from `/.well-known/openid-configuration`
* JWT signature verification (RS256/JWKS) with 1-hour cache
* Token encryption at rest (AES-256-CBC)
* Session management with automatic token refresh
* Frontchannel and backchannel logout
* Account linking and unlinking
* Role mapping via claim values
* Lock email and password for OIDC-linked users
* Profile picture sync from `picture` claim
* Configurable remember-me / session cookie
* Hide login form / Auto-login
* Login log in wp-admin
* Translations: de_DE, en_US, fr_FR, es_ES, sv_SE

== Upgrade Notice ==

= 1.0.0 =
Initial release – no upgrade steps required.
