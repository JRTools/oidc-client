=== OIDC Client ===
Contributors: johannesroesch
Tags: openid-connect, oauth2, sso, authentication, login
Requires at least: 6.7
Tested up to: 7.0
Requires PHP: 8.1
Stable tag: 1.2.0
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
* **Frontchannel logout** and **Backchannel logout** (REST endpoint `POST /wp-json/oidc-client/v1/backchannel-logout`)
* **Account linking** – link and unlink existing WordPress accounts to an OIDC provider from the user profile
* **Role mapping** – map claim values to WordPress roles via simple line-based configuration (`claim-value=role`)
* **Lock email address** – prevents OIDC-linked users from changing their email in WordPress
* **Lock password** – prevents OIDC-linked users from changing their password in WordPress
* **Profile picture sync** – uses the `picture` claim as the WordPress avatar
* **Standard Claims mapping** – automatically maps all OIDC Core 1.0 §5.1 standard claims (`name`, `given_name`, `family_name`, `nickname`, `locale`, `birthdate`, `zoneinfo`, `phone_number`, `address`, and more) to WordPress profile fields and user meta on every login
* **Remember me** – configurable persistent or session-only auth cookie
* **Hide login form** – shows only the OIDC button; still reachable via `?showlogin=1`
* **Auto-login** – immediately redirects to the OIDC provider when the login page is visited
* **Login log** – logs all login attempts (success and failure) to a database table, viewable in wp-admin
* **Translations** – de_DE, en_US, fr_FR, es_ES, sv_SE

= Requirements =

* PHP 8.1 or higher with the `openssl` extension
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

Register `https://your-site.com/wp-json/oidc-client/v1/backchannel-logout` as the backchannel logout URI at your provider.

== Screenshots ==

1. Settings page – Provider configuration with Auto-Discovery
2. Settings page – User management and role mapping
3. Login page with OIDC button
4. User profile – Account linking section
5. Login log in wp-admin

== Changelog ==

= 1.2.0 – 2026-07-13 =
* Full OIDC Core 1.0 §5.1 standard claims mapping: all standard claims (`name`, `given_name`, `family_name`, `nickname`, `locale`, `middle_name`, `birthdate`, `gender`, `zoneinfo`, `phone_number`, `phone_number_verified`, `email_verified`, `profile`, `address`, `updated_at`) are now mapped to WordPress profile fields and `_oidc_*` user meta on every login
* `nickname` claim is now mapped to both `user_nicename` (wp_users column) and the native `nickname` usermeta key
* Username derivation on new user creation: `preferred_username` → `nickname` → email prefix
* `display_name` and `user_url` are now also set on new user creation (previously update-only)
* Bugfix: removed deprecated `openssl_free_key()` call (deprecated since PHP 8.0)
* Bugfix: array-valued URL claims (e.g. `profile`) no longer cause a `TypeError` in `sync_user_meta()`
* Architecture: `OIDC_Auth` refactored into `OIDC_Token_Exchange` and `OIDC_User_Manager`; `OIDC_Admin` split into `OIDC_Admin_Fields` and `OIDC_Admin_Sanitize`; JWK logic extracted to `OIDC_JWK_Helper`
* Documentation updated: admin guide extended with claims mapping reference, developer guide updated with new class architecture
* CI: Mutation Testing now runs on PHP 8.4; all CI quality gates green

= 1.1.1 – 2026-06-30 =
* CI fixes: Infection upgraded to 0.32, Mutation Testing job moved to PHP 8.4
* SonarCloud organisation reconfigured; all open issues resolved
* WordPress 7.0 compatibility: "Tested up to" header updated
* Dependabot updates: actions/cache, mikepenz/action-junit-report, codecov/codecov-action, release-drafter, softprops/action-gh-release

= 1.1.0 – 2026-03-24 =
* Backchannel-Logout-URL korrigiert
* Mindest-PHP-Version auf 8.1 angehoben
* CI-Pipeline mit PHPStan, Infection und SonarCloud erweitert
* Testabdeckung deutlich erhöht
* SonarCloud-Issues behoben
* Abhängigkeiten aktualisiert

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

= 1.2.0 =
New standard claims mapping: additional user meta fields (`_oidc_*`) are written on login for any OIDC Core §5.1 claims your provider sends. No breaking changes – existing installations upgrade seamlessly.

= 1.0.0 =
Initial release – no upgrade steps required.
