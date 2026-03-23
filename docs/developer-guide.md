# Entwicklerhandbuch – OIDC Client

Dieses Handbuch richtet sich an PHP-Entwickler, die das Plugin verstehen, erweitern oder in eigene Projekte integrieren möchten.

---

## Projektstruktur

```
oidc-client/
├── oidc-client.php                  # Plugin-Header, Einstiegspunkt, Hook-Registrierung
├── composer.json                    # Dev-Abhängigkeiten (PHPUnit, Brain\Monkey, PHPStan usw.)
├── phpunit.xml                      # PHPUnit-Konfiguration
├── phpstan.neon                     # PHPStan-Konfiguration
├── infection.json5                  # Mutation-Testing-Konfiguration
├── Makefile                         # Entwicklungs-Shortcuts
├── README.md
├── docs/
│   ├── user-guide.md
│   ├── admin-guide.md
│   └── developer-guide.md           # Diese Datei
├── includes/
│   ├── class-oidc-jwt-helper.php    # Statische JWT/JWKS-Hilfsmethoden
│   ├── class-oidc-log.php           # Datenbanklog + Admin-Log-Seite
│   ├── class-oidc-tokens.php        # Token-Speicherung, Refresh, Verschlüsselung
│   ├── class-oidc-roles.php         # Rollen-Mapping-Logik
│   ├── class-oidc-logout.php        # Frontchannel- + Backchannel-Logout
│   ├── class-oidc-profile.php       # Account-Linking, E-Mail/Passwort-Sperre
│   ├── class-oidc-admin.php         # Settings-API, Discovery-AJAX, Cache-AJAX
│   ├── class-oidc-auth.php          # Authorization Code Flow, Callback, Session-Check
│   └── class-oidc-login.php         # Login-Button, Fehlermeldung, Auto-Login
├── languages/
│   ├── oidc-client.pot              # Übersetzungsvorlage
│   ├── oidc-client-de_DE.po/.mo     # Deutsch
│   ├── oidc-client-en_US.po/.mo     # Englisch
│   ├── oidc-client-fr_FR.po/.mo     # Französisch
│   ├── oidc-client-es_ES.po/.mo     # Spanisch
│   └── oidc-client-sv_SE.po/.mo     # Schwedisch
├── bin/
│   └── build.sh                     # Distributions-ZIP erstellen
└── tests/
    ├── bootstrap.php                # PHPUnit-Bootstrap (WP-Stubs, Konstanten)
    ├── phpstan-bootstrap.php        # PHPStan-Bootstrap
    └── Unit/
        ├── WpTestCase.php           # Abstrakte Basisklasse (Brain\Monkey)
        ├── JwtHelperTest.php
        ├── TokensTest.php
        ├── RolesTest.php
        └── AuthTest.php
```

---

## Architektur

### Schichtenmodell

```
┌──────────────────────────────────────────────────────────┐
│                    oidc-client.php                       │  Einstiegspunkt
│         Konstanten · require_once · oidc_client_init()   │  Hook-Verdrahtung
└────┬──────────┬──────────┬──────────┬────────────────────┘
     │          │          │          │
┌────▼──┐  ┌───▼───┐  ┌───▼────┐ ┌──▼──────┐
│ Auth  │  │ Login │  │ Admin  │ │ Logout  │
│(init) │  │(login)│  │(admin) │ │(init)   │
└────┬──┘  └───────┘  └────────┘ └──┬──────┘
     │                               │
     └───────────────┬───────────────┘
                ┌────▼──────┐
                │  Tokens   │  Verschlüsselung + Refresh
                └────┬──────┘
                     │
          ┌──────────┼──────────┐
     ┌────▼───┐  ┌───▼──┐  ┌───▼────┐
     │  Roles │  │ Log  │  │Profile │
     └────────┘  └──────┘  └────────┘
                     │
               ┌─────▼──────┐
               │ JWT Helper │  (statisch, kein State)
               └────────────┘
```

### Klassen

#### `OIDC_JWT_Helper` (`includes/class-oidc-jwt-helper.php`)

Statische Hilfsklasse für JWT-Verarbeitung und JWKS-Operationen.

| Methode | Beschreibung |
|---|---|
| `base64url_decode($input)` | Base64url-Dekodierung (RFC 4648 §5) |
| `parse_jwt($jwt)` | JWT in `[header, claims, parts]` zerlegen |
| `get_jwks($jwks_uri)` | JWKS abrufen (1 Stunde Transient-Cache) |
| `verify_signature($parts, $header, $jwks_uri)` | RS256-Signatur prüfen |
| `jwk_to_pem($jwk)` | RSA-JWK zu PEM-Public-Key konvertieren |

#### `OIDC_Tokens` (`includes/class-oidc-tokens.php`)

Verwaltet Token-Speicherung, Refresh und optionale AES-256-CBC-Verschlüsselung.

| Methode | Beschreibung |
|---|---|
| `store_tokens($user_id, $tokens)` | Tokens nach Login speichern (mit optionaler Verschlüsselung) |
| `get_id_token($user_id)` | ID-Token lesen (entschlüsselt) |
| `get_valid_access_token($user_id)` | Access-Token liefern, bei Bedarf automatisch erneuern |
| `clear_tokens($user_id)` | Access- und Refresh-Token löschen |
| `clear_all_tokens($user_id)` | Alle Token-Metas löschen (inkl. ID-Token) |

#### `OIDC_Roles` (`includes/class-oidc-roles.php`)

| Methode | Beschreibung |
|---|---|
| `apply_role_mapping($user_id, $userinfo)` | Rollen-Mapping aus Einstellungen auf User anwenden |

#### `OIDC_Auth` (`includes/class-oidc-auth.php`)

| Hook | Methode | Beschreibung |
|---|---|---|
| `login_init` | `handle_callback()` | OIDC-Callback verarbeiten |
| `oidc_initiate_login` | `initiate_login($extra_params)` | Redirect zum Provider starten |
| `init` | `check_session_validity()` | Session bei jedem Request prüfen |
| `get_avatar_url` | `filter_avatar_url()` | OIDC-Profilbild einbinden |

---

## WordPress-Optionen (Datenbankschlüssel)

Alle Optionen sind über `get_option()` / `update_option()` zugänglich:

| Option | Typ | Beschreibung |
|---|---|---|
| `oidc_discovery_url` | URL | Discovery-URL des Providers |
| `oidc_provider_name` | String | Name des Providers (für Login-Button) |
| `oidc_issuer` | String | Erwarteter `iss`-Claim |
| `oidc_authorization_endpoint` | URL | Authorization Endpoint |
| `oidc_token_endpoint` | URL | Token Endpoint |
| `oidc_userinfo_endpoint` | URL | Userinfo Endpoint |
| `oidc_jwks_uri` | URL | JWKS URI |
| `oidc_end_session_endpoint` | URL | End-Session Endpoint (für Logout) |
| `oidc_pkce_supported` | `1`/`''` | PKCE aktivieren |
| `oidc_client_id` | String | Client-ID |
| `oidc_client_secret` | String | Client-Secret |
| `oidc_scopes` | String | OAuth2-Scopes (leerzeichen-getrennt) |
| `oidc_token_auth_method` | `client_secret_post`/`client_secret_basic` | Token-Endpoint-Authentifizierung |
| `oidc_debug_mode` | `1`/`''` | Debug-Modus |
| `oidc_create_user` | `1`/`''` | Benutzer automatisch anlegen |
| `oidc_default_role` | String | Standard-Rolle für neue Benutzer |
| `oidc_enable_refresh` | `1`/`''` | Token-Refresh aktivieren |
| `oidc_active_claim` | String | Name des Active-Claims |
| `oidc_sync_avatar` | `1`/`''` | Profilbild synchronisieren |
| `oidc_hide_wp_login` | `1`/`''` | WP-Login-Formular ausblenden |
| `oidc_auto_login` | `1`/`''` | Auto-Login aktivieren |
| `oidc_button_icon_url` | URL | URL des Login-Button-Icons |
| `oidc_token_encryption` | `1`/`''` | Token-Verschlüsselung aktivieren |
| `oidc_lock_email` | `1`/`''` | E-Mail-Änderung sperren |
| `oidc_lock_password` | `1`/`''` | Passwort-Änderung sperren |
| `oidc_session_management` | `1`/`''` | Session-Management aktivieren |
| `oidc_remember_me` | `always`/`never` | Angemeldet-bleiben-Steuerung |
| `oidc_role_claim` | String | Name des Rollen-Claims |
| `oidc_role_mapping` | JSON | Rollen-Mapping als JSON-Objekt |

---

## User-Meta-Keys

| Meta-Key | Typ | Beschreibung |
|---|---|---|
| `_oidc_subject` | String | `sub`-Claim des Providers – eindeutige Kennung |
| `_oidc_id_token` | String | ID-Token (ggf. verschlüsselt mit `enc:`-Prefix) |
| `_oidc_access_token` | String | Access-Token (ggf. verschlüsselt) |
| `_oidc_access_token_expires` | int | Unix-Timestamp des Token-Ablaufs |
| `_oidc_refresh_token` | String | Refresh-Token (ggf. verschlüsselt) |
| `_oidc_avatar_url` | String | URL des Profilbilds vom Provider |

---

## Action- und Filter-Hooks

### Actions

#### `oidc_initiate_login`

Startet den OIDC-Login-Flow. Akzeptiert ein optionales `$extra_params`-Array.

```php
// Normaler Login
do_action( 'oidc_initiate_login' );

// Login mit erzwungener erneuter Anmeldung beim Provider
do_action( 'oidc_initiate_login', array( 'prompt' => 'login' ) );
```

### Filter

Das Plugin nutzt den `get_avatar_url`-Filter intern. Eigene öffentliche Filter-Hooks sind aktuell nicht vorhanden.

---

## REST-API-Endpunkte

| Methode | Pfad | Beschreibung |
|---|---|---|
| `POST` | `/wp-json/oidc-client/v1/backchannel-logout` | Backchannel-Logout-Endpoint (öffentlich, validiert via JWT) |

**Request-Body:**
```
Content-Type: application/x-www-form-urlencoded

logout_token=<signed-jwt>
```

**Response 200:** Logout erfolgreich (oder Benutzer nicht gefunden – idempotent)
**Response 400:** Ungültiger oder fehlender Logout-Token

---

## Lokale Entwicklung

**Voraussetzungen:** PHP 8.1+, Composer

```bash
# Abhängigkeiten installieren
make install

# Alle Checks in einem Schritt
make ci
```

| Make-Target | Befehl | Beschreibung |
|---|---|---|
| `make install` | `composer install` | Dev-Dependencies installieren |
| `make test` | `vendor/bin/phpunit` | Unit-Tests ausführen |
| `make lint` | `vendor/bin/phpcs` | Code-Style prüfen |
| `make fix` | `vendor/bin/phpcbf` | Auto-fixbare Fehler beheben |
| `make build` | `bash bin/build.sh` | Distributions-ZIP erstellen |
| `make ci` | `install + lint + test` | Vollständiger CI-Lauf |
| `make clean` | `rm -rf dist vendor` | Build-Artefakte bereinigen |

---

## Tests ausführen

```bash
# Alle Tests
vendor/bin/phpunit

# Einzelne Test-Klasse
vendor/bin/phpunit tests/Unit/JwtHelperTest.php

# Einzelner Test
vendor/bin/phpunit --filter test_base64url_decode_standard

# Mit Coverage (erfordert Xdebug)
vendor/bin/phpunit --coverage-html coverage/
```

### Test-Klassen

| Datei | Testet | Schwerpunkt |
|---|---|---|
| `JwtHelperTest.php` | `OIDC_JWT_Helper` | base64url-Dekodierung, JWT-Parsing, DER-Encoding, JWK→PEM |
| `TokensTest.php` | `OIDC_Tokens` | encrypt/decrypt-Roundtrip, Legacy-Plaintext, IV-Randomness |
| `RolesTest.php` | `OIDC_Roles` | Rollen-Mapping, kein Match, Array-Claims, ungültige Rollen |
| `AuthTest.php` | `OIDC_Auth` | Zufalls-String, Code-Verifier, PKCE-Challenge (S256) |

### Testarchitektur

Die Tests verwenden [Brain\Monkey](https://brain-wp.github.io/BrainMonkey/) für WordPress-Funktions-Mocks und [Mockery](http://docs.mockery.io/) für Objekt-Mocks.

Alle Test-Klassen erben von `WpTestCase` (`tests/Unit/WpTestCase.php`), die `Brain\Monkey\setUp()` und `tearDown()` automatisch aufruft.

**Das `exit`-Problem:** Der Redirector ruft nach `wp_redirect()` `exit` auf. In Tests wird `wp_redirect` als Stub registriert, der eine `RuntimeException` wirft – so wird `exit` nie erreicht und PHPUnit kann die Exception prüfen:

```php
Functions\expect( 'wp_redirect' )
    ->once()
    ->andReturnUsing( function () {
        throw new \RuntimeException( 'redirect_called' );
    } );

$this->expectException( \RuntimeException::class );
OIDC_Auth::some_method();
```

### Bootstrap

`tests/bootstrap.php` definiert:
- WordPress-Konstanten (`ABSPATH`, `AUTH_KEY`, `SECURE_AUTH_KEY` etc.)
- `WP_Error`-Stub
- `WP_User`-Stub mit Call-Tracking für `set_role()` / `add_role()`

---

## Mutation Testing

```bash
vendor/bin/infection --no-progress
```

Konfiguration in `infection.json5`: Mindest-MSI 70%, mindest-Covered-MSI 80%.

---

## Release erstellen

Ein Release wird automatisch über GitHub Actions ausgelöst, wenn ein Tag mit `v`-Präfix gepusht wird:

```bash
git tag v1.2.0
git push origin v1.2.0
```

GitHub Actions führt dann automatisch aus:

1. CI muss auf dem Commit grün sein (Job `wait-for-ci`)
2. Versionsnummer aus dem Tag in `oidc-client.php` eintragen
3. `composer install --no-dev`
4. `bash bin/build.sh` → `dist/oidc-client-1.2.0.zip`
5. GitHub Release mit dem ZIP als Asset anlegen

**Manuell bauen:**

```bash
make build
# Ergebnis: dist/oidc-client-<VERSION>.zip
```

---

## Übersetzungen

Das Plugin nutzt das WordPress i18n-System (`__()`, `_e()`, `esc_html__()` etc.) mit der Text-Domain `oidc-client`.

| Locale | Datei | Sprache |
|---|---|---|
| `de_DE` | `languages/oidc-client-de_DE.po` | Deutsch |
| `en_US` | `languages/oidc-client-en_US.po` | Englisch |
| `fr_FR` | `languages/oidc-client-fr_FR.po` | Französisch |
| `es_ES` | `languages/oidc-client-es_ES.po` | Spanisch |
| `sv_SE` | `languages/oidc-client-sv_SE.po` | Schwedisch |

**Eigene Übersetzung erstellen:**

```bash
cp languages/oidc-client.pot languages/oidc-client-<locale>.po
# Übersetzungen in der .po-Datei eintragen, dann kompilieren:
msgfmt languages/oidc-client-<locale>.po -o languages/oidc-client-<locale>.mo
```

---

## Coding-Konventionen

- WordPress Coding Standards (WPCS) werden über PHPCS durchgesetzt
- Alle Datenbankwerte werden mit `sanitize_text_field()` / `esc_url_raw()` bereinigt
- Prepared Statements via `$wpdb->prepare()` für alle parametrisierten Queries
- Nonces für alle schreibenden Admin-Aktionen
- Kein direkter Zugriff ohne `defined('ABSPATH')`-Guard

---

## Mitwirken

1. Repository forken
2. Feature-Branch erstellen: `git checkout -b feature/mein-feature`
3. Tests schreiben und alle bestehenden Tests grün halten: `make ci`
4. Pull Request öffnen
