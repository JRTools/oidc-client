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
│   ├── class-oidc-admin.php             # Settings-Seite (Koordination)
│   ├── class-oidc-admin-fields.php      # Settings-Felder und -Registrierung
│   ├── class-oidc-admin-sanitize.php    # Sanitierung der Settings-Eingaben
│   ├── class-oidc-auth.php              # Authorization Code Flow, Callback, Session-Check
│   ├── class-oidc-jwk-helper.php        # JWK-Parsing und PEM-Konvertierung
│   ├── class-oidc-jwt-helper.php        # Statische JWT/JWKS-Hilfsmethoden
│   ├── class-oidc-log.php               # Datenbanklog + Admin-Log-Seite
│   ├── class-oidc-login.php             # Login-Button, Fehlermeldung, Auto-Login
│   ├── class-oidc-logout.php            # Frontchannel- + Backchannel-Logout
│   ├── class-oidc-profile.php           # Account-Linking, E-Mail/Passwort-Sperre
│   ├── class-oidc-roles.php             # Rollen-Mapping-Logik
│   ├── class-oidc-token-exchange.php    # Token-Endpoint-Kommunikation, Code-Austausch
│   ├── class-oidc-tokens.php            # Token-Speicherung, Refresh, Verschlüsselung
│   └── class-oidc-user-manager.php      # Benutzeranlage, Profil-Sync, Claims-Mapping
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

#### `OIDC_Admin` (`includes/class-oidc-admin.php`)

Koordiniert die Settings-Seite: registriert AJAX-Handler für Discovery und JWKS-Cache-Leerung, bindet die Unterklassen ein.

#### `OIDC_Admin_Fields` (`includes/class-oidc-admin-fields.php`)

Registriert alle Settings-Felder und -Sektionen via WordPress Settings API. Kapselt die Darstellung der Einstellungsformulare.

#### `OIDC_Admin_Sanitize` (`includes/class-oidc-admin-sanitize.php`)

Sanitiert und validiert alle Eingaben beim Speichern der Settings. Enthält die Callback-Funktionen für `register_setting()`.

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

#### `OIDC_JWK_Helper` (`includes/class-oidc-jwk-helper.php`)

Kapselt das JWK-Parsing und die Konvertierung von RSA-JWKs in PEM-Public-Keys. Wurde aus `OIDC_JWT_Helper` extrahiert, um die Verantwortlichkeiten zu trennen.

| Methode | Beschreibung |
|---|---|
| `jwk_to_pem($jwk)` | RSA-JWK zu PEM-Public-Key konvertieren |

#### `OIDC_Token_Exchange` (`includes/class-oidc-token-exchange.php`)

Kapselt die gesamte Kommunikation mit dem Token-Endpoint des Providers (Code-Austausch und Token-Refresh). Wurde aus `OIDC_Auth` extrahiert.

| Methode | Beschreibung |
|---|---|
| `exchange_code($code, $code_verifier)` | Authorization Code gegen Tokens tauschen |
| `refresh_tokens($refresh_token)` | Neues Access-Token per Refresh-Token anfordern |

#### `OIDC_UserManager` (`includes/class-oidc-user-manager.php`)

Verwaltet die Benutzeranlage und den Profil-Sync. Übernimmt das Mapping aller OIDC Standard-Claims (§5.1) auf WordPress-Profilfelder. Wurde aus `OIDC_Auth` extrahiert.

| Methode | Beschreibung |
|---|---|
| `find_or_create_user($userinfo)` | Vorhandenen Benutzer suchen oder neuen anlegen |
| `sync_user_profile($user_id, $userinfo)` | Alle verfügbaren Claims auf WP-Felder und User-Meta übertragen |

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

### Plugin-spezifische Schlüssel (`_oidc_*`)

| Meta-Key | Typ | Beschreibung |
|---|---|---|
| `_oidc_subject` | String | `sub`-Claim des Providers – eindeutige Kennung |
| `_oidc_id_token` | String | ID-Token (ggf. verschlüsselt mit `enc:`-Prefix) |
| `_oidc_access_token` | String | Access-Token (ggf. verschlüsselt) |
| `_oidc_access_token_expires` | int | Unix-Timestamp des Token-Ablaufs |
| `_oidc_refresh_token` | String | Refresh-Token (ggf. verschlüsselt) |
| `_oidc_avatar_url` | String | URL des Profilbilds vom Provider (`picture`-Claim) |
| `_oidc_middle_name` | String | Zweiter Vorname (`middle_name`-Claim) |
| `_oidc_profile` | String | Profilseiten-URL beim Provider (`profile`-Claim) |
| `_oidc_gender` | String | Geschlecht (`gender`-Claim) |
| `_oidc_birthdate` | String | Geburtsdatum im Format `YYYY-MM-DD` (`birthdate`-Claim) |
| `_oidc_zoneinfo` | String | Zeitzone, z.B. `Europe/Berlin` (`zoneinfo`-Claim) |
| `_oidc_phone_number` | String | Telefonnummer (`phone_number`-Claim) |
| `_oidc_phone_number_verified` | String | Telefonnummer bestätigt (`phone_number_verified`-Claim) |
| `_oidc_email_verified` | String | E-Mail bestätigt (`email_verified`-Claim) |
| `_oidc_updated_at` | String | Zeitpunkt der letzten Profiländerung, Unix-Timestamp (`updated_at`-Claim) |
| `_oidc_address` | String | Adressobjekt, JSON-kodiert (`address`-Claim) |

### Native WordPress-Schlüssel (vom Plugin beschrieben)

| OIDC-Claim | Meta-Key | Beschreibung |
|---|---|---|
| `nickname` | `nickname` | Anzeigenickname |
| `locale` | `locale` | Benutzersprache (z.B. `de_DE`) |

---

## Action- und Filter-Hooks

Das Plugin bietet ein vollständiges Hook-API, über das andere Plugins in den OIDC-Ablauf eingreifen können.

### Actions

#### `oidc_initiate_login`

Startet den OIDC-Login-Flow. Akzeptiert ein optionales `$extra_params`-Array.

```php
// Normaler Login
do_action( 'oidc_initiate_login' );

// Login mit erzwungener erneuter Anmeldung beim Provider
do_action( 'oidc_initiate_login', array( 'prompt' => 'login' ) );
```

#### `oidc_login_success`

Wird nach erfolgreichem OIDC-Login ausgelöst, bevor der Redirect zur Zielseite stattfindet.

```php
add_action( 'oidc_login_success', function ( int $user_id, array $userinfo ) {
    // z.B. eigene Willkommens-E-Mail versenden
    wp_mail( $userinfo['email'], 'Willkommen!', '...' );
}, 10, 2 );
```

**Parameter:** `$user_id` (int), `$userinfo` (array) – Userinfo-Claims vom Provider.

#### `oidc_login_failed`

Wird ausgelöst, wenn ein OIDC-Login fehlschlägt, bevor die Fehlerweiterleitung erfolgt.

```php
add_action( 'oidc_login_failed', function ( string $message, int $user_id ) {
    // z.B. fehlgeschlagene Anmeldeversuche protokollieren
    error_log( 'OIDC Login fehlgeschlagen: ' . $message );
}, 10, 2 );
```

**Parameter:** `$message` (string) – Fehlermeldung, `$user_id` (int) – User-ID (0 wenn unbekannt).

#### `oidc_user_created`

Wird ausgelöst, nachdem ein neuer WordPress-Benutzer über OIDC angelegt wurde.

```php
add_action( 'oidc_user_created', function ( int $user_id, array $userinfo ) {
    // z.B. neuen Nutzer einer Gruppe hinzufügen
    my_plugin_add_to_onboarding_group( $user_id );
}, 10, 2 );
```

**Parameter:** `$user_id` (int), `$userinfo` (array).

#### `oidc_user_updated`

Wird ausgelöst, nachdem ein bestehender WordPress-Benutzer mit Daten vom Provider aktualisiert wurde.

```php
add_action( 'oidc_user_updated', function ( int $user_id, array $userinfo ) {
    // z.B. eigene Profilfelder synchronisieren
    update_user_meta( $user_id, 'my_department', $userinfo['department'] ?? '' );
}, 10, 2 );
```

**Parameter:** `$user_id` (int), `$userinfo` (array).

#### `oidc_tokens_stored`

Wird ausgelöst, nachdem Tokens für einen Benutzer gespeichert wurden (nur wenn Token-Refresh aktiviert ist).

```php
add_action( 'oidc_tokens_stored', function ( int $user_id ) {
    // z.B. eigene Token-Metadaten aktualisieren
} );
```

**Parameter:** `$user_id` (int).

#### `oidc_tokens_refreshed`

Wird ausgelöst, nachdem ein Token-Refresh erfolgreich durchgeführt wurde.

```php
add_action( 'oidc_tokens_refreshed', function ( int $user_id ) {
    // z.B. eigene Token-abhängige Caches leeren
} );
```

**Parameter:** `$user_id` (int).

#### `oidc_logout`

Wird während des Frontchannel-Logouts ausgelöst, bevor der Redirect zum End-Session-Endpoint des Providers stattfindet.

```php
add_action( 'oidc_logout', function ( int $user_id ) {
    // z.B. eigene Session-Daten bereinigen
    delete_user_meta( $user_id, 'my_session_data' );
} );
```

**Parameter:** `$user_id` (int).

#### `oidc_backchannel_logout`

Wird nach einem erfolgreichen Backchannel-Logout ausgelöst (Sessions zerstört, Tokens gelöscht).

```php
add_action( 'oidc_backchannel_logout', function ( int $user_id ) {
    // z.B. eigene Sessions oder Caches für diesen Nutzer löschen
} );
```

**Parameter:** `$user_id` (int).

#### `oidc_account_linked`

Wird ausgelöst, nachdem ein bestehender WordPress-Account mit einem OIDC-Provider verknüpft wurde.

```php
add_action( 'oidc_account_linked', function ( int $user_id, string $sub ) {
    // z.B. Verknüpfung in eigenem System registrieren
}, 10, 2 );
```

**Parameter:** `$user_id` (int), `$sub` (string) – OIDC Subject-Identifier.

---

### Filter

#### `oidc_scopes`

Ermöglicht das Anpassen der angeforderten OAuth2-Scopes.

```php
add_filter( 'oidc_scopes', function ( string $scopes ): string {
    return $scopes . ' groups';
} );
```

**Parameter:** `$scopes` (string) – leerzeichen-getrennte Scope-Liste.

#### `oidc_auth_params`

Ermöglicht das Hinzufügen oder Ändern von Parametern im Authorization-Request an den Provider.

```php
add_filter( 'oidc_auth_params', function ( array $params ): array {
    $params['ui_locales'] = get_user_locale();
    $params['acr_values'] = 'urn:mace:incommon:iap:silver';
    return $params;
} );
```

**Parameter:** `$params` (array) – Query-Parameter für den Authorization-Request.

#### `oidc_userinfo`

Ermöglicht das Verändern der Userinfo-Daten nach dem Abruf vom Provider, bevor der Benutzer angelegt oder aktualisiert wird.

```php
add_filter( 'oidc_userinfo', function ( array $userinfo ): array {
    // z.B. proprietären Claim auf Standard-Claim mappen
    if ( isset( $userinfo['custom_display_name'] ) ) {
        $userinfo['name'] = $userinfo['custom_display_name'];
    }
    return $userinfo;
} );
```

**Parameter:** `$userinfo` (array) – Userinfo-Claims vom Provider.

#### `oidc_new_user_data`

Ermöglicht das Anpassen des Datenarrays, das beim Anlegen eines neuen WordPress-Benutzers an `wp_insert_user()` übergeben wird.

```php
add_filter( 'oidc_new_user_data', function ( array $user_data, array $userinfo ): array {
    // z.B. eigene Felder befüllen
    $user_data['description'] = $userinfo['bio'] ?? '';
    return $user_data;
}, 10, 2 );
```

**Parameter:** `$user_data` (array) – Daten für `wp_insert_user()`, `$userinfo` (array).

#### `oidc_user_role`

Ermöglicht das Überschreiben der Rolle, die neuen Benutzern zugewiesen wird. Wird nach `oidc_new_user_data` ausgeführt und hat Vorrang vor dem dort gesetzten `role`-Wert.

```php
add_filter( 'oidc_user_role', function ( string $role, array $userinfo ): string {
    if ( in_array( 'editor-group', $userinfo['groups'] ?? array(), true ) ) {
        return 'editor';
    }
    return $role;
}, 10, 2 );
```

**Parameter:** `$role` (string) – WordPress-Rollenslug, `$userinfo` (array).

#### `oidc_login_redirect`

Ermöglicht das Ändern der Ziel-URL nach erfolgreichem Login. Wird nach dem Core-Filter `login_redirect` ausgeführt.

```php
add_filter( 'oidc_login_redirect', function ( string $redirect_to, WP_User $user ): string {
    if ( in_array( 'shop_manager', $user->roles, true ) ) {
        return admin_url( 'admin.php?page=wc-orders' );
    }
    return $redirect_to;
}, 10, 2 );
```

**Parameter:** `$redirect_to` (string) – Redirect-URL, `$user` (WP_User) – eingeloggter Benutzer.

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

Der Test-Suite umfasst aktuell **296 Tests**.

| Datei | Testet | Schwerpunkt |
|---|---|---|
| `JwtHelperTest.php` | `OIDC_JWT_Helper` | base64url-Dekodierung, JWT-Parsing, DER-Encoding, JWK→PEM |
| `JwkHelperTest.php` | `OIDC_JWK_Helper` | JWK-Parsing, RSA-PEM-Konvertierung |
| `TokensTest.php` | `OIDC_Tokens` | encrypt/decrypt-Roundtrip, Legacy-Plaintext, IV-Randomness, Hook-Ausführung |
| `TokenExchangeTest.php` | `OIDC_Token_Exchange` | Code-Austausch, PKCE, Fehlerbehandlung |
| `RolesTest.php` | `OIDC_Roles` | Rollen-Mapping, kein Match, Array-Claims, ungültige Rollen |
| `AuthTest.php` | `OIDC_Auth` | Session-Check, initiate_login, Callback, ID-Token-Validierung, Account-Linking, Hooks |
| `UserManagerTest.php` | `OIDC_User_Manager` | Benutzeranlage, Profil-Sync, Claims-Mapping, Fehlerbehandlung, Hooks |
| `LogoutTest.php` | `OIDC_Logout` | Frontchannel-/Backchannel-Logout, Rate-Limiting, Replay-Schutz, Hooks |
| `LoginTest.php` | `OIDC_Login` | Login-Button, Auto-Login, Fehleranzeige |
| `ProfileTest.php` | `OIDC_Profile` | E-Mail-/Passwort-Sperre, Account-Linking-UI |
| `LogTest.php` | `OIDC_Log` | DB-Logging, Admin-Log-Seite |
| `AdminTest.php` | `OIDC_Admin` | Settings-Registrierung, Discovery-AJAX, Sanitierung |
| `PluginMainTest.php` | `oidc-client.php` | Konstanten, Klassen-Existenz, `oidc_client_init()` |

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

Konfiguration in `infection.json5`: Mindest-MSI 70%, mindest-Covered-MSI 80%. Mutation Testing läuft im CI auf PHP 8.4.

---

## CI / Quality Gates

Der GitHub Actions Workflow prüft bei jedem Push und Pull Request:

| Gate | Tool | Schwellenwert |
|---|---|---|
| Unit-Tests | PHPUnit (PHP 8.1, 8.2, 8.3, 8.4) | Alle 296 Tests grün |
| Code Coverage | Codecov | ≥ 90 % Zeilenabdeckung |
| Code Style | PHPCS (WordPress Coding Standards) | Keine Fehler |
| Statische Analyse | PHPStan Level 5 | Keine Fehler |
| Mutation Testing | Infection (PHP 8.4) | MSI ≥ 70 %, Covered MSI ≥ 80 % |
| Quality Gate | SonarCloud | Muss „Passed" sein |
| Plugin-Kompatibilität | WordPress Plugin Check | Keine Blocking Issues |

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
