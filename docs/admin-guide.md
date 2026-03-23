# Administrationshandbuch – OIDC Client

Dieses Handbuch richtet sich an WordPress-Administratoren, die das Plugin installieren, konfigurieren und betreiben.

---

## Systemvoraussetzungen

| Anforderung | Minimum |
|---|---|
| PHP | 8.1 oder höher |
| WordPress | 5.9 oder höher |
| PHP-Extension | `openssl` (für JWT-Signaturprüfung und Token-Verschlüsselung) |
| OIDC-Provider | Muss Authorization Code Flow unterstützen |

> **Hinweis:** Die Extension `openssl` ist in der Regel bereits aktiviert. Prüfe mit `phpinfo()`, ob `openssl` in der Liste erscheint.

---

## Installation

### Variante A: ZIP hochladen (empfohlen)

1. Die neueste `oidc-client-x.y.z.zip` von der [Releases-Seite](https://github.com/johannesroesch/oidc-client/releases) herunterladen.
2. Im WordPress-Admin zu **Plugins → Neu hinzufügen → Plugin hochladen** navigieren.
3. Die ZIP-Datei auswählen und auf **Jetzt installieren** klicken.
4. Plugin aktivieren.

### Variante B: Manuell per FTP/SSH

1. Den Ordner `oidc-client` in das Verzeichnis `wp-content/plugins/` hochladen.
2. Im WordPress-Admin unter **Plugins** aktivieren.

Nach der Aktivierung legt das Plugin automatisch die Datenbanktabelle `{prefix}_oidc_login_log` an.

---

## Schnellstart

> Für den häufigsten Fall: ein Provider mit Discovery-URL (z.B. Keycloak, Entra ID, Google).

### Schritt 1: Plugin konfigurieren

1. WordPress-Admin → **Einstellungen → OIDC Client**
2. **Discovery URL** eintragen (z.B. `https://keycloak.example.com/realms/myrealm/.well-known/openid-configuration`)
3. Auf **Abrufen** klicken → Endpunkte werden automatisch ausgefüllt
4. **Provider-Name** eingeben (erscheint im Login-Button, z.B. `Keycloak`)
5. **Client ID** und **Client Secret** aus der Provider-Konfiguration eintragen
6. Auf **Einstellungen speichern** klicken

### Schritt 2: Provider konfigurieren

Im OIDC-Provider folgende URI als erlaubte **Redirect URI** eintragen:

```
https://deine-wordpress-seite.de/wp-login.php?oidc_callback=1
```

Den genauen Wert findest du auf der Einstellungsseite unter **Konfiguration auf OIDC-Provider-Seite**.

### Schritt 3: Testen

1. WordPress-Admin abmelden
2. Zur Login-Seite navigieren
3. Den Button **Anmelden mit [Provider-Name]** anklicken
4. Nach erfolgreicher Authentifizierung beim Provider sollte die Weiterleitung zurück zu WordPress erfolgen

---

## Einstellungen im Überblick

### Provider

| Einstellung | Beschreibung |
|---|---|
| **Discovery URL** | URL zum `/.well-known/openid-configuration`-Dokument des Providers. Nach Klick auf „Abrufen" werden alle Endpunkte automatisch ausgefüllt. |
| **Provider-Name** | Freitext, der im Login-Button angezeigt wird: „Anmelden mit _Name_". |
| **Issuer** | Wird automatisch aus der Discovery-URL befüllt. Muss mit dem `iss`-Claim im ID-Token übereinstimmen. |
| **Authorization Endpoint** | URL des Authorization-Endpoints. |
| **Token Endpoint** | URL des Token-Endpoints. |
| **Userinfo Endpoint** | URL des Userinfo-Endpoints (optional, wenn alle Claims im ID-Token enthalten sind). |
| **JWKS URI** | URL der JSON Web Key Sets – wird für die JWT-Signaturprüfung benötigt. |
| **PKCE (S256)** | PKCE gemäß RFC 7636 aktivieren (Standard: aktiviert). Deaktivieren nur wenn der Provider kein PKCE unterstützt und `invalid_client`-Fehler auftreten. |

### Client

| Einstellung | Beschreibung |
|---|---|
| **Client ID** | Die Client-ID, wie sie beim Provider registriert ist. |
| **Client Secret** | Das Client-Secret. Wird verschlüsselt gespeichert. |
| **Scopes** | Leerzeichen-getrennte OAuth2-Scopes (Standard: `openid email profile`). |
| **Token-Endpoint Authentifizierung** | `client_secret_post` (Standard, z.B. Keycloak, easyVerein) oder `client_secret_basic` (z.B. Entra ID, Okta). Bei `invalid_client`-Fehlern die andere Methode testen. |

### Benutzerverwaltung

| Einstellung | Beschreibung |
|---|---|
| **Benutzer automatisch anlegen** | Wenn aktiviert, wird beim ersten Login automatisch ein WordPress-Konto erstellt, sofern die E-Mail-Adresse noch nicht bekannt ist. |
| **Standard-Rolle für neue Benutzer** | WordPress-Rolle, die automatisch erstellten Konten zugewiesen wird (z.B. `subscriber`). |
| **Debug-Modus** | Zeigt bei Fehlern die vollständige Provider-Antwort im Fehlertext an. **Nur temporär zur Fehlersuche aktivieren!** |

### Erweiterte Optionen

| Einstellung | Beschreibung |
|---|---|
| **End-Session Endpoint** | URL des Logout-Endpoints beim Provider. Wird für den Frontchannel-Logout benötigt. Wird bei Discovery automatisch befüllt. |
| **Token-Refresh** | Speichert Access- und Refresh-Token nach dem Login und erneuert das Access-Token automatisch, wenn es abläuft. |
| **Active-Claim** | Name eines Claims (z.B. `active`), dessen Wert `true` sein muss, damit der Login erlaubt wird. |
| **Profilbild synchronisieren** | Übernimmt das `picture`-Claim als WordPress-Avatar. |
| **WP-Login-Formular ausblenden** | Blendet das Standard-WordPress-Login-Formular aus. Fallback für Admins: `?showlogin=1`. |
| **Auto-Login** | Leitet nicht angemeldete Besucher der Login-Seite direkt zum OIDC-Provider weiter. |
| **Button-Icon URL** | URL zu einem Bild im Login-Button (empfohlene Größe: 20×20 px). |
| **Token-Verschlüsselung** | Speichert Tokens verschlüsselt (AES-256-CBC). Erfordert `openssl` und aktivierten Token-Refresh. |
| **E-Mail sperren** | OIDC-Nutzer können ihre E-Mail im WordPress-Profil nicht selbst ändern. |
| **Passwort sperren** | OIDC-Nutzer können ihr Passwort im WordPress-Profil nicht selbst ändern. |
| **Session-Management** | Bindet die WordPress-Session an den Token-Ablauf. Erfordert Token-Refresh. |
| **Angemeldet bleiben** | `Nie` = Session-Cookie. `Immer` = dauerhaftes Cookie (14 Tage). |
| **JWKS-Cache leeren** | Schaltfläche zum Löschen des gecachten JWKS-Transients (z.B. nach Key-Rotation). |

### Rollen-Mapping

| Einstellung | Beschreibung |
|---|---|
| **Rollen-Claim** | Name des Claims, der die Rollen enthält, z.B. `roles` oder `groups`. |
| **Mapping-Tabelle** | Claim-Wert (z.B. `editor-group`) → WordPress-Rolle (z.B. `editor`). |

Enthält ein Claim mehrere Werte (Array), werden alle gemappt: der erste als primäre Rolle (`set_role`), weitere als zusätzliche Rollen (`add_role`). Kein passender Eintrag → bestehende WordPress-Rolle bleibt erhalten.

---

## Features

### Authorization Code Flow mit PKCE

Das Plugin implementiert den **Authorization Code Flow** gemäß OpenID Connect Core 1.0 mit **PKCE** (Proof Key for Code Exchange, RFC 7636).

```
Browser           WordPress          OIDC-Provider
   |                   |                    |
   |-- Login-Button -->|                    |
   |                   |-- ?code_challenge->|
   |<-- Redirect ------|                    |
   |                                        |
   |--- Anmeldung beim Provider ----------->|
   |<-- Redirect mit ?code ----------------|
   |                                        |
   |-- ?oidc_callback=1 + code ----------->|
   |                   |-- token request -->|
   |                   |<-- tokens ---------|
   |                   |-- userinfo ------->|
   |                   |<-- claims ---------|
   |                   |                    |
   |<-- eingeloggt ----|                    |
```

- **State-Parameter:** CSRF-Schutz; als WordPress-Transient für 5 Minuten gespeichert.
- **Nonce:** Replay-Schutz im ID-Token.
- **PKCE:** Verhindert Authorization Code Interception auch bei öffentlichen Clients.

### Auto-Discovery

Wenn der Provider eine Discovery URL bereitstellt, können alle Endpunkte automatisch befüllt werden:

1. Discovery URL eintragen → **Abrufen** klicken
2. Issuer, Authorization Endpoint, Token Endpoint, Userinfo Endpoint, JWKS URI und End-Session Endpoint werden automatisch ausgefüllt
3. PKCE-Checkbox wird automatisch gesetzt, wenn der Provider S256 unterstützt

### Token-Refresh

Wenn aktiviert, speichert das Plugin nach dem Login Access-, Refresh- und ID-Token. Das Access-Token wird automatisch erneuert, wenn es weniger als 60 Sekunden gültig ist. Bei Fehlschlag wird eine `WP_Error`-Instanz zurückgegeben.

### Token-Verschlüsselung

Alle gespeicherten Tokens werden mit **AES-256-CBC** verschlüsselt:

- Schlüsselmaterial: `SHA256(AUTH_KEY . SECURE_AUTH_KEY)` (aus `wp-config.php`)
- IV: zufällig generiert pro Verschlüsselung (16 Bytes)
- Vorhandene Klartext-Tokens werden beim nächsten Schreiben automatisch migriert

> **Wichtig:** `AUTH_KEY` und `SECURE_AUTH_KEY` in `wp-config.php` dürfen nach Aktivierung der Verschlüsselung nicht geändert werden – gespeicherte Tokens wären sonst nicht mehr entschlüsselbar.

### Session-Management

Bei **jedem Seitenaufruf** wird für eingeloggte OIDC-Nutzer geprüft:

1. Access-Token noch gültig? → weiter
2. Abgelaufen → Refresh versuchen
3. Refresh fehlgeschlagen → Session beenden, Nutzer zur Login-Seite weiterleiten

Stellt sicher, dass auf Provider-Seite deaktivierte Benutzer auch in WordPress zeitnah ausgeloggt werden.

### Frontchannel- und Backchannel-Logout

**Frontchannel:** Beim WordPress-Logout wird der Browser zum End-Session Endpoint des Providers weitergeleitet; der Provider beendet seine Session.

**Backchannel:** Der Provider kann WordPress direkt (Server-zu-Server) über einen Logout informieren:

- Endpoint: `POST /wp-json/oidc-client/v1/backchannel-logout`
- Das Plugin validiert: JWT-Signatur, `iss`/`aud`/`iat`-Claims, `events`-Claim, JTI-Replay-Schutz (24 Stunden)

### Account-Linking

Bestehende WordPress-Konten können mit dem Provider verknüpft werden (siehe [Benutzerhandbuch](user-guide.md)). Automatische Verknüpfung bei gleicher E-Mail-Adresse ist ebenfalls möglich.

### Active-Claim

Sperrt den Login, wenn ein bestimmter Claim nicht `true` ist:

- `active` – typisch bei Keycloak/easyVerein
- `email_verified` – Login nur wenn E-Mail bestätigt

### Login-Log

Unter **Werkzeuge → OIDC Login-Log** werden alle Login-Versuche protokolliert:

| Spalte | Inhalt |
|---|---|
| Zeitstempel | Datum und Uhrzeit |
| Benutzer | WordPress-Login-Name |
| IP-Adresse | IP des Clients |
| Status | ✓ Erfolg / ✗ Fehler |
| Meldung | Fehlermeldung oder „OIDC-Anmeldung erfolgreich" |

Die Tabelle unterstützt Paginierung (25 Einträge pro Seite).

---

## Provider-spezifische Konfiguration

### Keycloak

**Discovery URL:**
```
https://<host>/realms/<realm-name>/.well-known/openid-configuration
```

**Empfohlene Einstellungen:**
- Token-Endpoint Authentifizierung: `client_secret_post`
- PKCE: aktiviert

**Rollen mappen:**
- Claim-Name: `roles` (Realm-Rollen) oder `resource_access.<client-id>.roles` (Client-Rollen)
- In Keycloak muss ein Mapper konfiguriert sein, der die Rollen als Claim ausgibt
- Scopes: `openid email profile roles`

### Microsoft Entra ID (Azure AD)

**Discovery URL:**
```
https://login.microsoftonline.com/<tenant-id>/v2.0/.well-known/openid-configuration
```

**Empfohlene Einstellungen:**
- Token-Endpoint Authentifizierung: `client_secret_basic`
- PKCE: aktiviert

**Rollen mappen:**
- Claim-Name: `roles`
- Rollen müssen in der App-Registrierung als App-Rollen definiert und Benutzern/Gruppen zugewiesen sein

### Google

**Discovery URL:**
```
https://accounts.google.com/.well-known/openid-configuration
```

**Empfohlene Einstellungen:**
- Token-Endpoint Authentifizierung: `client_secret_post`
- PKCE: aktiviert
- Active-Claim: `email_verified`

> Google unterstützt kein Rollen-Mapping – Rollen müssen in WordPress manuell vergeben werden.

### Okta / Auth0

**Okta Discovery URL:**
```
https://<okta-domain>/.well-known/openid-configuration
```

**Auth0 Discovery URL:**
```
https://<auth0-domain>/.well-known/openid-configuration
```

**Empfohlene Einstellungen:**
- Token-Endpoint Authentifizierung: `client_secret_basic`

**Rollen bei Auth0:** Benötigt eine Action/Rule, die Rollen als Custom Claim einfügt, z.B. `https://example.com/roles`.

### easyVerein

**Discovery URL:**
```
https://easyverein.com/api/v1/o/.well-known/openid-configuration
```

**Empfohlene Einstellungen:**
- Token-Endpoint Authentifizierung: `client_secret_post`
- PKCE: aktiviert
- Active-Claim: `active`

---

## Konfiguration auf Provider-Seite

Auf der Einstellungsseite unter **Konfiguration auf OIDC-Provider-Seite** findest du alle URIs, die beim Provider eingetragen werden müssen:

| Parameter | URI |
|---|---|
| **Redirect URI (Callback URL)** | `https://deine-seite.de/wp-login.php?oidc_callback=1` |
| **Post-logout Redirect URI** | `https://deine-seite.de/wp-login.php` |
| **Backchannel Logout URI** | `https://deine-seite.de/wp-json/oidc-client/v1/backchannel-logout` |
| **Allowed Origin / CORS Origin** | `https://deine-seite.de` |
| **Initiate Login URI** | `https://deine-seite.de/wp-login.php` |

---

## Fehlersuche

### Häufige Fehler

#### `invalid_client`

1. **Falsche Client-ID oder Client-Secret** → Prüfen, kein Leerzeichen am Anfang/Ende
2. **Falsche Authentifizierungsmethode** → `client_secret_post` ↔ `client_secret_basic` tauschen
3. **PKCE nicht vom Provider unterstützt** → PKCE-Checkbox deaktivieren

#### `Ungültiger oder abgelaufener State-Parameter`

Die 5-Minuten-Frist zwischen Login-Klick und Provider-Rückkehr wurde überschritten, oder WordPress-Transients werden nicht korrekt gespeichert.

- Prüfen, ob `wp_options` schreibbar ist
- Bei Object-Caching: Transient-Speicherung sicherstellen
- Serverzeit prüfen

#### `ID-Token Issuer stimmt nicht überein`

Der `iss`-Claim im ID-Token stimmt nicht mit dem konfigurierten Issuer überein. Discovery URL erneut abrufen; Debug-Modus aktivieren zum Vergleich.

#### `Der Provider hat keine E-Mail-Adresse zurückgegeben`

- Scope `email` ergänzen
- Prüfen, ob der Provider E-Mails unter einem anderen Claim-Namen liefert
- Sicherstellen, dass eine E-Mail-Adresse beim Provider hinterlegt ist

#### `Kein lokales Konto für diese E-Mail-Adresse vorhanden`

„Benutzer automatisch anlegen" ist deaktiviert. Entweder aktivieren oder das Konto vorab in WordPress anlegen und dann verknüpfen.

#### Login-Schleife (ständige Weiterleitung)

Auto-Login ist aktiv, aber die Anmeldung beim Provider schlägt fehl. Lösung: `wp-login.php?showlogin=1` aufrufen → Auto-Login wird übersprungen → Einstellungen korrigieren.

### Debug-Modus aktivieren

1. **Einstellungen → OIDC Client → Debug-Modus** aktivieren und speichern
2. Login erneut versuchen
3. Fehlermeldung zeigt nun die vollständige Provider-Antwort

Zusätzlich in `wp-config.php`:

```php
define( 'WP_DEBUG', true );
define( 'WP_DEBUG_LOG', true );  // Log nach wp-content/debug.log
```

> **Achtung:** Debug-Modus nach der Fehlersuche wieder deaktivieren – die Ausgabe enthält möglicherweise sensible Daten.

---

## Sicherheitshinweise

### PKCE aktiviert lassen

PKCE (S256) verhindert Authorization Code Interception. Nur deaktivieren, wenn der Provider es ausdrücklich nicht unterstützt.

### HTTPS verwenden

Der gesamte OIDC-Flow muss über HTTPS laufen. Das Plugin erzwingt `sslverify: true` bei allen HTTP-Anfragen zum Provider.

### Client-Secret schützen

Das Client-Secret wird in der WordPress-Datenbank gespeichert:
- Datenbankzugriff auf minimale Berechtigungen beschränken
- Datenbankbackups verschlüsseln
- Token-Verschlüsselung aktivieren (schützt Tokens at rest)

### Auto-Login mit Bedacht einsetzen

> Aktiviere Auto-Login erst, wenn der OIDC-Login zuverlässig funktioniert. Der Fallback-URL für Admins lautet: `wp-login.php?showlogin=1`

### Backchannel-Logout-Endpoint

Der REST-Endpunkt ist öffentlich zugänglich (kein WordPress-Auth), da er vom Provider ohne Benutzerinteraktion aufgerufen wird. Das Plugin validiert den Logout-Token vollständig (Signatur, Claims, JTI-Replay-Schutz).

---

## Datenbankschema

Das Plugin legt beim Aktivieren eine Tabelle für das Login-Log an:

```sql
CREATE TABLE wp_oidc_login_log (
    id        INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    user_id   BIGINT UNSIGNED NOT NULL DEFAULT 0,
    timestamp DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP,
    ip        VARCHAR(45)     NOT NULL DEFAULT '',
    success   TINYINT(1)      NOT NULL DEFAULT 0,
    message   TEXT            NOT NULL
);
```

Die Tabelle wird **nicht** automatisch gelöscht, wenn das Plugin deaktiviert oder entfernt wird. Zum manuellen Löschen:

```sql
DROP TABLE IF EXISTS wp_oidc_login_log;
```
