# JRTools OpenID Connect

[![CI](https://github.com/JRTools/jrtools-openid-connect/actions/workflows/ci.yml/badge.svg)](https://github.com/JRTools/jrtools-openid-connect.php/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/JRTools/jrtools-openid-connect/branch/main/graph/badge.svg)](https://codecov.io/gh/JRTools/jrtools-openid-connect)
[![Quality Gate Status](https://sonarcloud.io/api/project_badges/measure?project=JRTools_jrtools-openid-connect&metric=alert_status)](https://sonarcloud.io/summary/new_code?id=JRTools_jrtools-openid-connect)
[![Bugs](https://sonarcloud.io/api/project_badges/measure?project=JRTools_jrtools-openid-connect&metric=bugs)](https://sonarcloud.io/summary/new_code?id=JRTools_jrtools-openid-connect)
[![Vulnerabilities](https://sonarcloud.io/api/project_badges/measure?project=JRTools_jrtools-openid-connect&metric=vulnerabilities)](https://sonarcloud.io/summary/new_code?id=JRTools_jrtools-openid-connect)
[![Latest Release](https://img.shields.io/github/v/release/JRTools/jrtools-openid-connect)](https://github.com/JRTools/jrtools-openid-connect/releases/latest)
[![License: GPL v2](https://img.shields.io/badge/license-GPL--2.0%2B-blue)](https://www.gnu.org/licenses/gpl-2.0.html)
[![PHP](https://img.shields.io/badge/PHP-8.1%2B-777bb4)](https://www.php.net)
[![WordPress](https://img.shields.io/badge/WordPress-6.7%2B-21759b)](https://wordpress.org)

WordPress-Plugin für die Anmeldung per OpenID Connect (Authorization Code Flow mit PKCE).

## Überblick

JRTools OpenID Connect ermöglicht die Anmeldung an WordPress über jeden standardkonformen OIDC-Provider. Nach der Konfiguration erscheint auf der Login-Seite ein „Anmelden mit [Provider-Name]"-Button; das Plugin übernimmt den gesamten Authorization Code Flow inklusive PKCE, Token-Validierung und Benutzerverwaltung.

Unterstützte Provider: **Keycloak**, **Microsoft Entra ID (Azure AD)**, **Google**, **Okta**, **Auth0**, **easyVerein** und alle weiteren standardkonformen Anbieter.

Beim Login werden alle Standard-Claims gemäß OIDC Core 1.0 §5.1 automatisch auf WordPress-Profilfelder übertragen (Name, E-Mail, Profilbild, Sprache u.a.), sofern der Provider die Claims liefert.

## Dokumentation

| Zielgruppe | Dokument |
|---|---|
| Endbenutzer | [Benutzerhandbuch](docs/user-guide.md) |
| Administratoren | [Administrationshandbuch](docs/admin-guide.md) |
| Entwickler | [Entwicklerhandbuch](docs/developer-guide.md) |

## Schnellstart

1. Plugin als ZIP von der [Releases-Seite](https://github.com/JRTools/jrtools-openid-connect/releases) herunterladen
2. Im WordPress-Admin unter **Plugins → Neu hinzufügen → Plugin hochladen** installieren und aktivieren
3. **Einstellungen → OIDC Client** aufrufen, Discovery URL eintragen und **Abrufen** klicken
4. Client ID und Client Secret eintragen, speichern
5. Redirect URI im OIDC-Provider eintragen: `https://deine-seite.de/wp-login.php?oidc_callback=1`

## Voraussetzungen

- PHP 8.1 oder höher
- WordPress 6.7 oder höher (offiziell unterstützt: die letzten 4 Minor-Versionen)
- PHP-Extension `openssl`

## Lizenz

GPL-2.0+
