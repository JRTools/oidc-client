# Benutzerhandbuch – OIDC Client

Dieses Handbuch richtet sich an Endbenutzer, die sich über einen OIDC-Provider (z.B. Keycloak, Google, Microsoft) bei einer WordPress-Website anmelden.

---

## Was ist OIDC-Login?

Statt Benutzername und Passwort direkt auf der WordPress-Website einzugeben, wirst du zu einem zentralen Anmelde-Dienst (dem „Provider") weitergeleitet. Nach erfolgreicher Anmeldung dort kommst du automatisch zurück und bist eingeloggt – ohne ein separates WordPress-Passwort zu benötigen.

Das nennt sich **Single Sign-On (SSO)**: ein Konto, eine Anmeldung, viele Dienste.

---

## Anmelden

1. Rufe die Login-Seite der Website auf (z.B. `https://example.com/wp-login.php`).
2. Klicke auf den Button **„Anmelden mit [Provider-Name]"**.
3. Du wirst zu deinem Provider weitergeleitet. Melde dich dort an.
4. Nach der Anmeldung wirst du automatisch zurück zur Website geleitet und bist eingeloggt.

> **Hinweis:** Wenn das klassische WordPress-Formular (Benutzername/Passwort) nicht sichtbar ist, ist die Website so konfiguriert, dass ausschließlich der Provider-Login genutzt wird.

---

## Konto verknüpfen

Wenn du bereits ein WordPress-Konto hast und es mit dem OIDC-Provider verknüpfen möchtest:

1. Melde dich an deinem bestehenden WordPress-Konto an.
2. Navigiere zu **Benutzer → Dein Profil**.
3. Scrolle zum Abschnitt **OpenID Connect**.
4. Klicke auf **„Mit OIDC-Anbieter verknüpfen"**.
5. Du wirst zum Provider weitergeleitet – nach der Anmeldung dort ist die Verknüpfung aktiv.

Ab sofort kannst du dich über den OIDC-Button auf der Login-Seite anmelden, ohne Benutzername und Passwort eingeben zu müssen.

**Automatische Verknüpfung:** Wenn du dich zum ersten Mal per OIDC anmeldest und ein WordPress-Konto mit derselben E-Mail-Adresse existiert, wird es automatisch verknüpft.

---

## Verknüpfung aufheben

1. Navigiere zu **Benutzer → Dein Profil**.
2. Scrolle zum Abschnitt **OpenID Connect**.
3. Klicke auf **„Verknüpfung aufheben"** und bestätige den Dialog.

Danach ist wieder die Anmeldung mit Benutzername und Passwort nötig. Stelle sicher, dass du dein WordPress-Passwort kennst, bevor du die Verknüpfung aufhebst.

---

## E-Mail und Passwort

Je nach Konfiguration der Website können OIDC-verknüpfte Konten möglicherweise keine E-Mail-Adresse und/oder kein Passwort im WordPress-Profil ändern:

- Das **E-Mail-Feld** erscheint dann als nicht bearbeitbar.
- Der **Passwort-Abschnitt** ist ausgeblendet.

Änderungen an E-Mail und Passwort müssen in diesem Fall direkt beim Provider vorgenommen werden.

---

## Sitzung abgelaufen

Falls du während der Nutzung der Website ausgeloggt wirst und die Meldung „Sitzung abgelaufen. Bitte erneut anmelden." erscheint: Das ist normal – deine Anmeldung beim Provider ist abgelaufen. Melde dich einfach erneut über den Login-Button an.

---

## Häufige Fragen

**Ich sehe keinen „Anmelden mit ..."-Button.**
Das Plugin ist möglicherweise nicht aktiv oder noch nicht konfiguriert. Wende dich an den Administrator der Website.

**Ich kann mich nach dem Klick auf den Button nicht anmelden.**
Prüfe, ob dein Konto beim Provider aktiv ist und ob du die richtigen Zugangsdaten verwendest. Falls das Problem weiterhin besteht, wende dich an den Administrator.

**Ich komme nach der Anmeldung immer zurück zur Login-Seite.**
Möglicherweise ist dein Konto beim Provider deaktiviert, oder es existiert noch kein WordPress-Konto für deine E-Mail-Adresse. Wende dich an den Administrator.

**Ich bin ausgesperrt und komme nicht mehr rein.**
Falls Auto-Login aktiv ist, kannst du das Login-Formular direkt über folgenden URL aufrufen:
```
https://deine-seite.de/wp-login.php?showlogin=1
```
