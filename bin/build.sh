#!/usr/bin/env bash
# bin/build.sh – Plugin-ZIP für WordPress-Release erstellen
#
# Verwendung: bash bin/build.sh
# Ausgabe:    dist/jrtools-openid-connect-<VERSION>.zip
#
set -euo pipefail

SLUG="jrtools-openid-connect"
VERSION=$(grep "^[ \t]*\* Version:" jrtools-openid-connect.php | awk '{print $NF}')

if [[ -z "${VERSION}" ]]; then
    echo "FEHLER: Version konnte nicht aus jrtools-openid-connect.php gelesen werden." >&2
    exit 1
fi

DIST="dist/${SLUG}"
ZIP="${SLUG}-${VERSION}.zip"

echo "→ Erstelle ${ZIP} (Version ${VERSION})…"

# Altes Build-Verzeichnis aufräumen
rm -rf dist
mkdir -p "${DIST}"

# Dateien kopieren – alles außer .distignore-Einträge
rsync -a \
    --exclude-from=".distignore" \
    --exclude="dist" \
    . "${DIST}/"

# ZIP erstellen
cd dist
zip -r "${ZIP}" "${SLUG}"
cd ..

echo "✓ Erstellt: dist/${ZIP}"
