#!/bin/bash
set -e

DB_DIR="./data"
DB_FILE="$DB_DIR/GeoLite2-ASN.mmdb"
DOWNLOAD_URL="https://download.maxmind.com/geoip/databases/GeoLite2-ASN/download?suffix=tar.gz"

if [ -f "$DB_FILE" ]; then
    echo "ASN database already exists at $DB_FILE"
    exit 0
fi

if [ -z "$MAXMIND_USER" ]; then
    echo -n "MaxMind account ID: "
    read MAXMIND_USER
fi

if [ -z "$MAXMIND_PASSWORD" ]; then
    echo -n "MaxMind license key: "
    read -s MAXMIND_PASSWORD
    echo
fi

echo "Downloading GeoLite2 ASN database..."
mkdir -p "$DB_DIR"
cd "$DB_DIR"

curl -u "$MAXMIND_USER:$MAXMIND_PASSWORD" -L "$DOWNLOAD_URL" | tar -xz
find . -name "GeoLite2-ASN.mmdb" -exec mv {} . \;

if [ -f "GeoLite2-ASN.mmdb" ]; then
    echo "Successfully downloaded ASN database to $DB_FILE"
else
    echo "Error: Failed to extract database file"
    exit 1
fi
