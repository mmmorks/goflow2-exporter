# ASN Database Setup

## Quick Start

1. Get a free MaxMind account: https://www.maxmind.com/en/geolite2/signup
2. Download the database:
   ```bash
   ./scripts/download-asn-db.sh
   ```
   You'll be prompted for your MaxMind account ID and license key.

3. Run the aggregator:
   ```bash
   cargo run
   ```

The database will be downloaded to `./data/GeoLite2-ASN.mmdb` and automatically used by the application.

## Environment Variables

- `MAXMIND_USER`: Your MaxMind account ID (optional, will prompt if not set)
- `MAXMIND_PASSWORD`: Your MaxMind license key (optional, will prompt if not set)
- `ASN_DB_PATH`: Optional, defaults to `./data/GeoLite2-ASN.mmdb`
