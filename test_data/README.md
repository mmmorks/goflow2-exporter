# Test MaxMind Database

This directory contains a minimal MaxMind ASN database for testing purposes.

## Contents

- `test-asn.mmdb` - Minimal ASN database with entries for:
  - Google DNS (8.8.8.0/24, 2001:4860:4860::/48) → ASN 15169
  - Cloudflare DNS (1.1.1.0/24) → ASN 13335

## Regenerating

To regenerate the test database:

```bash
pip install mmdb-writer
python3 create_test_db.py
```

This creates a mixed IPv4/IPv6 compatible database that can be committed to the repository for consistent testing.
