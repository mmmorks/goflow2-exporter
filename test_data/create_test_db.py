#!/usr/bin/env python3
"""
Create a minimal MaxMind ASN database for testing.
Requires: pip install mmdb-writer
"""

import netaddr
from mmdb_writer import MMDBWriter

# Create a mixed IPv4/IPv6 ASN database
writer = MMDBWriter(6, 'GeoLite2-ASN', languages=['en'], ipv4_compatible=True)

# Add Google DNS entries (ASN 15169)
writer.insert_network(netaddr.IPSet([netaddr.IPNetwork('8.8.8.0/24')]), {
    'autonomous_system_number': 15169,
    'autonomous_system_organization': 'Google LLC'
})

writer.insert_network(netaddr.IPSet([netaddr.IPNetwork('2001:4860:4860::/48')]), {
    'autonomous_system_number': 15169,
    'autonomous_system_organization': 'Google LLC'
})

# Add Cloudflare DNS
writer.insert_network(netaddr.IPSet([netaddr.IPNetwork('1.1.1.0/24')]), {
    'autonomous_system_number': 13335,
    'autonomous_system_organization': 'Cloudflare, Inc.'
})

# Write the database
writer.to_db_file('test_data/test-asn.mmdb')

print("Created test-asn.mmdb with minimal test data")
