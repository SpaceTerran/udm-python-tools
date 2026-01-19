#!/usr/bin/env python3
"""
List Port Forwarding Rules

Lists all port forwarding rules from UniFi UDM Pro.
"""

import sys
from dotenv import load_dotenv
from unifi_client import get_client_from_env

# Load environment variables
load_dotenv()


def main():
    """List all port forwarding rules."""
    # Check for optional name filter
    name_filter = None
    if len(sys.argv) > 1:
        name_filter = sys.argv[1].lower()

    try:
        client = get_client_from_env()
    except ValueError as e:
        print(f"✗ Error: {e}")
        print("\nPlease create a .env file based on .env.example")
        sys.exit(1)

    # Authenticate
    if not client.login():
        sys.exit(1)

    # List all port forwards
    print("\nFetching port forwarding rules...")
    all_rules = client.list_port_forwards()

    if not all_rules:
        print("  No port forwarding rules found.")
        return

    # Filter by name if specified
    if name_filter:
        all_rules = [r for r in all_rules if name_filter in r.get("name", "").lower()]
        if not all_rules:
            print(f"  No rules matching '{name_filter}' found.")
            return

    print(f"\n{'='*70}")
    print(f"PORT FORWARDING RULES: {len(all_rules)} total")
    print(f"{'='*70}\n")

    for rule in all_rules:
        rule_id = rule.get("_id", "N/A")
        name = rule.get("name", "Unnamed")
        enabled = "✓ Enabled" if rule.get("enabled", True) else "✗ Disabled"
        dst_port = rule.get("dst_port", "N/A")
        fwd_port = rule.get("fwd_port", "N/A")
        # API returns 'fwd' not 'fwd_ip' - check both for compatibility
        fwd_ip = rule.get("fwd", rule.get("fwd_ip", "N/A"))
        proto = rule.get("proto", rule.get("protocol", "tcp_udp"))

        print(f"Name: {name}")
        print(f"  ID: {rule_id}")
        print(f"  Status: {enabled}")
        print(f"  External Port: {dst_port}")
        print(f"  Forward To: {fwd_ip}:{fwd_port}")
        print(f"  Protocol: {proto}")
        if rule.get("src"):
            print(f"  Source IP: {rule.get('src')}")
        if rule.get("src_limiting_enabled"):
            print(f"  Source Limiting: Enabled ({rule.get('src_limiting_type', 'ip')})")
        if rule.get("log"):
            print("  Logging: Enabled")
        if rule.get("pfwd_interface"):
            print(f"  Interface: {rule.get('pfwd_interface')}")
        if rule.get("destination_ip") and rule.get("destination_ip") != "any":
            print(f"  Destination IP: {rule.get('destination_ip')}")
        print("-" * 70)

    print(f"\n{'='*70}")
    print(f"Total rules: {len(all_rules)}")
    print(f"{'='*70}")


if __name__ == "__main__":
    main()
