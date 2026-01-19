#!/usr/bin/env python3
"""
View Port Forwarding Rule

View detailed information about a specific port forwarding rule by ID.
"""

import json
import sys
from dotenv import load_dotenv
from unifi_client import get_client_from_env

# Load environment variables
load_dotenv()


def main():
    """View a specific port forwarding rule."""
    if len(sys.argv) < 2:
        print("Usage: python view_port_forward.py <rule_id>")
        print("\nTo list rules, run: python list_port_forwards.py")
        sys.exit(1)

    rule_id = sys.argv[1]

    try:
        client = get_client_from_env()
    except ValueError as e:
        print(f"✗ Error: {e}")
        print("\nPlease create a .env file based on .env.example")
        sys.exit(1)

    # Authenticate
    if not client.login():
        sys.exit(1)

    # Get the rule
    print(f"\nFetching rule: {rule_id}...")
    rule = client.get_port_forward_by_id(rule_id)

    if not rule:
        print(f"✗ Rule not found: {rule_id}")
        print("\nTo list all rules, run: python list_port_forwards.py")
        sys.exit(1)

    # Display formatted rule
    print(f"\n{'='*70}")
    print("PORT FORWARD DETAILS")
    print(f"{'='*70}\n")

    name = rule.get("name", "Unnamed")
    enabled = "✓ Enabled" if rule.get("enabled", True) else "✗ Disabled"
    dst_port = rule.get("dst_port", "N/A")
    fwd_port = rule.get("fwd_port", "N/A")
    # API returns 'fwd' not 'fwd_ip' - check both for compatibility
    fwd_ip = rule.get("fwd", rule.get("fwd_ip", "N/A"))
    proto = rule.get("proto", rule.get("protocol", "tcp_udp"))

    print(f"  Name: {name}")
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

    # Display full JSON for reference
    print(f"\n{'='*70}")
    print("FULL JSON DATA")
    print(f"{'='*70}\n")
    print(json.dumps(rule, indent=2, default=str))


if __name__ == "__main__":
    main()
