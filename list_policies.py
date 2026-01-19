#!/usr/bin/env python3
"""
List Firewall Policies

Lists all firewall policies from UniFi UDM Pro.
Use this to get policy IDs, then use view_policy.py to see details.
"""

import sys
from dotenv import load_dotenv
from unifi_client import get_client_from_env

# Load environment variables
load_dotenv()


def main():
    """List all firewall policies."""
    try:
        client = get_client_from_env()
    except ValueError as e:
        print(f"✗ Error: {e}")
        print("\nPlease create a .env file based on .env.example")
        sys.exit(1)

    # Authenticate
    if not client.login():
        sys.exit(1)

    # List all policies
    print("\nFetching firewall policies...")
    all_policies = client.list_firewall_policies()

    if not all_policies:
        print("  No firewall policies found.")
        return

    # Separate active and disabled
    active_policies = [p for p in all_policies if p.get("enabled", False)]
    disabled_policies = [p for p in all_policies if not p.get("enabled", False)]

    print(f"\n{'='*70}")
    print(f"FIREWALL POLICIES: {len(all_policies)} total")
    print(f"{'='*70}\n")

    # List active policies
    if active_policies:
        print(f"ACTIVE POLICIES ({len(active_policies)}):")
        print("-" * 70)
        for policy in active_policies:
            policy_id = policy.get("_id", "N/A")
            name = policy.get("name", "Unnamed")
            index = policy.get("index", "")
            print(f"  {policy_id[:24]}... | Index: {index:>10} | {name}")
        print()

    # List disabled policies
    if disabled_policies:
        print(f"DISABLED POLICIES ({len(disabled_policies)}):")
        print("-" * 70)
        for policy in disabled_policies:
            policy_id = policy.get("_id", "N/A")
            name = policy.get("name", "Unnamed")
            index = policy.get("index", "")
            print(f"  {policy_id[:24]}... | Index: {index:>10} | {name}")
        print()

    print(f"{'='*70}")
    print(f"Summary: {len(active_policies)} active, {len(disabled_policies)} disabled")
    print(f"{'='*70}")
    print("\nTo view a specific policy, use:")
    print("  python view_policy.py <policy_id>")


if __name__ == "__main__":
    main()
