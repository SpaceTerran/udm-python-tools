#!/usr/bin/env python3
"""
View Firewall Policy

View detailed information about a specific firewall policy by ID.
Use list_policies.py to get policy IDs.
"""

import json
import sys
from dotenv import load_dotenv
from unifi_client import get_client_from_env

# Load environment variables
load_dotenv()


def main():
    """View a specific firewall policy."""
    if len(sys.argv) < 2:
        print("Usage: python view_policy.py <policy_id>")
        print("\nTo get policy IDs, run: python list_policies.py")
        sys.exit(1)

    policy_id = sys.argv[1]

    try:
        client = get_client_from_env()
    except ValueError as e:
        print(f"✗ Error: {e}")
        print("\nPlease create a .env file based on .env.example")
        sys.exit(1)

    # Authenticate
    if not client.login():
        sys.exit(1)

    # Get the policy
    print(f"\nFetching policy: {policy_id}...")
    policy = client.get_policy_by_id(policy_id)

    if not policy:
        print(f"✗ Policy not found: {policy_id}")
        print("\nTo list all policies, run: python list_policies.py")
        sys.exit(1)

    # Display formatted policy
    print(f"\n{'='*70}")
    print("POLICY DETAILS")
    print(f"{'='*70}\n")
    print(client.format_policy(policy))

    # Display full JSON for reference
    print(f"\n{'='*70}")
    print("FULL JSON DATA")
    print(f"{'='*70}\n")
    print(json.dumps(policy, indent=2, default=str))


if __name__ == "__main__":
    main()
