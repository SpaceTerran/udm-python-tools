#!/usr/bin/env python3
"""
Create Firewall Policy

Create a new firewall policy from a JSON file holding the full policy
structure.
"""

import json
import sys
from dotenv import load_dotenv
from unifi_client import get_client_from_env

# Load environment variables
load_dotenv()


def main():
    """Create a firewall policy."""
    if len(sys.argv) < 2:
        print("Usage: python create_policy.py <policy_json_file>")
        print("\nExample:")
        print("  python create_policy.py policy.json")
        sys.exit(1)

    try:
        with open(sys.argv[1], 'r') as f:
            policy_data = json.load(f)
    except FileNotFoundError:
        print(f"✗ File not found: {sys.argv[1]}")
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"✗ Invalid JSON: {e}")
        sys.exit(1)

    try:
        client = get_client_from_env()
    except ValueError as e:
        print(f"✗ Error: {e}")
        print("\nPlease create a .env file based on .env.example")
        sys.exit(1)

    # Authenticate
    if not client.login():
        sys.exit(1)

    print(f"\nCreating policy: {policy_data.get('name', 'Unnamed')}")
    print("Policy data:")
    print(json.dumps(policy_data, indent=2))

    # Create the policy
    result = client.create_policy(policy_data)

    if result:
        policy_id = result.get("_id") if isinstance(result, dict) else None
        if policy_id:
            print(f"\n✓ Successfully created policy with ID: {policy_id}")
            print("\nPolicy details:")
            print(client.format_policy(result if isinstance(result, dict) else {}))
        else:
            print(f"\n✓ Policy created (response: {result})")
    else:
        print("\n✗ Failed to create policy")
        sys.exit(1)


if __name__ == "__main__":
    main()
