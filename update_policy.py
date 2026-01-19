#!/usr/bin/env python3
"""
Update Firewall Policy

Update a firewall policy by ID with JSON data.
"""

import json
import sys
from dotenv import load_dotenv
from unifi_client import get_client_from_env

# Load environment variables
load_dotenv()


def main():
    """Update a firewall policy."""
    if len(sys.argv) < 3:
        print("Usage: python update_policy.py <policy_id> <json_file_or_inline_json>")
        print("\nExamples:")
        print("  # Update from JSON file")
        print("  python update_policy.py 6831f9f5c8ac4702c97c5e1e updates.json")
        print("\n  # Update with inline JSON")
        print("  python update_policy.py 6831f9f5c8ac4702c97c5e1e '{\"enabled\": true}'")
        print("\n  # Update name")
        print("  python update_policy.py 6831f9f5c8ac4702c97c5e1e '{\"name\": \"New Name\"}'")
        print("\nTo get policy IDs, run: python list_policies.py")
        sys.exit(1)

    policy_id = sys.argv[1]
    json_input = sys.argv[2]

    # Parse JSON input (file or inline)
    try:
        if json_input.startswith('{'):
            # Inline JSON
            update_data = json.loads(json_input)
        else:
            # JSON file
            with open(json_input, 'r') as f:
                update_data = json.load(f)
    except json.JSONDecodeError as e:
        print(f"✗ Invalid JSON: {e}")
        sys.exit(1)
    except FileNotFoundError:
        print(f"✗ File not found: {json_input}")
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

    # Get current policy
    policy = client.get_policy_by_id(policy_id)
    if not policy:
        print(f"✗ Policy not found: {policy_id}")
        sys.exit(1)

    print("\nCurrent policy:")
    print(client.format_policy(policy))
    print("\nUpdates to apply:")
    print(json.dumps(update_data, indent=2))

    print(f"\nUpdating policy {policy_id}...")

    # Update the policy (with verification enabled by default)
    success = client.update_policy(policy_id, update_data, verify=True)

    if success:
        print(f"✓ Successfully updated and verified policy: {policy.get('name', policy_id)}")
        
        # Fetch and display updated policy
        updated_policy = client.get_policy_by_id(policy_id)
        if updated_policy:
            print("\nUpdated policy:")
            print(client.format_policy(updated_policy))
            
            # Show what changed
            print("\nChanges applied:")
            for key, value in update_data.items():
                old_value = policy.get(key, "(not set)")
                new_value = updated_policy.get(key, "(not set)")
                if old_value != new_value:
                    print(f"  {key}: {old_value} → {new_value}")
    else:
        print(f"✗ Failed to update policy: {policy_id}")
        print("  The update may have been rejected by the API or verification failed.")
        print(f"  Check the policy state with: python view_policy.py {policy_id}")
        sys.exit(1)


if __name__ == "__main__":
    main()
