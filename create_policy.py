#!/usr/bin/env python3
"""
Create Firewall Policy

Create a new firewall policy. This is a helper script - you'll need to provide
the full policy JSON structure. For common cases, see examples in the script.
"""

import json
import sys
from dotenv import load_dotenv
from unifi_client import get_client_from_env

# Load environment variables
load_dotenv()


def create_internal_to_dmz_policy(name: str, port: str, protocol: str = "tcp", index: int = 10002):
    """
    Create a policy allowing Internal zone to DMZ on a specific port.

    Args:
        name: Policy name
        port: Destination port
        protocol: Protocol (tcp, udp, etc.)
        index: Policy index (priority)

    Returns:
        Policy data dictionary
    """
    return {
        "name": name,
        "action": "ALLOW",
        "enabled": True,
        "index": index,
        "protocol": protocol.lower(),
        "ip_version": "IPV4",
        "logging": False,
        "source": {
            "zone_id": "68236f2bbc658009c2e6668b",  # Internal zone
            "matching_target": "ANY",
            "port_matching_type": "ANY",
            "match_opposite_ports": False,
        },
        "destination": {
            "zone_id": "68236f2bbc658009c2e66690",  # DMZ zone
            "ips": ["192.168.4.36"],
            "matching_target": "IP",
            "matching_target_type": "SPECIFIC",
            "port": port,
            "port_matching_type": "SPECIFIC",
            "match_opposite_ports": False,
        },
        "connection_state_type": "ALL",
        "connection_states": [],
        "schedule": {
            "mode": "ALWAYS",
        },
    }


def main():
    """Create a firewall policy."""
    if len(sys.argv) < 2:
        print("Usage: python create_policy.py <policy_json_file>")
        print("   OR: python create_policy.py --internal-dmz-ssh")
        print("   OR: python create_policy.py --internal-dmz-https")
        print("\nExamples:")
        print("  # Create SSH access from Internal to DMZ")
        print("  python create_policy.py --internal-dmz-ssh")
        print("\n  # Create HTTPS access from Internal to DMZ")
        print("  python create_policy.py --internal-dmz-https")
        print("\n  # Create from JSON file")
        print("  python create_policy.py policy.json")
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

    # Handle quick-create options
    if sys.argv[1] == "--internal-dmz-ssh":
        policy_data = create_internal_to_dmz_policy(
            "Internal to DMZ - SSH",
            "22",
            "tcp",
            10002
        )
    elif sys.argv[1] == "--internal-dmz-https":
        policy_data = create_internal_to_dmz_policy(
            "Internal to DMZ - HTTPS",
            "443",
            "tcp",
            10003
        )
    else:
        # Load from JSON file
        try:
            with open(sys.argv[1], 'r') as f:
                policy_data = json.load(f)
        except FileNotFoundError:
            print(f"✗ File not found: {sys.argv[1]}")
            sys.exit(1)
        except json.JSONDecodeError as e:
            print(f"✗ Invalid JSON: {e}")
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
